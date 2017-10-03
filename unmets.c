// Copyright (c) 2017 Alexey Tourbin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// I don't use "static" in this program to indicate file scope.
// The program is supposed to be compiled with -fwhole-program.

#include <string.h>
#include <assert.h>

// The string tab for %{Name}+%{EVR}, %{RequireVersion} and %{ProvideVersion}.
char strtab[256<<20];
int strtabPos = 1; // Any reference is non-zero.

int *lookupStrtab(const char *ver, size_t vlen)
{
    // Hash the version.
    unsigned b1 = (unsigned char) ver[vlen/2+0];
    unsigned b2 = (unsigned char) ver[vlen/2+1];
    unsigned hash = vlen;
    hash = 33 * hash + b1;
    hash = 33 * hash + b2;
    // Get the hash chain which always has 2 indices into strtab[].
    static int lookup[1<<16][2];
    return lookup[hash % (1<<16)];
}

int addVer(const char *ver)
{
    size_t vlen = strlen(ver);
    assert(vlen);
    // Lookup up in the cache.
    int *va = lookupStrtab(ver, vlen);
    if (va[0] && memcmp(ver, strtab + va[0], vlen + 1) == 0)
	return va[0];
    if (va[1] && memcmp(ver, strtab + va[1], vlen + 1) == 0)
	return va[1];
    // Store in the cache.
    va[1] = va[0];
    int vpos = va[0] = strtabPos;
    assert(vpos + vlen + 1 < sizeof strtab);
    memcpy(strtab + vpos, ver, vlen + 1);
    strtabPos += vlen + 1;
    return vpos;
}

#include <rpm/rpmlib.h>

int addPkg(Header h)
{
    int pkgIx = strtabPos;

    const char *name = headerGetString(h, RPMTAG_NAME);
    assert(name);
    size_t len = strlen(name);
    assert(strtabPos + len + 1 < sizeof strtab);
    memcpy(strtab + strtabPos, name, len);
    strtabPos += len;
    strtab[strtabPos++] = ' ';

    char *ver = headerGetAsString(h, RPMTAG_EVR);
    assert(ver);
    size_t vlen = strlen(ver);

    // Put EVR into the lookup cache.
    int *va = lookupStrtab(ver, vlen);
    if (!( (va[0] && memcmp(ver, strtab + va[0], vlen + 1) == 0) ||
	   (va[1] && memcmp(ver, strtab + va[1], vlen + 1) == 0) ))
	va[1] = va[0], va[0] = strtabPos;

    assert(strtabPos + vlen + 1 < sizeof strtab);
    memcpy(strtab + strtabPos, ver, vlen + 1);
    strtabPos += vlen + 1;
    free(ver);

    return pkgIx;
}

// This program builds and processes two big sequences: the sequence
// of Requires and the sequence of Provides (the latter also includes
// %{Filenames}).  A sequence is made of variable-length records.
// Each record starts with a 4-byte token.
struct depToken {
    // RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL
    // 0 = no version
    unsigned sense: 4;
    // A sequence of dependencies is sorted by name; the names are further
    // front-encoded, roughly like in locatedb(5).  This lcpLen field encodes
    // the length of the common prefix with the preceding name ("lcp" stands
    // for "the longest common prefix").
    unsigned lcpLen: 12;
    // This is the length of the rest of the name after the common prefix.
    // The name is stored after the 4-byte version, without a terminating
    // '\0' character (thus when len is 0, nothing is stored).  In the worst
    // case, the 12-bit length limits the name to 4095 characters, which indeed
    // matches PATH_MAX.
    unsigned len: 12;
};

static_assert(sizeof(struct depToken) == 4, "depToken");
static_assert((RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL) < 16, "sense");

// Right after the token there goes a 4-byte version (its index in the
// string tab), unless sense is 0.  And so Provide records look like this:
// - sense == 0:
//   +-+-+-+-+ +-    -+
//   | token | | name |
//   +-+-+-+-+ +-    -+
// - otherwise:
//   +-+-+-+-+ +-+-+-+-+ +-    -+
//   | token | |  ver  | | name |
//   +-+-+-+-+ +-+-+-+-+ +-    -+
//
// Require records additionally store a 4-byte package reference (to be
// printed if the dependency turns out to be unmet).  They look like this:
// - sense == 0:
//   +-+-+-+-+ +-+-+-+-+ +-    -+
//   | token | |  pkg  | | name |
//   +-+-+-+-+ +-+-+-+-+ +-    -+
// - otherwise:
//   +-+-+-+-+ +-+-+-+-+ +-+-+-+-+ +-    -+
//   | token | |  ver  | |  pkg  | | name |
//   +-+-+-+-+ +-+-+-+-+ +-+-+-+-+ +-    -+

#include <stdbool.h>
#include "qsort.h"

static inline int depCmp(size_t i, size_t j, const char **names, const char **versions, int *flags)
{
    int cmp = strcmp(names[i], names[j]);
    if (cmp) return cmp;
    bool hasVer1 = flags[i] & RPMSENSE_SENSEMASK;
    bool hasVer2 = flags[j] & RPMSENSE_SENSEMASK;
    // Deps with version go before the versionless ones.
    // This way, the latter are easier to discard.
    cmp = hasVer2 - hasVer1;
    if (cmp) return cmp;
    // Neither has a version?
    if (!hasVer1) return cmp;
    // Both have versions.  Any ordering would do.
    return strcmp(versions[i], versions[j]);
}

static inline void depSwap(size_t i, size_t j, const char **names, const char **versions, int *flags)
{
    const char *tmpName, *tmpVersion; int tmpFlags;
    tmpName =  names[i], tmpVersion  = versions[i], tmpFlags = flags[i];
    names[i] = names[j], versions[i] = versions[j], flags[i] = flags[j];
    names[j] = tmpName,  versions[j] = tmpVersion,  flags[j] = tmpFlags;
}

void sortDeps(int n, const char **names, const char **versions, int *flags)
{
#define DEP_LESS(i, j) depCmp(i, j, names, versions, flags) < 0
#define DEP_SWAP(i, j) depSwap(i, j, names, versions, flags)
    QSORT(n, DEP_LESS, DEP_SWAP);
}

#include "lcp.h"

// Pack either Requires (pkgIx != 0) or Provides (pkgIx == 0) into [p,end).
// Returns next p.
char *addDeps(Header h, int pkgIx, char *p, char *end)
{
    const int tags[2][3] = {
	{ RPMTAG_REQUIRENAME, RPMTAG_REQUIREVERSION, RPMTAG_REQUIREFLAGS },
	{ RPMTAG_PROVIDENAME, RPMTAG_PROVIDEVERSION, RPMTAG_PROVIDEFLAGS },
    };
    struct rpmtd_s td1, td2, td3;
    int rc = headerGet(h, tags[!pkgIx][0], &td1, HEADERGET_MINMEM);
    // Assume that Requires must be present - someplace, they check
    // for the "rpmlib(PayloadIsLzma)" dependency as mandatory.
    // Provides must also be present, due to "Provides: %name = %EVR".
    assert(rc == 1);
    assert(td1.count > 0);
    int n = td1.count;
    assert(td1.type == RPM_STRING_ARRAY_TYPE);
    const char **names = td1.data;

    rc = headerGet(h, tags[!pkgIx][1], &td2, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td2.count == n);
    assert(td2.type == RPM_STRING_ARRAY_TYPE);
    const char **versions = td2.data;

    rc = headerGet(h, tags[!pkgIx][2], &td3, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td3.count == n);
    assert(td3.type == RPM_INT32_TYPE);
    int *flags = td3.data;

    sortDeps(n, names, versions, flags);

    size_t lastNameLen = 0;
    for (int i = 0; i < n; i++) {
	// Make a token.
	unsigned sense = flags[i] & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL);
	size_t nameLen = strlen(names[i]);
	assert(nameLen < 4096);
	size_t lcpLen = i ? lcp(names[i-1], lastNameLen, names[i], nameLen) : 0;
	// RequireName not changed?
	bool sameName = lcpLen == nameLen && nameLen == lastNameLen;
	if (pkgIx && sameName)
	    // No version? It must be a dup then, as per depCmp ordering.
	    // E.g. "Requires: /bin/sh" and "Requires(pre): /bin/sh".
	    if (sense == 0)
		continue;
	size_t len1 = nameLen - lcpLen;
	struct depToken token = { .sense = sense, .lcpLen = lcpLen, .len = len1 };
	// Put the record.
	assert(p + 4 + (sense ? 4 : 0) + (pkgIx ? 4 : 0) + len1 < end);
	memcpy(p, &token, 4);
	p += 4;
	if (sense) {
	    int vpos = addVer(versions[i]);
	    memcpy(p, &vpos, 4);
	    p += 4;
	}
	if (pkgIx) {
	    memcpy(p, &pkgIx, 4);
	    p += 4;
	}
	memcpy(p, names[i] + lcpLen, len1);
	p += len1;
	lastNameLen = nameLen;
    }

    rpmtdFreeData(&td1);
    rpmtdFreeData(&td2);
    rpmtdFreeData(&td3);

    return p;
}

char *addReq(Header h, int pkgIx, char *p, char *end)
{
    assert(pkgIx);
    return addDeps(h, pkgIx, p, end);
}

char *addProv(Header h, char *p, char *end)
{
    return addDeps(h, 0, p, end);
}

// Pack filenames (on behalf of Provides).
char *addFnames(Header h, char *p, char *end)
{
    struct rpmtd_s td1, td2, td3;
    int bnc = 0;
    const char **bn = NULL, **dn = NULL;
    int *di = NULL;
    int rc = headerGet(h, RPMTAG_BASENAMES, &td1, HEADERGET_MINMEM);
    if (rc != 1)
	return p;
    assert(td1.type == RPM_STRING_ARRAY_TYPE);
    assert(td1.count > 0);
    bnc = td1.count;
    bn = td1.data;

    rc = headerGet(h, RPMTAG_DIRNAMES, &td2, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td2.type == RPM_STRING_ARRAY_TYPE);
    assert(td2.count > 0);
    dn = td2.data;

    rc = headerGet(h, RPMTAG_DIRINDEXES, &td3, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td3.type == RPM_INT32_TYPE);
    assert(td3.count == bnc);
    di = td3.data;

    char fname[4096], lastFname[4096];
    size_t fnameLen = 0, lastFnameLen = 0;
    int lastDi = -1;
    size_t dirLen = 0;

    for (int i = 0; i < bnc; i++) {
	if (lastDi != di[i]) {
	    lastDi = di[i];
	    dirLen = strlen(dn[lastDi]);
	    assert(dirLen < 4096);
	    memcpy(fname, dn[lastDi], dirLen);
	}
	size_t bnLen = strlen(bn[i]);
	fnameLen = dirLen + bnLen;
	assert(fnameLen > 0);
	assert(fnameLen < 4096);
	memcpy(fname + dirLen, bn[i], bnLen + 1);
	// Make a token.
	size_t lcpLen = i ? lcp(lastFname, lastFnameLen, fname, fnameLen) : 0;
	size_t len1 = fnameLen - lcpLen;
	struct depToken token = { .sense = 0, .lcpLen = lcpLen, .len = len1 };
	// Put the record.
	assert(p + 4 + len1 < end);
	memcpy(p, &token, 4);
	p += 4;
	memcpy(p, fname + lcpLen, len1);
	p += len1;
	// Copy fname to lastFname.
	memcpy(lastFname, fname, fnameLen + 1);
	lastFnameLen = fnameLen;
    }

    rpmtdFreeData(&td1);
    rpmtdFreeData(&td2);
    rpmtdFreeData(&td3);

    return p;
}

// Dump a packed [p,end) sequence to stdout.  Useful for debugging,
// e.g. the dump can be compared to /usr/bin/pkglist-query output.
void dumpSeq(const char *p, const char *end, bool isReq)
{
    char name[4096];
    while (1) {
	struct depToken token;
	assert(p + 4 <= end);
	memcpy(&token, p, 4), p += 4;
	// ver
	const char *ver = NULL;
	if (token.sense) {
	    int verIx;
	    assert(p + 4 <= end);
	    memcpy(&verIx, p, 4), p += 4;
	    assert(verIx < strtabPos);
	    ver = strtab + verIx;
	}
	// pkg
	if (isReq) {
	    int pkgIx;
	    assert(p + 4 <= end);
	    memcpy(&pkgIx, p, 4), p += 4;
	    assert(pkgIx < strtabPos);
	    fputs(strtab + pkgIx, stdout);
	    putchar('\t');
	}
	// name
	assert(p + token.len <= end);
	memcpy(name + token.lcpLen, p, token.len);
	p += token.len;
	name[token.lcpLen + token.len] = '\0';
	if (!token.sense)
	    puts(name);
	else {
	    fputs(name, stdout);
	    putchar(' ');
	    if (token.sense & RPMSENSE_LESS)	putchar('<');
	    if (token.sense & RPMSENSE_GREATER)	putchar('>');
	    if (token.sense & RPMSENSE_EQUAL)	putchar('=');
	    putchar(' ');
	    puts(ver);
	}
	if (p == end)
	    break;
    }
}

// Merge seq1 + seq2 into p.  The output size is bounded by seq1 + seq2.
char *mergeSeq(const char *seq1, const char *end1, const char *seq2, const char *end2, bool isReq, char *p)
{
    bool valid1 = false, valid2 = false;
    char name1[4096], name2[4096], lastName[4096];
    size_t name1len = 0, name2len = 0, lastNameLen = 0;
    size_t lcp1len = 0, lcp2len = 0;
    int ver1 = 0, ver2 = 0;
    int sense1 = 0, sense2 = 0;
    int pkg1 = 0, pkg2 = 0;
#define decodeDep(N, isReq)				\
    do {						\
	struct depToken token;				\
	memcpy(&token, seq##N, 4), seq##N += 4;		\
	sense##N = token.sense;				\
	ver##N = 0;					\
	if (sense##N)					\
	    memcpy(&ver##N, seq##N, 4), seq##N += 4;	\
	if (isReq)					\
	    memcpy(&pkg##N, seq##N, 4), seq##N += 4;	\
	lcp##N##len = token.lcpLen;			\
	size_t len = token.len;				\
	memcpy(name##N + lcp##N##len, seq##N, len);	\
	seq##N += len;					\
	name##N##len = lcp##N##len + len;		\
	name##N[name##N##len] = '\0';			\
    } while (0)
    while (seq1 < end1 || seq2 < end2 || valid1 || valid2) {
	if (seq1 < end1 && !valid1) {
	    valid1 = true;
	    decodeDep(1, isReq);
	}
	if (seq2 < end2 && !valid2) {
	    valid2 = true;
	    decodeDep(2, isReq);
	}
	int cmp = valid1 && valid2 ? strcmp(name1, name2) :
		  valid1 ? -1 : 1;
	// If the name is the same, order by having version.
	if (cmp == 0) {
	    cmp = (bool) sense1 - (bool) sense2;
	    // If both have versions, order by version.
	    if (cmp == 0 && sense1)
		cmp = ver1 - ver2;
	    // As a last resort, Requires are ordered by pkg.
	    if (cmp == 0 && isReq)
		cmp = pkg1 - pkg2;
	}
	const char *name = NULL;
	size_t nameLen = 0;
	int ver = 0;
	int sense = 0;
	int pkg = 0;
	if (cmp <= 0) {
	    name = name1, nameLen = name1len, ver = ver1, sense = sense1, pkg = pkg1;
	    valid1 = false;
	    // Fold identical dependencies, typically Provides
	    // (e.g. i586-wine Provides: wine = %EVR).
	    if (cmp == 0)
		valid2 = false;
	}
	else {
	    name = name2, nameLen = name2len, ver = ver2, sense = sense2, pkg = pkg2;
	    valid2 = false;
	}
	// Make a token.
	size_t lcpLen = lastNameLen ? lcp(lastName, lastNameLen, name, nameLen) : 0;
	size_t len1 = nameLen - lcpLen;
	struct depToken token = { .sense = sense, .lcpLen = lcpLen, .len = len1 };
	// Put the record.
	memcpy(p, &token, 4), p += 4;
	if (sense)
	    memcpy(p, &ver, 4), p += 4;
	if (isReq)
	    memcpy(p, &pkg, 4), p += 4;
	memcpy(p, name + lcpLen, len1);
	p += len1;
	// Copy lastName for the next iteration.
	memcpy(lastName + lcpLen, name + lcpLen, len1 + 1);
	lastNameLen = nameLen;
    }
    return p;
}

// Print an unmet dependency.
void unmet1(int pkg, const char *name, int ver, int sense)
{
    assert(pkg < sizeof strtab);
    fputs(strtab + pkg, stdout);
    putchar('\t');
    if (sense == 0)
	puts(name);
    else {
	fputs(name, stdout);
	putchar(' ');
	if (sense & RPMSENSE_LESS)	putchar('<');
	if (sense & RPMSENSE_GREATER)	putchar('>');
	if (sense & RPMSENSE_EQUAL)	putchar('=');
	putchar(' ');
	assert(ver < sizeof strtab);
	puts(strtab + ver);
    }
}

// This sucks more than anything that has ever sucked before.
#include <rpm/rpmstrpool.h>

// Try to satisfy R with P.
bool satisfy(rpmstrPool *poolp, rpmds *dsRp, int verR, int senseR, int verP, int senseP)
{
    // The routine should only be called for versioned Requires.
    // This is unlike unversioned provides, which can satsisfy
    // the peculiar dependencies "python(foo) < 0" used by imz.
    assert(senseR);

    // Equal version strings => equal versions.
    if (senseR == RPMSENSE_EQUAL && senseP == RPMSENSE_EQUAL)
	if (strcmp(strtab + verR, strtab + verP) == 0)
	    return true;

    rpmstrPool pool = *poolp;
    if (!pool)
	pool = *poolp = rpmstrPoolCreate();
    rpmds dsR = *dsRp;
    if (!dsR)
	dsR = *dsRp = rpmdsSinglePool(pool, RPMTAG_REQUIRENAME, "", strtab + verR, senseR);
    rpmds dsP = rpmdsSinglePool(pool, RPMTAG_PROVIDENAME, "", strtab + verP, senseP);
    bool ret = rpmdsCompare(dsP, dsR);
    rpmdsFree(dsP);
    return ret;
}

// Join {R,P} and print unmet dependencies.  There are two kinds of unmet dependencies:
// - when R.name is not in P, it's a name-only unmet dependency;
// - otherwise, the dependency can be unmet due to {R.ver,P.ver} version check.
void unmets(const char *seqR, const char *endR, const char *seqP, const char *endP)
{
    char nameR[4096], nameP[4096];
    size_t nameRlen = 0, namePlen = 0;
    size_t lcpRlen = 0, lcpPlen = 0;
    int verR = 0, verP = 0;
    int senseR = 0, senseP = 0;
    int pkgR = 0, pkgP = 0;
    decodeDep(R, true);
    decodeDep(P, false);
    int cmp = strcmp(nameP, nameR);
    while (1) {
	// Skip unused Provides.
	while (cmp < 0) {
	    if (seqP == endP)
		break;
	    decodeDep(P, false);
	    cmp = strcmp(nameP, nameR);
	}
	// No more Provides, but some Requires left?
	if (cmp < 0)
	    // Print name-only unmet Requires.
	    while (1) {
		unmet1(pkgR, nameR, 0, 0);
		if (seqR == endR)
		    return;
		decodeDep(R, true);
	    }
	// Prov > Req?  Print name-only unmet Requires.
	while (cmp > 0) {
	    unmet1(pkgR, nameR, 0, 0);
	    if (seqR == endR)
		break;
	    decodeDep(R, true);
	    cmp = strcmp(nameP, nameR);
	}
	// No more Requires left?
	if (cmp > 0)
	    return;
	// Prov < Req?  Next Provides.
	if (cmp < 0)
	    continue;
	// The two names match.  Now skip Requires without a version.
	while (senseR == 0) {
	    // No more Requires left?
	    if (seqR == endR)
		return;
	    decodeDep(R, true);
	    cmp = strcmp(nameP, nameR);
	    if (cmp)
		break;
	}
	// All the Requires were versionless?
	if (cmp)
	    continue;
	// For each Requires, iterate over Provides with the same name.
	rpmstrPool pool = NULL;
	do {
	    rpmds dsR = NULL;
	    bool happy = satisfy(&pool, &dsR, verR, senseR, verP, senseP);
	    if (!happy && seqP < endP) {
		const char *seqP1 = seqP;
		char nameP1[4096];
		int pkgP1, verP1 = 0, senseP1 = 0;
		size_t nameP1len = namePlen, lcpP1len = lcpPlen;
		memcpy(nameP1, nameP, namePlen + 1);
		while (1) {
		    decodeDep(P1, false);
		    int cmp1 = strcmp(nameP, nameP1);
		    if (cmp1)
			break;
		    happy = satisfy(&pool, &dsR, verR, senseR, verP1, senseP1);
		    if (happy || seqP1 == endP)
			break;
		}
	    }
	    rpmdsFree(dsR);
	    // Going to load the next Requires.
	    int senseR1 = senseR, verR1 = verR;
	    do {
		// Show if the dependency is unmet.
		if (!happy)
		    unmet1(pkgR, nameR, verR, senseR);
		// No more Requires left?
		if (seqR == endR) {
		    rpmstrPoolFree(pool);
		    return;
		}
		decodeDep(R, true);
		cmp = strcmp(nameP, nameR);
		// Fast-forward if it's the same Requires (from another package).
	    } while (cmp == 0 && senseR == senseR1 && verR == verR1);
	    // Proceed if the Requires name is the same.
	} while (cmp == 0);
	rpmstrPoolFree(pool);
    }
}

// There are 3 buffers for sequences: one for the Requires sequence,
// another for the Provides sequence, and one more that is used as an
// output buffer during merges.  The result of a merge which affects only
// a part of the buffer (i.e. the buffer has more than 2 subsequences,
// the two rightmost being merged) is copied back to the original
// buffer; however, when the buffer has only two subsequences to merge,
// the original buffer and the output buffer switch their places after
// such a merge.
#define SEQBUFSIZE (64<<20)
char seqBuf1[SEQBUFSIZE], seqBuf2[SEQBUFSIZE], seqBuf3[SEQBUFSIZE];
char *reqSeq = seqBuf1, *provSeq = seqBuf2, *tmpSeq = seqBuf3;
int reqFill, provFill;

// When a package is first processed, its Requires (Provides) sequence
// is appended to reqSeq (resp. provSeq) at reqOff=reqFill (resp.
// provOff=provFill).  The corresponding entry is pushed onto the stack,
// with npkg=1 set.  Then follows a series of balanced merges, e.g. 1+1,
// which means that if the two topmost stack entries both have npkg=1, they
// are popped off the stack, their sequences are merged, and the resulting
// entry with npkg=2 is pushed back to the stack; then 2+2, and so on.
// At some point, the stack will have entries with the following npkg values,
// from top to bottom: 1 2 4 ... n; pushing one more package will trigger a
// cascade of merges which will result in a single stack entry with npkg=2n.
struct stackEnt {
    int npkg;
    int reqOff, provOff;
};

// With the stack depth of 30, up to a billion packages can be processed.
// The real limitation lies within the strtab size and SEQBUFSIZE.
struct stackEnt stack[30];
int nstack;

// Merge the two topmost stack entries.
void mergeStack(void)
{
#define mergeDep(dep, isReq)							\
    do {								\
	int off1 = stack[nstack-1].dep##Off;				\
	int off2 = stack[nstack-2].dep##Off;				\
	int fill = mergeSeq(dep##Seq + off1, dep##Seq + dep##Fill,	\
			    dep##Seq + off2, dep##Seq + off1,		\
			    isReq, tmpSeq) - tmpSeq;			\
	if (nstack > 2) /* copy back */					\
	    memcpy(dep##Seq + off2, tmpSeq, fill);			\
	else { /* switch places */					\
	    char *p = dep##Seq;						\
	    dep##Seq = tmpSeq, tmpSeq = p;				\
	}								\
	dep##Fill = off2 + fill;					\
    } while (0)
    mergeDep(req, true);
    mergeDep(prov, false);
    stack[nstack-2].npkg += stack[nstack-1].npkg;
    nstack--;
}

int verbose;
int npkg;

void addHeader(Header h)
{
    // Add the package.
    int pkgIx = addPkg(h);
    // Add Requires.
    int reqOff = reqFill;
    reqFill = addReq(h, pkgIx, reqSeq + reqFill, reqSeq + SEQBUFSIZE) - reqSeq;
    // Add Provides.
    int prov2off = provFill;
    provFill = addProv(h, provSeq + provFill, provSeq + SEQBUFSIZE) - provSeq;
    // Add Filenames.
    int prov1off = provFill;
    provFill = addFnames(h, provSeq + provFill, provSeq + SEQBUFSIZE) - provSeq;
    // Merge Provides+Filenames.
    if (provFill > prov1off) {
	int fill = mergeSeq(provSeq + prov1off, provSeq + provFill,
			    provSeq + prov2off, provSeq + prov1off,
			    false, tmpSeq) - tmpSeq;
	memcpy(provSeq + prov2off, tmpSeq, fill);
	provFill = prov2off + fill;
    }
    // Push onto the stack.
    stack[nstack++] = (struct stackEnt) { 1, reqOff, prov2off };
    // Run merges.
    while (nstack > 1 && stack[nstack-1].npkg >= stack[nstack-2].npkg)
	mergeStack();
    // It's done when it's done.
    if (verbose > 1)
	fprintf(stderr, "loaded %s\n", strtab + pkgIx);
    npkg++;
}

#include <stdbool.h>
#include <getopt.h>

int dump_requires;
int dump_provides;

const struct option longopts[] = {
    { "dump-requires", no_argument, &dump_requires, 1 },
    { "dump-provides", no_argument, &dump_provides, 1 },
    { "help", no_argument, NULL, 'h' },
    { "verbose", no_argument, NULL, 'v' },
    { NULL },
};

int main(int argc, char **argv)
{
    const char *argv0 = argv[0];
    bool usage = false;
    int c;
    while ((c = getopt_long(argc, argv, "v", longopts, NULL)) != -1) {
	switch (c) {
	case 0:
	    break;
	case 'v':
	    verbose++;
	    break;
	default:
	    usage = true;
	}
    }
    argc -= optind, argv += optind;
    if (dump_requires && dump_provides) {
	fprintf(stderr, "%s: --dump-requires and --dump-provides are mutually exclusive\n", argv0);
	usage = 1;
    }
    if (argc && !usage) {
	fprintf(stderr, "%s: too many arguments\n", argv0);
	usage = 1;
    }
    if (usage) {
	fprintf(stderr, "Usage: cat /var/lib/apt/lists/*pkglist.* | %s\n", argv0);
	return 1;
    }
    FD_t Fd = fdDup(0);
    Header h;
    while ((h = headerRead(Fd, HEADER_MAGIC_YES))) {
	if (npkg == 0) {
	    // Smuggle rpmilb Provides with the frist package.
	    rpmds ds = NULL;
	    int rc = rpmdsRpmlib(&ds, NULL);
	    assert(rc == 0 && ds);
	    rc = rpmdsPutToHeader(ds, h);
	    assert(rc == 0);
	    rpmdsFree(ds);
	}
	addHeader(h);
	headerFree(h);
    }
    Fclose(Fd);
    // Run the final series of merges.
    while (nstack > 1)
	mergeStack();
    if (verbose)
	fprintf(stderr, "loaded %d headers (%.1fM strtab, %.1fM req, %.1fM prov)\n",
			 npkg,
			(double) strtabPos / (1 << 20),
			(double) reqFill / (1 << 20),
			(double) provFill / (1 << 20));
    if (dump_requires)
	dumpSeq(reqSeq, reqSeq + reqFill, true);
    else if (dump_provides)
	dumpSeq(provSeq, provSeq + provFill, false);
    else
	unmets(reqSeq, reqSeq + reqFill, provSeq, provSeq + provFill);
    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
