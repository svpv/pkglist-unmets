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
int strtabPos = 1;

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
    // front-encoded, roughly like in locatedb(5).  The delta field uses the
    // range of [-4095,4095] to encode the change in the common prefix length;
    // the value of -4096, if ever used, should reset the prefix length to 0.
    int delta: 13;
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
    cmp = hasVer1 - hasVer2;
    if (cmp) return cmp;
    // Neither has a version?
    if (!hasVer1) return cmp;
    // Both have versions.
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

    size_t lastNameLen = 0, lastLcpLen = 0;
    for (int i = 0; i < n; i++) {
	// Make a token.
	unsigned sense = flags[i] & (RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL);
	size_t nameLen = strlen(names[i]);
	assert(nameLen < 4096);
	size_t lcpLen = i ? lcp(names[i-1], lastNameLen, names[i], nameLen) : 0;
	int delta = (int) lcpLen - (int) lastLcpLen;
	size_t len1 = nameLen - lcpLen;
	struct depToken token = {
	    .sense = sense,
	    .delta = delta,
	    .len = len1,
	};
	// RequireName not changed?
	if (pkgIx && delta == 0 && len1 == 0)
	    // No version? It must be a dup then, as per depCmp ordering.
	    // E.g. "Requires: /bin/sh" and "Requires(pre): /bin/sh".
	    if (sense == 0)
		continue;
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
	lastNameLen = nameLen, lastLcpLen = lcpLen;
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
    size_t fnameLen = 0, lastFnameLen = 0, lastLcpLen = 0;
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
	int delta = (int) lcpLen - (int) lastLcpLen;
	size_t len1 = fnameLen - lcpLen;
	struct depToken token = {
	    .sense = 0,
	    .delta = delta,
	    .len = len1,
	};
	// Put the record.
	assert(p + 4 + len1 < end);
	memcpy(p, &token, 4);
	p += 4;
	memcpy(p, fname + lcpLen, len1);
	p += len1;
	// Copy fname to lastFname.
	memcpy(lastFname, fname, fnameLen + 1);
	lastFnameLen = fnameLen, lastLcpLen = lcpLen;
    }

    rpmtdFreeData(&td1);
    rpmtdFreeData(&td2);
    rpmtdFreeData(&td3);

    return p;
}

int verbose;
int npkg;

char frame[8<<20];

void addHeader(Header h)
{
    int pkgIx = addPkg(h);
    addReq(h, pkgIx, frame, frame + sizeof frame);
    addProv(h, frame, frame + sizeof frame);
    addFnames(h, frame, frame + sizeof frame);
    if (verbose > 1)
	fprintf(stderr, "loaded %s\n", strtab + pkgIx);
    npkg++;
}

#include <stdbool.h>
#include <getopt.h>

const struct option longopts[] = {
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
	case 'v':
	    verbose++;
	    break;
	default:
	    usage = true;
	}
    }
    argc -= optind, argv += optind;
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
	addHeader(h);
	headerFree(h);
    }
    Fclose(Fd);
    if (verbose)
	fprintf(stderr, "loaded %d headers (%.1fM strtab)\n", npkg,
			(double) strtabPos / (1 << 20));
    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
