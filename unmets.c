// Copyright (c) 2017, 2018 Alexey Tourbin
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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <endian.h>
#include <t1ha.h>
#include "fpmap.h"

// The first version of this program was written in 2017.  To find unmet
// dependencies, the program gradually built two sorted sequences, the sequence
// of Requires and the sequence of Provides, sorted by name.  The names in each
// sequence were further front-encoded, like in locatedb(5).  This technique
// both saved some memory and accelerated merge sort (because the strings
// devoid of their common prefixes could be compared and merged much faster).
//
// Then two important developments happened in 2018:
// 1) Leo Yuiriev published t1ha2, a non-cryptographic 128-bit hash function.
// It compares favorably to other such functions in terms of both speed and
// quality, making fingerprinting techniques more reliable and affordable.
// (To mitigate the risks of using a non-cryptographic function, each hash
// operation in the code below is seeded with a random number obtained from
// auxv[AT_RANDOM] at program startup.)
// 2) At about the same time, I was experimenting with a new breed of
// probabilistic data structures rooted in the theory of balanced allocation,
// similar to what's been lately dubbed the "cuckoo filter".  Specifically
// I manged to produce the "fingerpint map" (fpmap for short), a very efficient
// auxiliary data structure for building big hash tables.
//
// So can an efficient lookup technique outperform efficient merge sort?
// Yes it can.  The main intuition here is that global lexicographical ordering
// is both somewhat expensive - O(n log n) - and redundant.  To merge Requires
// against Provides, only local grouping is strictly necessary.  The extra work
// can be avoided if we directly map each Requires/Provides name to its group.
// This will obviously cost only O(n).
//
// Suppose we create a new group for the dependency named "coreutils", and
// the dependency at hand turns out to be Provides.  We want the record to take
// as few bytes as possible.  Why, there can even be no such Requires, why
// bother.  Can we get away with just this?
//
//	+---+-+-+-+-+-+-+-+-*-+-+-+-+
//	| F |  ver  |   name hash   |
//	+---+-+-+-+-+-+-+-+-*-+-+-+-+
//
// "F" contains the flags.  Then we need to store a reference to the version,
// such as in "Provides: coreutils = 8.27", so that versioned Requires can be
// resolved.  But we don't need to store the whole name, because the name will
// only be needed to list unmet Requires, and each Requires comes with its
// name.  Instead, we store a 64-bit hash value.  The fpmap structure stores
// another 32+16 bits of the very same 128-bit hash, so we use something like
// 112-bit hash to identify names.  Pretty good actually, for our purposes.
//
// But what if the first dependency that we process is Requires?  Then we need
// to store the name, because we aren't sure if the dependency will be
// satisfied.  We store it as an immediate variable-length literal value.
// We also need to store a reference to the package with the dependency.
//
//	+---+-+-+-+-+-+-+-+-+-                    -+
//	| F |  ver  |  pkg  | c o r e u t i l s \0 |
//	+---+-+-+-+-+-+-+-+-+-                    -+
//
// But the corresponding Provides will likely show up next, and if it satisfies
// the Requires, the record can be converted to Provides: the name will be
// clobbered with the hash, because the hash is easier to compare.  Still,
// we can restore the name by recovering just the four missing characters.
//
//	+---+-+-+-+-+-+-+-+-*-+-+-+-+             -+
//	| F |  ver  |   name hash   | u t i l s \0 |
//	+---+-+-+-+-+-+-+-+-*-+-+-+-+             -+
//
// Now, this kind of "inplace merge" works only in simple cases, until we get
// more than one Requires that cannot be immediately satisfied, or more than
// one Provides version.  To aggregate a few different dependencies with the
// same name, we switch to an "external" malloc'd structure, and simply store
// a pointer to the structure.  But what about the name?  Well, if there's
// an immediate value, or if it can be restored, that's great.  Otherwise,
// we've got just enough bytes (4 out of 8 bytes initially taken by the hash)
// to store a reference to the name.
//
//	+---+-+-+-+-*-+-+-+-+-+-+-+-+
//	| F |      ptr      |nameref|
//	+---+-+-+-+-*-+-+-+-+-+-+-+-+

// So here's the dependency record.  Looks ominous but it isn't.
struct dep {
    uint8_t flags;
    union {
	// The Provides record with a hash.
	struct {
	    uint32_t ver;
	    uint64_t hash;
	} __attribute__((packed)) prov;
	// Either Requires or external record.
	struct {
	    union {
		struct {
		    uint32_t ver;
		    uint32_t pkg;
		};
		struct ext *ext;
	    };
	    // Immediate name or reference.
	    union {
		char name[1];
		uint32_t nameref;
	    };
	} __attribute__((packed));
    };
} __attribute__((packed));

// Note that about 85% of dependency names are provided but never required,
// and the average name length is about 32 characters.  We manage to pack such
// Provides into just 13 bytes (not including the version, but versions are
// shared).  I believe this is as good as it can get.
static_assert(sizeof(struct dep) == 13, "struct dep packing");

// The flags:
// An external record accessible via ptr.
#define F_EXT   0x01
// RPMSENSE dependency flags (such as ">="), unless F_EXT is set.
#define F_SENSE 0x0f
// Saw Provides with this name without a version, sticky.
#define F_PROV0 0x1f
// Saw Provides with this name with a version, sticky.
#define F_PROV1 0x2f
// The record is Provides, the name is identified by its 64-bit hash.
#define F_NHASH 0x4f
// The dependency name is identified with an immediate literal value, sticky.
// Can be clobbered with a hash and then restored.  When neither F_NHASH nor
// F_NLIT bits are set, the name is identified with a 4-byte reference.
#define F_NLIT  0x8f

// The global data structure.
struct {
    // The seed for fingerprinting.
    uint64_t seed;
    // Maps dependencies by name.
    struct fpmap *nmap;
    // Version strings are unique.
    struct fpmap *vmap;
    // The store.
    uint8_t *data;
    // How many bytes allocated.
    size_t alloc;
    // Current position for the write pointer.
    size_t pos;
} G;

// Add a Provides dependency without a version.
void addProv0(const char *name, size_t len)
{
    uint64_t hi;
    uint64_t lo = t1ha2_atonce128(&hi, name, len, G.seed);
    uint32_t pos[10];
    size_t n = fpmap_find(G.nmap, lo, pos);
    for (size_t i = 0; i < n; i++) {
	struct dep *d = (void *)(G.data + pos[i]);
	// Recheck the name.
	if (d->flags & F_NHASH) {
	    if (d->prov.hash != hi)
		continue;
	}
	else if (d->flags & F_NLIT) {
	    if (memcmp(name, d->name, len + 1))
		continue;
	}
	else {
	    if (memcmp(name, G.data + d->nameref, len + 1))
		continue;
	}
	// Piece of cake.
	d->flags |= F_PROV0;
	return;
    }
    // Not found.
    // TODO: insert.
}

#include <string.h>
#include <assert.h>

#ifdef DEBUG
#define Assert(x) assert(x)
#else
#define Assert(x) ((void) 0)
#endif

// A fast copying routine which can copy more bytes than requested.
// Works best with short strings when only one iteration may suffice.
// With constant n, such as n=4, memcpy should still be used.
#ifdef __SSE2__
#include <emmintrin.h>
static inline void copy(void *dst, const void *src, ssize_t n)
{
    Assert(n >= 0);
    while (1) {
	// Using two registers to copy 32 bytes works much faster
	// than using one register to copy 16 bytes at a time.
	__m128i xmm0 = _mm_loadu_si128((__m128i *) src + 0);
	__m128i xmm1 = _mm_loadu_si128((__m128i *) src + 1);
	_mm_storeu_si128((__m128i *) dst + 0, xmm0);
	_mm_storeu_si128((__m128i *) dst + 1, xmm1);
	n -= sizeof xmm0 + sizeof xmm1;
	if (n <= 0)
	    break;
	src = (__m128i *) src + 2;
	dst = (__m128i *) dst + 2;
    }
}
#else
#define copy memcpy
#endif

// Like memcmp(3) except that it finds the longest common prefix.
// Can load more bytes than requested.  Further does some clever
// cheating by clobbering its first const arg to and fro.
static inline size_t blcp(const char *s1, const char *s2, size_t n)
{
    const char *s0 = s1;
    unsigned char *cp = (unsigned char *) &s1[n];
    unsigned char c = *cp;
    *cp = ~(unsigned char) s2[n];
#ifdef __SSE2__
    while (1) {
	__m128i xmm1 = _mm_loadu_si128((__m128i *) s1);
	__m128i xmm2 = _mm_loadu_si128((__m128i *) s2);
	__m128i xmm3 = _mm_cmpeq_epi8(xmm1, xmm2);
	unsigned short mask = _mm_movemask_epi8(xmm3);
	if (mask != 0xffff) {
	    s1 += ffs(~mask) - 1;
	    break;
	}
	s1 += 16;
	s2 += 16;
    }
#else
    while (*s1 == *s2)
	s1++, s2++;
#endif
    *cp = c;
    return s1 - s0;
}

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
    // Only needs 4 bits, more bits are used only for padding,
    // so that all the bits in the structure are initialized.
    unsigned sense: 8;
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

static inline int depCmp(size_t i, size_t j, const char **names, int *versions, int *senses)
{
    int cmp = strcmp(names[i], names[j]);
    if (cmp) return cmp;
    // Deps with version go before the versionless ones.
    // This way, the latter are easier to discard.
    cmp = senses[j] - senses[i];
    if (cmp) return cmp;
    // Neither has a version?
    if (!senses[i]) return cmp;
    // Both have versions.
    Assert(senses[i] && senses[j]);
    // Order by version index in strtab.
    return versions[i] - versions[j];
}

static inline void depSwap(size_t i, size_t j, const char **names, int *versions, int *senses)
{
    const char *tmpName; int tmpVersion; int tmpSense;
    tmpName  = names[i], tmpVersion  = versions[i], tmpSense  = senses[i];
    names[i] = names[j], versions[i] = versions[j], senses[i] = senses[j];
    names[j] = tmpName,  versions[j] = tmpVersion,  senses[j] = tmpSense;
}

void sortDeps(int n, const char **names, int *versions, int *senses)
{
#define DEP_LESS(i, j) depCmp(i, j, names, versions, senses) < 0
#define DEP_SWAP(i, j) depSwap(i, j, names, versions, senses)
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
    union { const char **s; int *i; } versions = { td2.data };

    rc = headerGet(h, tags[!pkgIx][2], &td3, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td3.count == n);
    assert(td3.type == RPM_INT32_TYPE);
    int *flags = td3.data;


    for (int i = 0; i < n; i++) {
	flags[i] &= RPMSENSE_LESS | RPMSENSE_GREATER | RPMSENSE_EQUAL;
	versions.i[i] = flags[i] ? addVer(versions.s[i]) : 0;
    }

    sortDeps(n, names, versions.i, flags);

    size_t lastNameLen = 0;
    for (int i = 0; i < n; i++) {
	// Make a token.
	unsigned sense = flags[i];
	size_t nameLen = strlen(names[i]);
	assert(nameLen < 4096);
	size_t lcpLen = i ? lcp(names[i-1], lastNameLen, names[i], nameLen) : 0;
	// RequireName not changed?
	bool sameName = lcpLen == nameLen && nameLen == lastNameLen;
	if (sameName) {
	    // No version? It must be a dup then, as per depCmp ordering.
	    // E.g. "Requires: /bin/sh" and "Requires(pre): /bin/sh".
	    if (pkgIx && sense == 0)
		continue;
	    // The logic is only valid for Requires (hence pkgIx is checked);
	    // versionless Provides should not be eliminated, because they
	    // can resolve imzian "python(foo) < 0" dependencies.  Another
	    // more general rule can handle dups for both Requires and Provides.
	    if (flags[i-1] == flags[i] && versions.i[i-1] == versions.i[i])
		continue;
	}
	size_t len1 = nameLen - lcpLen;
	struct depToken token = { .sense = sense, .lcpLen = lcpLen, .len = len1 };
	// Put the record.
	assert(p + 4 + (sense ? 4 : 0) + (pkgIx ? 4 : 0) + len1 < end);
	memcpy(p, &token, 4);
	p += 4;
	if (sense)
	    memcpy(p, &versions.i[i], 4), p += 4;
	if (pkgIx)
	    memcpy(p, &pkgIx, 4), p += 4;
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
    while (p < end) {
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
    }
}

// Merge seq1 + seq2 into p.  The output size is bounded by seq1 + seq2.
// This is a state-of-the-art routine which produces the output without
// re-encoding the inputs (that is, it tries to reuse common prefixes;
// furthermore, when possible, it copies input records as is).  The code
// is not for the feeble-minded; understand it may help you the following
// THEOREM (Tourbin 2017)
// If lcp(a, b) = n and lcp(a, c) = m, then
//  * lcp(b, c) = min(n, m) if n != m;
//  * lcp(b, c) >= n if n = m.
static inline __attribute__((always_inline))
char *mergeSeq(const char *seq1, const char *end1, const char *seq2, const char *end2, bool isReq, char *p)
{
    // Decoded tokens, names[12]len are partial lengths.
    size_t lcp1len = 0, lcp2len = 0;
    size_t name1len = 0, name2len = 0;
    // Additional information from records.
    int ver1 = 0, ver2 = 0;
    int sense1 = 0, sense2 = 0;
    int pkg1 = 0, pkg2 = 0;
    // When a record is decoded, its sequence gets advanced.  Sometimes,
    // however, we want to look back to the start of the record.
    const char *seq1start = NULL, *seq2start = NULL;
    // When a few consecutive elements come from the same sequence,
    // they can be grouped and copied at once.
    const char *copy1start = seq1, *copy2start = seq2;
    // Common prefix between name1 and name2.
    size_t lcp12len = 0;
    // Common prefix between name1 and name2 from the previous iteration.
    size_t lastLcp12len = 0;
    // Which sequence gets advanced: (adv < 0) if seq1, (adv > 0) if seq2,
    // both only in the beginning.  Except for this special case, also
    // indicates which record was issued on the previous iteration.
    int adv = 0;
    // lcpLen of the element which gets advanced.
    size_t advLcpLen = 0;
#define decodeDepM(N)					\
    do {						\
	seq##N##start = seq##N;				\
	struct depToken token;				\
	memcpy(&token, seq##N, 4), seq##N += 4;		\
	sense##N = token.sense;				\
	ver##N = 0;					\
	if (sense##N)					\
	    memcpy(&ver##N, seq##N, 4), seq##N += 4;	\
	if (isReq)					\
	    memcpy(&pkg##N, seq##N, 4), seq##N += 4;	\
	lcp##N##len = advLcpLen = token.lcpLen;		\
	name##N##len = token.len;			\
	seq##N += name##N##len;				\
    } while (0)
#define putToken(N, lcpLen)					\
    do {							\
	size_t len = lcp##N##len + name##N##len - lcpLen;	\
	struct depToken token = { sense##N, lcpLen, len };	\
	memcpy(p, &token, 4), p += 4;				\
	if (sense##N) memcpy(p, &ver##N, 4), p += 4;		\
	if (isReq)    memcpy(p, &pkg##N, 4), p += 4;		\
	Assert(lcpLen >= lcp##N##len);				\
	copy##N##start = seq##N - name##N##len + (lcpLen - lcp##N##len); \
    } while (0)
    decodeDepM(1);
    decodeDepM(2);
    while (1) {
	lastLcp12len = lcp12len;
	// Comparison name1 <=> name2.
	int cmp;
	// Let advLcpLen=lcp(a,b) be the common prefix between the most
	// recently advanced element "b" and the preceding element from
	// the same sequence; let lastLcp12len=lcp(a,c) be the common
	// prefix between the opposing elements from seq1 and seq2 on
	// the previous iteration (during which the element "a" must have
	// been output).  By the THEOREM, we can infer the common prefix
	// between the currently opposing elements "b" and "c".
	if (advLcpLen != lastLcp12len) {
	    // Both sequences are advanced only in the beginning,
	    // in which case this branch is not taken, because
	    // advLcpLen = 0 (first elements don't have prefixes).
	    Assert(adv);
	    // Because inputs are sorted, we can further deduce the result
	    // of compassion.  If the prefix of "b" gets smaller, this
	    // means that some letters within "b" change and become
	    // lexicographically greater.
	    if (advLcpLen < lastLcp12len)
		lcp12len = advLcpLen, cmp = -adv;
	    else
		lcp12len = lastLcp12len, cmp = +adv;
	}
	else {
	    lcp12len = lastLcp12len;
	    // Intuitively, when merging, we cannot produce shorter
	    // common prefixes out of longer common prefixes.  Therefore,
	    // we believe all the bytes which we need to compare must be
	    // placed immediately in seq1 and seq2.
	    Assert(lcp12len >= lcp1len);
	    Assert(lcp12len >= lcp2len);
	    // Will compare [seq1-l1,seq2), [seq2-l2,seq2).
	    // In seq1, literals start at seq1 - name1len.  Subtracting
	    // lcp1len + name2len will logically position at the beginning
	    // of the string.
	    size_t l1 = lcp1len + name1len - lcp12len;
	    size_t l2 = lcp2len + name2len - lcp12len;
	    if (l2 == 0)
		cmp = l1;
	    else if (l1 == 0)
		cmp = -1;
	    else {
		const char *s1 = seq1 - l1;
		const char *s2 = seq2 - l2;
		cmp = (unsigned char) *s1 - (unsigned char) *s2;
		if (cmp == 0) {
		    size_t maxlen = l1 < l2 ? l1 : l2;
		    size_t len = blcp(s1, s2, maxlen);
		    lcp12len += len;
		    if (len < maxlen)
			cmp = (unsigned char) s1[len] - (unsigned char) s2[len];
		    else
			cmp = (int) l1 - (int) l2;
		}
	    }
	}
	// If the name is the same...
	if (cmp == 0) {
	    // Requires and Provides are handled differently.
	    if (isReq) {
		// Start with depCmp order.
		cmp = sense2 - sense1;
		// However, dependencies without version should go first.
		// This way it will be much easier to skip them in unmets().
		// This doesn't contradict depCmp order, because addDeps()
		// doesn't issue both versioned and unversioned Requires
		// with the same name.
		if (sense1 == 0 || sense2 == 0)
		    cmp = -cmp;
		// If both have versions, order by version.
		else if (cmp == 0)
		    cmp = ver1 - ver2;
		// As a last resort, Requires are ordered by pkg reference.
		if (cmp == 0)
		    cmp = pkg1 - pkg2;
	    }
	    else {
		// The same order as depCmp.  Versioned Provides go first.
		// They are more likely to satisfy Requires.
		cmp = sense2 - sense1;
		if (cmp == 0)
		    cmp = ver1 - ver2;
		// No last resort, identical Provides will be folded
		// into a single record.
	    }
	}
	// Fold identical dependencies, typically Provides
	// (e.g. i586-wine Provides: wine = %EVR).
	if (cmp == 0) {
	    if (adv <= 0) {
		// Break the adv=0 initial case.
		adv = -1;
		// Need to discard the opposing dup.
		if (seq2 == end2) {
		    // It was the last element in seq2.
		    copy(p, copy1start, end1 - copy1start), p += end1 - copy1start;
		    return p;
		}
		// Pretend the dup never existed.
		decodeDepM(2);
		// As if we've been opposing the next element.
		lcp12len = lcp2len;
		copy2start = seq2start;
		if (seq1 == end1) {
		    // Issuing the last element from seq1.
		    copy(p, copy1start, end1 - copy1start), p += end1 - copy1start;
		    // The remains of seq2 can be appended as is (because the name is the same).
		    copy(p, copy2start, end2 - copy2start), p += end2 - copy2start;
		    return p;
		}
		// Both elements are advanced for the next iteration.
		decodeDepM(1);
	    }
	    else {
		// When cmp == 0, direct copying is always possible.
		// This just mirrors the logic for the (adv > 0) case.
		Assert(adv > 0);
		if (seq1 == end1) {
		    copy(p, copy2start, end2 - copy2start), p += end2 - copy2start;
		    return p;
		}
		decodeDepM(1);
		lcp12len = lcp1len;
		copy1start = seq1start;
		if (seq2 == end2) {
		    copy(p, copy2start, end2 - copy2start), p += end2 - copy2start;
		    copy(p, copy1start, end1 - copy1start), p += end1 - copy1start;
		    return p;
		}
		decodeDepM(2);
	    }
	}
	else if (cmp < 0) {
	    if (adv > 0) {
		// Switching from seq2 to seq1, flush seq2.
		copy(p, copy2start, seq2start - copy2start), p += seq2start - copy2start;
		copy2start = seq2start;
		// Last put was the record from seq2, after being compared
		// to the current record from seq1 that we're now issuing.
		// Therefore, we already know the common prefix between
		// the output elements.  If the input prefix is different,
		// the token needs to be reassembled (and putToken will
		// set the new copy1start).
		if (lastLcp12len != lcp1len)
		    putToken(1, lastLcp12len);
	    }
	    adv = -1;
	    if (seq1 == end1) {
		copy(p, copy1start, end1 - copy1start), p += end1 - copy1start;
		Assert(seq2start == copy2start);
		if (lcp12len != lcp2len)
		    putToken(2, lcp12len);
		copy(p, copy2start, end2 - copy2start), p += end2 - copy2start;
		return p;
	    }
	    decodeDepM(1);
	}
	else {
	    if (adv < 0) {
		copy(p, copy1start, seq1start - copy1start), p += seq1start - copy1start;
		copy1start = seq1start;
		if (lastLcp12len != lcp2len)
		    putToken(2, lastLcp12len);
	    }
	    adv = +1;
	    if (seq2 == end2) {
		copy(p, copy2start, end2 - copy2start), p += end2 - copy2start;
		Assert(seq1start == copy1start);
		if (lcp12len != lcp1len)
		    putToken(1, lcp12len);
		copy(p, copy1start, end1 - copy1start), p += end1 - copy1start;
		return p;
	    }
	    decodeDepM(2);
	}
    }
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
    if (verR == verP) {
	if (senseR & senseP & RPMSENSE_EQUAL)
	    return true;
    }
    else if (senseR == RPMSENSE_EQUAL && senseP == RPMSENSE_EQUAL) {
	if (strcmp(strtab + verR, strtab + verP) == 0)
	    return true;
    }

#ifdef ALT_RPM_API
    bool ret = rpmRangesOverlap("", strtab + verP, senseP,
				"", strtab + verR, senseR,
				_rpmds_nopromote);
#else
    rpmstrPool pool = *poolp;
    if (!pool)
	pool = *poolp = rpmstrPoolCreate();
    rpmds dsR = *dsRp;
    if (!dsR)
	dsR = *dsRp = rpmdsSinglePool(pool, RPMTAG_REQUIRENAME, "", strtab + verR, senseR);
    rpmds dsP = rpmdsSinglePool(pool, RPMTAG_PROVIDENAME, "", strtab + verP, senseP);
    bool ret = rpmdsCompare(dsP, dsR);
    rpmdsFree(dsP);
#endif
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
// Update: there are now two separate stacks for Requires and Provides.
struct stackEnt {
    int npkg;
    int off;
};

// With the stack depth of 30, up to a billion packages can be processed.
// The real limitation lies within the strtab size and SEQBUFSIZE.
struct stackEnt reqStack[30], provStack[30];
int nreqStack, nprovStack;

// Merge the two topmost stack entries.
void mergeReqStack(void)
{
#define mergeStack(dep, isReq)						\
    do {								\
	int off1 = dep##Stack[n##dep##Stack-1].off;			\
	int off2 = dep##Stack[n##dep##Stack-2].off;			\
	int fill = mergeSeq(dep##Seq + off1, dep##Seq + dep##Fill,	\
			    dep##Seq + off2, dep##Seq + off1,		\
			    isReq, tmpSeq) - tmpSeq;			\
	if (n##dep##Stack > 2) /* copy back */				\
	    memcpy(dep##Seq + off2, tmpSeq, fill);			\
	else { /* switch places */					\
	    char *p = dep##Seq;						\
	    dep##Seq = tmpSeq, tmpSeq = p;				\
	}								\
	dep##Fill = off2 + fill;					\
	dep##Stack[n##dep##Stack-2].npkg +=				\
	dep##Stack[n##dep##Stack-1].npkg;				\
	n##dep##Stack--;						\
    } while (0)
    mergeStack(req, true);
}
void mergeProvStack(void)
{
    mergeStack(prov, false);
}

// Peek at the first character in a sequence.
unsigned char seqFirstChar(const char *p, bool isReq)
{
    struct depToken token;
    memcpy(&token, p, 4), p += 4;
    if (token.sense)
	p += 4;
    if (isReq)
	p += 4;
    return *p;
}

int build_deps;
int verbose;
int npkg;

void addHeader(Header h)
{
    // Add the package.
    int pkgIx = addPkg(h);
    if (verbose > 1)
	fprintf(stderr, "loading %s\n", strtab + pkgIx);
    npkg++;
    // If --build-deps is enabled, only BuildRequires should be checked;
    // in other words, Requires from regular packages should be skipped.
    bool isSource = headerIsSource(h);
    if (build_deps && !isSource)
	goto noreq;
    // Add Requires.
    int reqOff = reqFill;
    reqFill = addReq(h, pkgIx, reqSeq + reqFill, reqSeq + SEQBUFSIZE) - reqSeq;
    // Push onto the stack.
    reqStack[nreqStack++] = (struct stackEnt) { .npkg = 1, .off = reqOff };
    // Run merges.
    while (nreqStack > 1 && reqStack[nreqStack-1].npkg >= reqStack[nreqStack-2].npkg)
	mergeReqStack();
noreq:
    // Source rpms have neither Provides nor Filenames which could satisfy Requires.
    if (isSource)
	return;
    // Add Filenames.
    int prov2off = provFill;
    provFill = addFnames(h, provSeq + provFill, provSeq + SEQBUFSIZE) - provSeq;
    // Add Provides.
    int prov1off = provFill;
    provFill = addProv(h, provSeq + provFill, provSeq + SEQBUFSIZE) - provSeq;
    provStack[nprovStack++] = (struct stackEnt) { .npkg = 1, .off = prov2off };
    // Merge Provides+Filenames, unless Provides has no paths.
    if (prov1off > prov2off && seqFirstChar(provSeq + prov1off, false) <= '/') {
	provStack[nprovStack++] = (struct stackEnt) { .npkg = 1, .off = prov1off };
	mergeProvStack();
	provStack[nprovStack-1].npkg = 1;
    }
    while (nprovStack > 1 && provStack[nprovStack-1].npkg >= provStack[nprovStack-2].npkg)
	mergeProvStack();
}

void addRpmlibProv(void)
{
    rpmds ds = NULL;
    int rc = rpmdsRpmlib(&ds, NULL);
    assert(rc == 0 && ds);
    Header h = headerNew();
    assert(h);
    rc = rpmdsPutToHeader(ds, h);
    assert(rc == 0);
    int provOff = provFill;
    provFill = addProv(h, provSeq + provFill, provSeq + SEQBUFSIZE) - provSeq;
    assert(provFill > provOff);
    provStack[nprovStack++] = (struct stackEnt) { .npkg = 1, .off = provOff };
    rpmdsFree(ds);
    headerFree(h);
}

#include <zpkglist.h>
#include <unistd.h>

bool processFd(int fd, const char *argv0, const char *fname)
{
    const char *err[2];
    struct zpkglistReader *z;
    const char *func = "zpkglistFdopen";
    ssize_t ret = zpkglistFdopen(&z, fd, err);
    if (ret > 0) {
	void *blob;
	func = "zpkglistNextMalloc";
	while ((ret = zpkglistNextMalloc(z, &blob, NULL, false, err)) > 0) {
	    Header h = headerImport(blob, ret, HEADERIMPORT_FAST);
	    if (h == NULL) {
		free(blob);
		func = err[0] = "headerImport",
		err[1] = "import failed";
		ret = -1;
		break;
	    }
	    addHeader(h);
	    headerFree(h);
	}
	zpkglistFree(z);
    }
    close(fd);
    if (ret < 0) {
	if (strcmp(func, err[0]) == 0 || strncmp(err[0], "zpkglist", 8) == 0)
	    fprintf(stderr, "%s: %s: %s: %s\n", argv0, fname, err[0], err[1]);
	else
	    fprintf(stderr, "%s: %s: %s: %s: %s\n", argv0, fname, func, err[0], err[1]);
	return false;
    }
    return true;
}

#include <getopt.h>
#include <fcntl.h> // O_RDONLY

#ifdef DEBUG
unsigned djb(const char *p, const char *end)
{
    unsigned hash = 5381;
    while (p < end)
	hash = 33 * hash + (unsigned char) *p++;
    return hash;
}
#endif

int dump_requires;
int dump_provides;

const struct option longopts[] = {
    { "dump-requires", no_argument, &dump_requires, 1 },
    { "dump-provides", no_argument, &dump_provides, 1 },
    { "build-deps", no_argument, &build_deps, 1 },
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
    else if (argc == 0 && isatty(0)) {
	fprintf(stderr, "refusing to read binary data from a terminal\n");
	usage = 1;
    }
    if (usage) {
	fprintf(stderr, "Usage: %s [PKGLIST...]\n", argv0);
	return 1;
    }
    addRpmlibProv();
    // With no args, process stdin.
    char *assume_argv[] = { "-", NULL };
    if (argc == 0)
	argc = 1, argv = assume_argv;
    int maxReqFill = 0;
    for (int i = 0; i <= argc; i++) {
	// Assume the last arg is "--".
	if (i == argc || strcmp(argv[i], "--") == 0) {
	    if (!nreqStack)
		continue;
	    while (nreqStack > 1) mergeReqStack();
	    while (nprovStack > 1) mergeProvStack();
#ifdef DEBUG
	    fprintf(stderr, "reqSeq size=%d hash=%08x\n",
		    reqFill, djb(reqSeq, reqSeq + reqFill));
#endif
	    if (reqFill > maxReqFill)
		maxReqFill = reqFill;
	    if (dump_requires)
		dumpSeq(reqSeq, reqSeq + reqFill, true);
	    else if (!dump_provides)
		unmets(reqSeq, reqSeq + reqFill, provSeq, provSeq + provFill);
	    // This portion of Requires has been processed.
	    reqFill = 0, nreqStack = 0;
	}
	else {
	    int fd = 0;
	    const char *fname = argv[i];
	    if (strcmp(argv[i], "-") == 0)
		fname = "<stdin>";
	    else {
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
		    fprintf(stderr, "%s: %s: open: %m\n", argv0, fname);
		    return 1;
		}
	    }
	    if (!processFd(fd, argv0, fname))
		return 1;
	}
    }
    while (nprovStack > 1) mergeProvStack();
#ifdef DEBUG
    fprintf(stderr, "provSeq size=%d hash=%08x\n",
	    provFill, djb(provSeq, provSeq + provFill));
#endif
    if (dump_provides)
	dumpSeq(provSeq, provSeq + provFill, false);
    if (verbose)
	fprintf(stderr, "loaded %d headers (%.1fM strtab, %.1fM req, %.1fM prov)\n",
			 npkg,
			(double) strtabPos  / (1 << 20),
			(double) maxReqFill / (1 << 20),
			(double) provFill   / (1 << 20));
    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
