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

// The string tabs for %{RequireVersion} and %{ProvideVersion}.
// Since they are mostly occupied by set-versions, I make no
// attempts to find dups.
char depVerTab[256<<20];
int depVerPos;

#include <string.h>
#include <assert.h>

// This program builds and processes two big sequences: the sequence
// of Requires and the sequence of Provides (the latter also includes
// %{Filenames}).  A sequence is made of variable-length records.
// Each record starts with a token.
struct provToken {
    // 1 = lt | 2 = gt | 4 = eq
    // 0 = no version
    unsigned sense: 3;
    // The sequence of Provides is sorted by name; the names are further
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
    // Right after the token there goes a 4-byte version, unless sense is 0.
    // And so Provide records look like this:
    // - sense == 0:
    //   +-+-+-+-+ +-    -+
    //   | token | | name |
    //   +-+-+-+-+ +-    -+
    // - otherwise:
    //   +-+-+-+-+ +-+-+-+-+ +-    -+
    //   | token | |  ver  | | name |
    //   +-+-+-+-+ +-+-+-+-+ +-    -+
};

// The string tab where package names are stored.
char pkgNameTab[64<<20];
int pkgNamePos;

// Package names are referenced multiple times (by each Require record
// from a package, 9 of them on average).  Instead of identifying packages
// by their offset in pkgNameTab[], the following table makes it possible
// to identify packages by their number.  The maximum number of packages that
// can be processed simultaneously is 1M, due to 20-bit indexes, see below.
int pkgIxTab[1<<20];
int pkgIxPos;

// Requires dependencies are structured similarly to provides, except that
// the token additionally stores the 20-bit index that identifies the package
// the dependency came from.
struct reqToken {
    unsigned sense: 3;
    int delta: 13;
    unsigned len: 12;
    unsigned pkg: 20;
    // Right after the token there goes a 4-byte version, unless sense is 0.
    // And so Require records look like this:
    // - sense == 0:
    //   +-+-+-+-+-+-+ +-    -+
    //   |   token   | | name |
    //   +-+-+-+-+-+-+ +-    -+
    // - otherwise:
    //   +-+-+-+-+-+-+ +-+-+-+-+ +-    -+
    //   |   token   | |  ver  | | name |
    //   +-+-+-+-+-+-+ +-+-+-+-+ +-    -+
} __attribute__((packed));

static_assert(sizeof(struct provToken) == 4, "provToken");
static_assert(sizeof(struct reqToken)  == 6, "reqToken");

#include <rpm/rpmlib.h>

// Add the package to pkgNameTab.
int addPkg(Header h)
{
    int pkgIx = pkgIxPos;
    pkgIxTab[pkgIxPos++] = pkgNamePos;

    const char *name = headerGetString(h, RPMTAG_NAME);
    assert(name);
    size_t len = strlen(name);
    assert(pkgNamePos + len + 1 < sizeof pkgNameTab);
    memcpy(pkgNameTab + pkgNamePos, name, len);
    pkgNamePos += len;
    pkgNameTab[pkgNamePos++] = ' ';

    char *EVR = headerGetAsString(h, RPMTAG_EVR);
    assert(EVR);
    len = strlen(EVR);
    assert(pkgNamePos + len + 1 < sizeof pkgNameTab);
    memcpy(pkgNameTab + pkgNamePos, EVR, len + 1);
    pkgNamePos += len + 1;
    free(EVR);

    return pkgIx;
}

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

char frame[8<<20];

void addReq(Header h, int pkgIx)
{
    struct rpmtd_s td1, td2, td3;
    int rc = headerGet(h, RPMTAG_REQUIRENAME, &td1, HEADERGET_MINMEM);
    // Assume that Requires must be present - someplace, they check
    // for the "rpmlib(PayloadIsLzma)" dependency as mandatory.
    assert(rc == 1);
    assert(td1.count > 0);
    int n = td1.count;
    assert(td1.type == RPM_STRING_ARRAY_TYPE);
    const char **names = td1.data;

    rc = headerGet(h, RPMTAG_REQUIREVERSION, &td2, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td2.count == n);
    assert(td2.type == RPM_STRING_ARRAY_TYPE);
    const char **versions = td2.data;

    rc = headerGet(h, RPMTAG_REQUIREFLAGS, &td3, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td3.count == n);
    assert(td3.type == RPM_INT32_TYPE);
    int *flags = td3.data;

    sortDeps(n, names, versions, flags);

    char *p = frame, *end = p + sizeof frame;
    size_t lastNameLen = 0, lastLcpLen = 0;
    for (int i = 0; i < n; i++) {
	// Make a token.
	unsigned sense = (flags[i] & RPMSENSE_SENSEMASK) >> 1;
	assert(sense < 8);
	size_t nameLen = strlen(names[i]);
	assert(nameLen < 4096);
	size_t lcpLen = i ? lcp(names[i-1], lastNameLen, names[i], nameLen) : 0;
	int delta = (int) lcpLen - (int) lastLcpLen;
	size_t len1 = nameLen - lcpLen;
	struct reqToken token = {
	    .sense = sense,
	    .delta = delta,
	    .len = len1,
	    .pkg = pkgIx,
	};
	// Name not changed?
	if (delta == 0 && len1 == 0)
	    // No version? It must be a dup then, as per depCmp ordering.
	    // E.g. "Requires: /bin/sh" and "Requires(pre): /bin/sh".
	    if (sense == 0)
		continue;
	// Put the record.
	assert(p + 6 + (sense ? 4 : 0) + len1 < end);
	memcpy(p, &token, 6);
	p += 6;
	if (sense) {
	    // Put version.
	    size_t vlen = strlen(versions[i]);
	    assert(depVerPos + vlen + 1 < sizeof depVerTab);
	    memcpy(depVerTab + depVerPos, versions[i], vlen + 1);
	    memcpy(p, &depVerPos, 4);
	    depVerPos += vlen + 1;
	    p += 4;
	}
	memcpy(p, names[i] + lcpLen, len1);
	p += len1;
	lastNameLen = nameLen, lastLcpLen = lcpLen;
    }

    rpmtdFreeData(&td1);
    rpmtdFreeData(&td2);
    rpmtdFreeData(&td3);
}

void addProv(Header h)
{
    struct rpmtd_s td1, td2, td3;
    int rc = headerGet(h, RPMTAG_PROVIDENAME, &td1, HEADERGET_MINMEM);
    // Assume that Provides must be present, due to "Provides: %name = %EVR".
    assert(rc == 1);
    assert(td1.count > 0);
    int n = td1.count;
    assert(td1.type == RPM_STRING_ARRAY_TYPE);
    const char **names = td1.data;

    rc = headerGet(h, RPMTAG_PROVIDEVERSION, &td2, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td2.count == n);
    assert(td2.type == RPM_STRING_ARRAY_TYPE);
    const char **versions = td2.data;

    rc = headerGet(h, RPMTAG_PROVIDEFLAGS, &td3, HEADERGET_MINMEM);
    assert(rc == 1);
    assert(td3.count == n);
    assert(td3.type == RPM_INT32_TYPE);
    int *flags = td3.data;

    sortDeps(n, names, versions, flags);

    // Load filenames.
    struct rpmtd_s td4, td5, td6;
    int bnc = 0;
    const char **bn = NULL, **dn = NULL;
    int *di = NULL;
    if (headerGet(h, RPMTAG_BASENAMES, &td4, HEADERGET_MINMEM) == 1) {
	assert(td4.type == RPM_STRING_ARRAY_TYPE);
	assert(td4.count > 0);
	bnc = td4.count;
	bn = td4.data;

	rc = headerGet(h, RPMTAG_DIRNAMES, &td5, HEADERGET_MINMEM);
	assert(rc == 1);
	assert(td5.type == RPM_STRING_ARRAY_TYPE);
	assert(td5.count > 0);
	dn = td5.data;

	rc = headerGet(h, RPMTAG_DIRINDEXES, &td6, HEADERGET_MINMEM);
	assert(rc == 1);
	assert(td6.type == RPM_INT32_TYPE);
	assert(td6.count == bnc);
	di = td6.data;
    }

    // Filename stuff.
    char fname[4096];
    size_t fnameLen = 0;
    bool validFname = false;
    int lastDi = -1;
    size_t dirLen = 0;

    // Either last Provides or fname.
    const char *lastName = NULL;
    char lastNameBuf[4096];
    size_t lastNameLen = 0, lastLcpLen = 0;

    // Merge Provides with filenames.
    char *p = frame, *end = p + sizeof frame;
    int i = 0, j = 0;
    while (i < n || j < bnc) {
	// Generate or update filename.
	if (j < bnc && !validFname) {
	    validFname = true;
	    if (lastDi != di[j]) {
		lastDi = di[j];
		dirLen = strlen(dn[lastDi]);
		assert(dirLen < 4096);
		memcpy(fname, dn[lastDi], dirLen);
	    }
	    size_t bnLen = strlen(bn[j]);
	    assert(dirLen + bnLen < 4096);
	    memcpy(fname + dirLen, bn[j], bnLen + 1);
	    fnameLen = dirLen + bnLen;
	}
	// Find out name/version/sense to be encoded.
	const char *name = NULL, *version = NULL;
	size_t nameLen = 0;
	unsigned sense = 0;
	if (i < n && j < bnc) {
	    int cmp = strcmp(names[i], fname);
	    if (cmp <= 0) {
		// Take Provides.
		name = names[i], nameLen = strlen(name);
		version = versions[i], sense = (flags[i] & RPMSENSE_SENSEMASK) >> 1;
		i++;
		// Advance filenames as well?
		if (cmp == 0)
		    j++, validFname = false;
	    }
	    else {
		// Take Filename, leave Provides for the next iteration.
		name = fname, nameLen = fnameLen, validFname = false;
		j++;
	    }
	}
	else if (i < n) {
	    name = names[i], nameLen = strlen(name);
	    version = versions[i], sense = (flags[i] & RPMSENSE_SENSEMASK) >> 1;
	    i++;
	}
	else {
	    assert(j < bnc);
	    name = fname, nameLen = fnameLen, validFname = false;
	    j++;
	}
	// Make a token.
	assert(nameLen > 0);
	assert(nameLen < 4096);
	size_t lcpLen = i || j ? lcp(lastName, lastNameLen, name, nameLen) : 0;
	int delta = (int) lcpLen - (int) lastLcpLen;
	size_t len1 = nameLen - lcpLen;
	struct provToken token = {
	    .sense = sense,
	    .delta = delta,
	    .len = len1,
	};
	// Put the record.
	assert(p + 4 + (sense ? 4 : 0) + len1 < end);
	memcpy(p, &token, 4);
	p += 4;
	if (sense) {
	    // Put version.
	    size_t vlen = strlen(version);
	    assert(depVerPos + vlen + 1 < sizeof depVerTab);
	    memcpy(depVerTab + depVerPos, version, vlen + 1);
	    memcpy(p, &depVerPos, 4);
	    depVerPos += vlen + 1;
	    p += 4;
	}
	memcpy(p, name + lcpLen, len1);
	p += len1;
	// Copy fname for lastName.
	lastName = name == fname ? memcpy(lastNameBuf, name, nameLen + 1) : name;
	lastNameLen = nameLen, lastLcpLen = lcpLen;
    }

    rpmtdFreeData(&td1);
    rpmtdFreeData(&td2);
    rpmtdFreeData(&td3);
    if (bnc) {
	rpmtdFreeData(&td4);
	rpmtdFreeData(&td5);
	rpmtdFreeData(&td6);
    }
}

int verbose;

void addHeader(Header h)
{
    int pkgIx = addPkg(h);
    addReq(h, pkgIx);
    addProv(h);
    if (verbose > 1)
	fprintf(stderr, "loaded %s\n", pkgNameTab + pkgIxTab[pkgIx]);
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
	fprintf(stderr, "loaded %d headers (%dM out of %zuM pkgTab)\n", pkgIxPos,
			1 + (pkgNamePos >> 20), sizeof pkgNameTab >> 20);
    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet:
