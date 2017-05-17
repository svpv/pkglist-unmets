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

// String tabs for %{RequireVersion} and %{ProvideVersion}.
// Since they are mostly occupied by set-versions, I make no
// attempts to find dups.  The maximum size of 256M is due
// to 28-bit indexes, see below.
char reqVerTab[256<<20], provVerTab[256<<20];
int reqVerPos, provVerPos;

#include <string.h>
#include <assert.h>

// This program builds and processes two big sequences: the sequence
// of Requires and the sequence of Provides (the latter also includes
// %{Filenames}).  A sequence is made of variable-length records.
// Each record starts with a 4-byte token.
struct provToken {
    // 1 = lt | 2 = gt | 4 = eq
    // 0 = no version
    unsigned sense: 3;
    // Right after the token there goes a 3-byte version, unless sense is 0;
    // with hight bits taken from bigVer, it makes a 28-bit index into
    // provVerTab[].
    unsigned bigVer: 4;
    // The sequence of Provides is sorted by name; the names are further
    // front-encoded, roughly like in locatedb(5).  The delta field uses the
    // range of [-4095,4095] to encode the change in the common prefix length;
    // the value of -4096, if ever used, should reset the prefix length to 0.
    int delta: 13;
    // This is the length of the rest of the name after the common prefix.
    // The name is stored after the 3-byte version, without a terminating
    // '\0' character (thus when len is 0, nothing is stored).  In the worst
    // case, the 12-bit length limits the name to 4095 characters, which indeed
    // matches PATH_MAX.
    unsigned len: 12;
    // And so Provide records look like this:
    // - sense == 0:
    //   +-+-+-+-+ +-    -+
    //   | token | | name |
    //   +-+-+-+-+ +-    -+
    // - otherwise:
    //   +-+-+-+-+ +-+-+-+ +-    -+
    //   | token | | ver | | name |
    //   +-+-+-+-+ +-+-+-+ +-    -+
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

// Unversioned dependencies are structured similarly to Provides.
struct reqToken {
    // 0, no version
    unsigned sense: 3;
    // (Since there is no version, bigVer is replaced with bigPkg.)
    // Right after the token there goes a 2-byte package; along with
    // hight bits taken from bigPkg, it makes a 20-bit index into pkgIx[].
    unsigned bigPkg: 4;
    // These are the same as in provToken.  In particular, fairly long
    // RequresNames (approaching PATH_MAX) are fully supported.
    int delta: 13;
    unsigned len: 12;
    // And so unversioned Require records look like this:
    //   +-+-+-+-+ +-+-+ +-    -+
    //   | token | |pkg| + name |
    //   +-+-+-+-+ +-+-+ +-    -+
};

// Things get a little bit more complicated with versioned dependencies.
// Those may need to reference both bigVer and bigPkg, but the 32 bits that
// I have sorta cannot be stretched.  Therefore, I come up with a clever
// device of limiting the length of versioned RequireNames to 1023 characters.
// The difference is that unversioned path-like Requires can be easily
// generated by symlinks.req (and so the question then becomes whether
// symlinks are permitted deeply in the packaged hierarchy).  With versioned
// dependencies, it's harder to fancy a valid example.
struct reqTokenV {
    // not 0
    unsigned sense: 3;
    unsigned bigVer: 4;
    unsigned bigPkg: 4;
    int delta: 11;
    unsigned len: 10;
    // And so versioned Require records look like this:
    //   +-+-+-+-+ +-+-+-+ +-+-+ +-    -+
    //   | token | | ver + |pkg| + name |
    //   +-+-+-+-+ +-+-+-+ +-+-+ +-    -+
};

static_assert(sizeof(struct provToken) == 4, "provToken");
static_assert(sizeof(struct reqToken)  == 4, "reqToken");
static_assert(sizeof(struct reqTokenV) == 4, "reqTokenV");

#include <rpm/rpmlib.h>

void addHeader(Header h)
{
}

int main()
{
    FD_t Fd = fdDup(0);
    Header h;
    while ((h = headerRead(Fd, HEADER_MAGIC_YES))) {
	addHeader(h);
	headerFree(h);
    }
    Fclose(Fd);
    return 0;
}

// ex:set ts=8 sts=4 sw=4 noet: