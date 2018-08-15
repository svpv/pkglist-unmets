// Copyright (c) 2018 Alexey Tourbin
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

#include <stdint.h>
#include <string.h>

// Format %u efficiently, writes trailing null characters.
static size_t fmtU32(uint32_t v, char out[16])
{
    char buf[32], *b = buf + 16;
    memset(b, 0, 16);
    // Alexandrescu, "Three Optimization Tips for C++"
    static const char digits[200] =
	"00010203040506070809"
	"10111213141516171819"
	"20212223242526272829"
	"30313233343536373839"
	"40414243444546474849"
	"50515253545556575859"
	"60616263646566676869"
	"70717273747576777879"
	"80818283848586878889"
	"90919293949596979899";
    while (v >= 100) {
	uint32_t r = v % 100;
	v /= 100;
	memcpy(b -= 2, digits + 2 * r, 2);
    }
    if (v >= 10)
	memcpy(b -= 2, digits + 2 * v, 2);
    else
	*--b = v + '0';
    memcpy(out, b, 16);
    return buf + 16 - b;
}

#ifdef __SSE2__
#include <emmintrin.h>
#endif
#include <arpa/inet.h>
#include <rpm/rpmtag.h>
#include "hdrblob.h"

#define unlikely(cond) __builtin_expect(cond, 0)

static inline const char *getStr(const struct HeaderEntry *e, int tag,
	const char *data, size_t dl)
{
#ifdef __SSE2__
    __m128i xmm1 = _mm_set_epi32(htonl(1), -1, htonl(RPM_STRING_TYPE), htonl(tag));
    __m128i xmm2 = _mm_loadu_si128((__m128i *) e);
    __m128i xmm3 = _mm_cmpeq_epi32(xmm1, xmm2);
    int mask = _mm_movemask_epi8(xmm3);
    if (unlikely(mask != 0xf0ff))
	return NULL;
#else
    if (unlikely(e->tag != htonl(tag)))
	return NULL;
    if (unlikely(e->type != htonl(RPM_STRING_TYPE)))
	return NULL;
    if (unlikely(e->cnt != htonl(1)))
	return NULL;
#endif
    size_t off0 = ntohl(e->off);
    size_t off1 = ntohl(e[1].off);
    if (unlikely(off0 >= dl))
	return NULL;
    if (unlikely(off0 >= off1))
	return NULL;
    if (unlikely(data[off1-1] != '\0'))
	return NULL;
    if (unlikely(data[off0] == '\0'))
	return NULL;
    return &data[off0];
}

static inline bool getU32(const struct HeaderEntry *e, int tag,
	uint32_t *val, const char *data, size_t dl)
{
    if (unlikely(e->tag != htonl(tag)))
	return false;
    if (unlikely(e->type != htonl(RPM_INT32_TYPE)))
	return false;
    if (unlikely(e->cnt != htonl(1)))
	return false;
    size_t off = ntohl(e->off);
    if (unlikely(off > dl - 4))
	return false;
    if (unlikely(off & 3))
	return false;
    *val = ntohl(*(uint32_t *)(data + off));
    return true;
}

// Package location relative to the repo, e.g. RPMS.classic or ../SRPMS.hasher.
// (This is the last tag used by genpkglist.)
#define CRPMTAG_DIRECTORY         1000010
// Maps src.rpm to its subpackages, e.g. foo.src.rpm => [foo, libfoo, libfoo-devel].
// (This is the last tag used by gensrclist.)
#define CRPMTAG_BINARY            1000011

size_t hdrblobNEVRA(const struct HeaderBlob *blob, size_t blobSize,
	const char **N, char E[16], const char **V, const char **R, const char **A)
{
    size_t il = ntohl(blob->il);
    size_t dl = ntohl(blob->dl);
    if (unlikely(il < 5))
	return -1;
    const struct HeaderEntry *ee = blob->ee;
    const void *data = ee + il;
    *N = getStr(&ee[1], RPMTAG_N, data, dl); if (unlikely(!*N)) return -1;
    *V = getStr(&ee[2], RPMTAG_V, data, dl); if (unlikely(!*V)) return -1;
    *R = getStr(&ee[3], RPMTAG_R, data, dl); if (unlikely(!*R)) return -1;
#ifdef HDRBLOB_DEBUG // These checks are somewhat expensive.
    // Adjacent NVR, no embedded null bytes.
    if (rawmemchr(*N, '\0') + 1 != *V) return -1;
    if (rawmemchr(*V, '\0') + 1 != *R) return -1;
#endif
    // Deal with Epoch.
    size_t ret;
    const struct HeaderEntry *e = &ee[4];
    if (ntohl(e->tag) > RPMTAG_E)
	ret = 0;
    else {
	uint32_t E32;
	if (!getU32(e, RPMTAG_E, &E32, data, dl))
	    return -1;
	if (E32 >= 10)
	    ret = fmtU32(E32, E);
	else {
	    memset(E, 0, 16);
	    *E = E32 + '0';
	    ret = 1;
	}
	e++;
    }
    // Is it a source package?
    if (ee[il-1].tag == htonl(CRPMTAG_BINARY)) {
	*A = "src";
	return ret;
    }
    if (ee[il-1].tag != htonl(CRPMTAG_DIRECTORY))
	return -1;
    // Deal with Arch.
    while (ntohl(e->tag) < RPMTAG_ARCH)
	e++;
    *A = getStr(e, RPMTAG_ARCH, data, dl);
    if (unlikely(!*A))
	return -1;
    return ret;
}
