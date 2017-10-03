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

#ifndef LCP_H
#define LCP_H

#ifdef __SSE2__
#include <emmintrin.h>
#include <strings.h>
#endif

// the longest common prefix
static size_t lcp(const char *s1, size_t len1,
		  const char *s2, size_t len2)
{
    const char *s0 = s1;
#ifdef __SSE2__
    size_t minlen = len1 < len2 ? len1 : len2;
    size_t xmmsize = minlen / 16;
    size_t xmmleft = minlen % 16;
    __m128i xmm1, xmm2;
    unsigned short mask;
    if (xmmsize % 2) {
	xmm1 = _mm_loadu_si128((__m128i *) s1);
	xmm2 = _mm_loadu_si128((__m128i *) s2);
	xmm1 = _mm_cmpeq_epi8(xmm1, xmm2);
	mask = _mm_movemask_epi8(xmm1);
	if (mask != 0xffff) {
	    s1 += ffs(~mask) - 1;
	    return s1 - s0;
	}
	s1 += 16, s2 += 16;
	xmmsize--;
    }
    while (xmmsize) {
	xmm1 = _mm_loadu_si128((__m128i *) s1);
	xmm2 = _mm_loadu_si128((__m128i *) s2);
	xmm1 = _mm_cmpeq_epi8(xmm1, xmm2);
	mask = _mm_movemask_epi8(xmm1);
	if (mask != 0xffff) {
	    s1 += ffs(~mask) - 1;
	    return s1 - s0;
	}
	s1 += 16, s2 += 16;
	xmm1 = _mm_loadu_si128((__m128i *) s1);
	xmm2 = _mm_loadu_si128((__m128i *) s2);
	xmm1 = _mm_cmpeq_epi8(xmm1, xmm2);
	mask = _mm_movemask_epi8(xmm1);
	if (mask != 0xffff) {
	    s1 += ffs(~mask) - 1;
	    return s1 - s0;
	}
	s1 += 16, s2 += 16;
	xmmsize -= 2;
    }
#if 1
    // this code which handles the remaining bytes is tricky; one way
    // to test is to comment it out and see if the output is the same
    size_t len = s1 - s0;
    switch (xmmleft) {
    case 0:
	return len;
    case 1:
	return len + (*s1 == *s2);
    case 2:
	if (*s1 != *s2)
	    return len;
	return len + 1 + (s1[1] == s2[1]);
    case 3:
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 4:
	if (*(int *) s1 == *(int *) s2)
	    return len + 4;
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 5:
	if (*(int *) s1 == *(int *) s2)
	    return len + 4 + (s1[4] == s2[4]);
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 6:
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6;
	    return len + 4 + (s1[4] == s2[4]);
	}
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 7:
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
	}
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 8:
	if (*(long long *) s1 == *(long long *) s2)
	    return len + 8;
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 9:
	if (*(long long *) s1 == *(long long *) s2)
	    return len + 8 + (s1[8] == s2[8]);
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 10:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (s1[8] != s2[8])
		return len + 8;
	    return len + 9 + (s1[9] == s2[9]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 11:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (*(short *) (s1 + 8) == *(short *) (s2 + 8))
		return len + 10 + (s1[10] == s2[10]);
	    return len + 8 + (s1[8] == s2[8]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 12:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (*(int *) (s1 + 8) == *(int *) (s2 + 8))
		return len + 12;
	    if (*(short *) (s1 + 8) == *(short *) (s2 + 8))
		return len + 10 + (s1[10] == s2[10]);
	    return len + 8 + (s1[8] == s2[8]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 13:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (*(int *) (s1 + 8) == *(int *) (s2 + 8))
		return len + 12 + (s1[12] == s2[12]);
	    if (*(short *) (s1 + 8) == *(short *) (s2 + 8))
		return len + 10 + (s1[10] == s2[10]);
	    return len + 8 + (s1[8] == s2[8]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 14:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (*(int *) (s1 + 8) == *(int *) (s2 + 8)) {
		if (*(short *) (s1 + 12) == *(short *) (s2 + 12))
		    return len + 14;
		return len + 12 + (s1[12] == s2[12]);
	    }
	    if (*(short *) (s1 + 8) == *(short *) (s2 + 8))
		return len + 10 + (s1[10] == s2[10]);
	    return len + 8 + (s1[8] == s2[8]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    case 15:
	if (*(long long *) s1 == *(long long *) s2) {
	    if (*(int *) (s1 + 8) == *(int *) (s2 + 8)) {
		if (*(short *) (s1 + 12) == *(short *) (s2 + 12))
		    return len + 14 + (s1[14] == s2[14]);
		return len + 12 + (s1[12] == s2[12]);
	    }
	    if (*(short *) (s1 + 8) == *(short *) (s2 + 8))
		return len + 10 + (s1[10] == s2[10]);
	    return len + 8 + (s1[8] == s2[8]);
	}
	if (*(int *) s1 == *(int *) s2) {
	    if (*(short *) (s1 + 4) == *(short *) (s2 + 4))
		return len + 6 + (s1[6] == s2[6]);
	    return len + 4 + (s1[4] == s2[4]);
        }
	if (*(short *) s1 == *(short *) s2)
	    return len + 2 + (s1[2] == s2[2]);
	return len + (*s1 == *s2);
    }
#endif
#endif
    // when lengths are different, there's no need to test for EOL
    if (len1 != len2)
	while (*s1 == *s2)
	    s1++, s2++;
    else
	while (*s1 && *s1 == *s2)
	    s1++, s2++;
    return s1 - s0;
}
#endif
