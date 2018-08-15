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

// Lightweight accessor functions for rpm headers which come from pkglist files.
// To get the best performance, I rely on some peculiarities of pkglist headers,
// such as CRPMTAG entries.  Thus the code won't work in the more general case,
// and is less suitable for the end-user applications which are required to
// survive incremental pkglist format changes (such as adding new tags).

#pragma once
#include <stdint.h>
#include <zpkglist.h> // struct HeaderBlob

// Get the credentials.  Returns (size_t) -1 on error.  Returns 0 if there is
// no Epoch; otherwise, returns strlen(E).  For src.rpm records, Arch is set
// to "src".  Name, Version and Release are adjacent in the header memory, so
// that e.g. R - V == strlen(V) + 1.
size_t hdrblobNEVRA(const struct HeaderBlob *blob, size_t blobSize,
	const char **N, char E[16], const char **V, const char **R, const char **A);

// Get the Requires dependencies.  Returns (size_t) -1 on error.  Returns the
// number of Requires, or 0 when there are no Requires.  Names and Versions
// point to the start of adjacent strings in the header memory; lastN and lastV
// point to the null byte that either terminates the last string or is an
// additional null byte due to padding.  Flags are in network byte order.
size_t hdrblobRequires(const struct HeaderBlob *blob, size_t blobSize,
	const char **N, const char **lastN,
	const char **V, const char **lastV,
	const uint32_t *flags);

// Get the Requires dependencies.  Should not be called on src.rpm records.
size_t hdrblobProvides(const struct HeaderBlob *blob, size_t blobSize,
	const char **N, const char **lastN,
	const char **V, const char **lastV,
	const uint32_t *flags);
