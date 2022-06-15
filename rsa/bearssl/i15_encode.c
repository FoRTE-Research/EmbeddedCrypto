/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"

/* see inner.h */
void
br_i15_encode(void *dst, size_t len, const uint16_t *x)
{
	unsigned char *buf;
	size_t u, xlen;
	uint32_t acc;
	int acc_len;

	xlen = (x[0] + 15) >> 4;
	if (xlen == 0) {
		memset(dst, 0, len);
		return;
	}
	u = 1;
	acc = 0;
	acc_len = 0;
	buf = (unsigned char*)dst;
	while (len -- > 0) {
		if (acc_len < 8) {
			if (u <= xlen) {
				acc += (uint32_t)x[u ++] << acc_len;
			}
			acc_len += 15;
		}
		buf[len] = (unsigned char)acc;
		acc >>= 8;
		acc_len -= 8;
	}
}
