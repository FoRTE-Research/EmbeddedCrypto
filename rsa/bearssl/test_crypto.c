/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bearssl.h"
#include "inner.h"

/*
 * Decode an hexadecimal string. Returned value is the number of decoded
 * bytes.
 */
static size_t
hextobin(unsigned char *dst, const char *src)
{
    size_t num;
    unsigned acc;
    int z;

    num = 0;
    z = 0;
    acc = 0;
    while (*src != 0) {
        int c = *src ++;
        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'A' && c <= 'F') {
            c -= ('A' - 10);
        } else if (c >= 'a' && c <= 'f') {
            c -= ('a' - 10);
        } else {
            continue;
        }
        if (z) {
            *dst ++ = (acc << 4) + c;
            num ++;
        } else {
            acc = c;
        }
        z = !z;
    }
    return num;
}

static void
check_equals(const char *banner, const void *v1, const void *v2, size_t len)
{
    size_t u;
    const unsigned char *b;

    if (memcmp(v1, v2, len) == 0) {
        return;
    }
    fprintf(stderr, "\n%s failed\n", banner);
    fprintf(stderr, "v1: ");
    for (u = 0, b = v1; u < len; u ++) {
        fprintf(stderr, "%02X", b[u]);
    }
    fprintf(stderr, "\nv2: ");
    for (u = 0, b = v2; u < len; u ++) {
        fprintf(stderr, "%02X", b[u]);
    }
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

/*
 * A 1024-bit RSA key, generated with OpenSSL.
 */
static const unsigned char RSA_N[] = {
        0xBF, 0xB4, 0xA6, 0x2E, 0x87, 0x3F, 0x9C, 0x8D,
        0xA0, 0xC4, 0x2E, 0x7B, 0x59, 0x36, 0x0F, 0xB0,
        0xFF, 0xE1, 0x25, 0x49, 0xE5, 0xE6, 0x36, 0xB0,
        0x48, 0xC2, 0x08, 0x6B, 0x77, 0xA7, 0xC0, 0x51,
        0x66, 0x35, 0x06, 0xA9, 0x59, 0xDF, 0x17, 0x7F,
        0x15, 0xF6, 0xB4, 0xE5, 0x44, 0xEE, 0x72, 0x3C,
        0x53, 0x11, 0x52, 0xC9, 0xC9, 0x61, 0x4F, 0x92,
        0x33, 0x64, 0x70, 0x43, 0x07, 0xF1, 0x3F, 0x7F,
        0x15, 0xAC, 0xF0, 0xC1, 0x54, 0x7D, 0x55, 0xC0,
        0x29, 0xDC, 0x9E, 0xCC, 0xE4, 0x1D, 0x11, 0x72,
        0x45, 0xF4, 0xD2, 0x70, 0xFC, 0x34, 0xB2, 0x1F,
        0xF3, 0xAD, 0x6A, 0xF0, 0xE5, 0x56, 0x11, 0xF8,
        0x0C, 0x3A, 0x8B, 0x04, 0x46, 0x7C, 0x77, 0xD9,
        0x41, 0x1F, 0x40, 0xBE, 0x93, 0x80, 0x9D, 0x23,
        0x75, 0x80, 0x12, 0x26, 0x5A, 0x72, 0x1C, 0xDD,
        0x47, 0xB3, 0x2A, 0x33, 0xD8, 0x19, 0x61, 0xE3
};
static const unsigned char RSA_E[] = {
        0x01, 0x00, 0x01
};
/* unused
static const unsigned char RSA_D[] = {
	0xAE, 0x56, 0x0B, 0x56, 0x7E, 0xDA, 0x83, 0x75,
	0x6C, 0xC1, 0x5C, 0x00, 0x02, 0x96, 0x1E, 0x58,
	0xF9, 0xA9, 0xF7, 0x2E, 0x27, 0xEB, 0x5E, 0xCA,
	0x9B, 0xB0, 0x10, 0xD6, 0x22, 0x7F, 0xA4, 0x6E,
	0xA2, 0x03, 0x10, 0xE6, 0xCB, 0x7B, 0x0D, 0x34,
	0x1E, 0x76, 0x37, 0xF5, 0xD3, 0xE5, 0x00, 0x70,
	0x09, 0x9E, 0xD4, 0x69, 0xFB, 0x40, 0x0A, 0x8B,
	0xCB, 0x3E, 0xC8, 0xB4, 0xBC, 0xB1, 0x50, 0xEA,
	0x9D, 0xD9, 0x89, 0x8A, 0x98, 0x40, 0x79, 0xD1,
	0x07, 0x66, 0xA7, 0x90, 0x63, 0x82, 0xB1, 0xE0,
	0x24, 0xD0, 0x89, 0x6A, 0xEC, 0xC5, 0xF3, 0x21,
	0x7D, 0xB8, 0xA5, 0x45, 0x3A, 0x3B, 0x34, 0x42,
	0xC2, 0x82, 0x3C, 0x8D, 0xFA, 0x5D, 0xA0, 0xA8,
	0x24, 0xC8, 0x40, 0x22, 0x19, 0xCB, 0xB5, 0x85,
	0x67, 0x69, 0x60, 0xE4, 0xD0, 0x7E, 0xA3, 0x3B,
	0xF7, 0x70, 0x50, 0xC9, 0x5C, 0x97, 0x29, 0x49
};
*/
static const unsigned char RSA_P[] = {
        0xF2, 0xE7, 0x6F, 0x66, 0x2E, 0xC4, 0x03, 0xD4,
        0x89, 0x24, 0xCC, 0xE1, 0xCD, 0x3F, 0x01, 0x82,
        0xC1, 0xFB, 0xAF, 0x44, 0xFA, 0xCC, 0x0E, 0xAA,
        0x9D, 0x74, 0xA9, 0x65, 0xEF, 0xED, 0x4C, 0x87,
        0xF0, 0xB3, 0xC6, 0xEA, 0x61, 0x85, 0xDE, 0x4E,
        0x66, 0xB2, 0x5A, 0x9F, 0x7A, 0x41, 0xC5, 0x66,
        0x57, 0xDF, 0x88, 0xF0, 0xB5, 0xF2, 0xC7, 0x7E,
        0xE6, 0x55, 0x21, 0x96, 0x83, 0xD8, 0xAB, 0x57
};
static const unsigned char RSA_Q[] = {
        0xCA, 0x0A, 0x92, 0xBF, 0x58, 0xB0, 0x2E, 0xF6,
        0x66, 0x50, 0xB1, 0x48, 0x29, 0x42, 0x86, 0x6C,
        0x98, 0x06, 0x7E, 0xB8, 0xB5, 0x4F, 0xFB, 0xC4,
        0xF3, 0xC3, 0x36, 0x91, 0x07, 0xB6, 0xDB, 0xE9,
        0x56, 0x3C, 0x51, 0x7D, 0xB5, 0xEC, 0x0A, 0xA9,
        0x7C, 0x66, 0xF9, 0xD8, 0x25, 0xDE, 0xD2, 0x94,
        0x5A, 0x58, 0xF1, 0x93, 0xE4, 0xF0, 0x5F, 0x27,
        0xBD, 0x83, 0xC7, 0xCA, 0x48, 0x6A, 0xB2, 0x55
};
static const unsigned char RSA_DP[] = {
        0xAF, 0x97, 0xBE, 0x60, 0x0F, 0xCE, 0x83, 0x36,
        0x51, 0x2D, 0xD9, 0x2E, 0x22, 0x41, 0x39, 0xC6,
        0x5C, 0x94, 0xA4, 0xCF, 0x28, 0xBD, 0xFA, 0x9C,
        0x3B, 0xD6, 0xE9, 0xDE, 0x56, 0xE3, 0x24, 0x3F,
        0xE1, 0x31, 0x14, 0xCA, 0xBA, 0x55, 0x1B, 0xAF,
        0x71, 0x6D, 0xDD, 0x35, 0x0C, 0x1C, 0x1F, 0xA7,
        0x2C, 0x3E, 0xDB, 0xAF, 0xA6, 0xD8, 0x2A, 0x7F,
        0x01, 0xE2, 0xE8, 0xB4, 0xF5, 0xFA, 0xDB, 0x61
};
static const unsigned char RSA_DQ[] = {
        0x29, 0xC0, 0x4B, 0x98, 0xFD, 0x13, 0xD3, 0x70,
        0x99, 0xAE, 0x1D, 0x24, 0x83, 0x5A, 0x3A, 0xFB,
        0x1F, 0xE3, 0x5F, 0xB6, 0x7D, 0xC9, 0x5C, 0x86,
        0xD3, 0xB4, 0xC8, 0x86, 0xE9, 0xE8, 0x30, 0xC3,
        0xA4, 0x4D, 0x6C, 0xAD, 0xA4, 0xB5, 0x75, 0x72,
        0x96, 0xC1, 0x94, 0xE9, 0xC4, 0xD1, 0xAA, 0x04,
        0x7C, 0x33, 0x1B, 0x20, 0xEB, 0xD3, 0x7C, 0x66,
        0x72, 0xF4, 0x53, 0x8A, 0x0A, 0xB2, 0xF9, 0xCD
};
static const unsigned char RSA_IQ[] = {
        0xE8, 0xEB, 0x04, 0x79, 0xA5, 0xC1, 0x79, 0xDE,
        0xD5, 0x49, 0xA1, 0x0B, 0x48, 0xB9, 0x0E, 0x55,
        0x74, 0x2C, 0x54, 0xEE, 0xA8, 0xB0, 0x01, 0xC2,
        0xD2, 0x3C, 0x3E, 0x47, 0x3A, 0x7C, 0xC8, 0x3D,
        0x2E, 0x33, 0x54, 0x4D, 0x40, 0x29, 0x41, 0x74,
        0xBA, 0xE1, 0x93, 0x09, 0xEC, 0xE0, 0x1B, 0x4D,
        0x1F, 0x2A, 0xCA, 0x4A, 0x0B, 0x5F, 0xE6, 0xBE,
        0x59, 0x0A, 0xC4, 0xC9, 0xD9, 0x82, 0xAC, 0xE1
};

static const br_rsa_public_key RSA_PK = {
        (void *)RSA_N, sizeof RSA_N,
        (void *)RSA_E, sizeof RSA_E
};

static const br_rsa_private_key RSA_SK = {
        1024,
        (void *)RSA_P, sizeof RSA_P,
        (void *)RSA_Q, sizeof RSA_Q,
        (void *)RSA_DP, sizeof RSA_DP,
        (void *)RSA_DQ, sizeof RSA_DQ,
        (void *)RSA_IQ, sizeof RSA_IQ
};

/*
 * A 2048-bit RSA key, generated with OpenSSL.
 */
static const unsigned char RSA2048_N[] = {
        0xEA, 0xB1, 0xB0, 0x87, 0x60, 0xE2, 0x69, 0xF5,
        0xC9, 0x3F, 0xCB, 0x4F, 0x9E, 0x7D, 0xD0, 0x56,
        0x54, 0x8F, 0xF5, 0x59, 0x97, 0x04, 0x3F, 0x30,
        0xE1, 0xFB, 0x7B, 0xF5, 0xA0, 0xEB, 0xA7, 0x7B,
        0x29, 0x96, 0x7B, 0x32, 0x48, 0x48, 0xA4, 0x99,
        0x90, 0x92, 0x48, 0xFB, 0xDC, 0xEC, 0x8A, 0x3B,
        0xE0, 0x57, 0x6E, 0xED, 0x1C, 0x5B, 0x78, 0xCF,
        0x07, 0x41, 0x96, 0x4C, 0x2F, 0xA2, 0xD1, 0xC8,
        0xA0, 0x5F, 0xFC, 0x2A, 0x5B, 0x3F, 0xBC, 0xD7,
        0xE6, 0x91, 0xF1, 0x44, 0xD6, 0xD8, 0x41, 0x66,
        0x3E, 0x80, 0xEE, 0x98, 0x73, 0xD5, 0x32, 0x60,
        0x7F, 0xDF, 0xBF, 0xB2, 0x0B, 0xA5, 0xCA, 0x11,
        0x88, 0x1A, 0x0E, 0xA1, 0x61, 0x4C, 0x5A, 0x70,
        0xCE, 0x12, 0xC0, 0x61, 0xF5, 0x50, 0x0E, 0xF6,
        0xC1, 0xC2, 0x88, 0x8B, 0xE5, 0xCE, 0xAE, 0x90,
        0x65, 0x23, 0xA7, 0xAD, 0xCB, 0x04, 0x17, 0x00,
        0xA2, 0xDB, 0xB0, 0x21, 0x49, 0xDD, 0x3C, 0x2E,
        0x8C, 0x47, 0x27, 0xF2, 0x84, 0x51, 0x63, 0xEB,
        0xF8, 0xAF, 0x63, 0xA7, 0x89, 0xE1, 0xF0, 0x2F,
        0xF9, 0x9C, 0x0A, 0x8A, 0xBC, 0x57, 0x05, 0xB0,
        0xEF, 0xA0, 0xDA, 0x67, 0x70, 0xAF, 0x3F, 0xA4,
        0x92, 0xFC, 0x4A, 0xAC, 0xEF, 0x89, 0x41, 0x58,
        0x57, 0x63, 0x0F, 0x6A, 0x89, 0x68, 0x45, 0x4C,
        0x20, 0xF9, 0x7F, 0x50, 0x9D, 0x8C, 0x52, 0xC4,
        0xC1, 0x33, 0xCD, 0x42, 0x35, 0x12, 0xEC, 0x82,
        0xF9, 0xC1, 0xB7, 0x60, 0x7B, 0x52, 0x61, 0xD0,
        0xAE, 0xFD, 0x4B, 0x68, 0xB1, 0x55, 0x0E, 0xAB,
        0x99, 0x24, 0x52, 0x60, 0x8E, 0xDB, 0x90, 0x34,
        0x61, 0xE3, 0x95, 0x7C, 0x34, 0x64, 0x06, 0xCB,
        0x44, 0x17, 0x70, 0x78, 0xC1, 0x1B, 0x87, 0x8F,
        0xCF, 0xB0, 0x7D, 0x93, 0x59, 0x84, 0x49, 0xF5,
        0x55, 0xBB, 0x48, 0xCA, 0xD3, 0x76, 0x1E, 0x7F
};
static const unsigned char RSA2048_E[] = {
        0x01, 0x00, 0x01
};
static const unsigned char RSA2048_P[] = {
        0xF9, 0xA7, 0xB5, 0xC4, 0xE8, 0x52, 0xEC, 0xB1,
        0x33, 0x6A, 0x68, 0x32, 0x63, 0x2D, 0xBA, 0xE5,
        0x61, 0x14, 0x69, 0x82, 0xC8, 0x31, 0x14, 0xD5,
        0xC2, 0x6C, 0x1A, 0xBE, 0xA0, 0x68, 0xA6, 0xC5,
        0xEA, 0x40, 0x59, 0xFB, 0x0A, 0x30, 0x3D, 0xD5,
        0xDD, 0x94, 0xAE, 0x0C, 0x9F, 0xEE, 0x19, 0x0C,
        0xA8, 0xF2, 0x85, 0x27, 0x60, 0xAA, 0xD5, 0x7C,
        0x59, 0x91, 0x1F, 0xAF, 0x5E, 0x00, 0xC8, 0x2D,
        0xCA, 0xB4, 0x70, 0xA1, 0xF8, 0x8C, 0x0A, 0xB3,
        0x08, 0x95, 0x03, 0x9E, 0xA4, 0x6B, 0x9D, 0x55,
        0x47, 0xE0, 0xEC, 0xB3, 0x21, 0x7C, 0xE4, 0x16,
        0x91, 0xE3, 0xD7, 0x1B, 0x3D, 0x81, 0xF1, 0xED,
        0x16, 0xF9, 0x05, 0x0E, 0xA6, 0x9F, 0x37, 0x73,
        0x18, 0x1B, 0x9C, 0x9D, 0x33, 0xAD, 0x25, 0xEF,
        0x3A, 0xC0, 0x4B, 0x34, 0x24, 0xF5, 0xFD, 0x59,
        0xF5, 0x65, 0xE6, 0x92, 0x2A, 0x04, 0x06, 0x3D
};
static const unsigned char RSA2048_Q[] = {
        0xF0, 0xA8, 0xA4, 0x20, 0xDD, 0xF3, 0x99, 0xE6,
        0x1C, 0xB1, 0x21, 0xE8, 0x66, 0x68, 0x48, 0x00,
        0x04, 0xE3, 0x21, 0xA3, 0xE8, 0xC5, 0xFD, 0x85,
        0x6D, 0x2C, 0x98, 0xE3, 0x36, 0x39, 0x3E, 0x80,
        0xB7, 0x36, 0xA5, 0xA9, 0xBB, 0xEB, 0x1E, 0xB8,
        0xEB, 0x44, 0x65, 0xE8, 0x81, 0x7D, 0xE0, 0x87,
        0xC1, 0x08, 0x94, 0xDD, 0x92, 0x40, 0xF4, 0x8B,
        0x3C, 0xB5, 0xC1, 0xAD, 0x9D, 0x4C, 0x14, 0xCD,
        0xD9, 0x2D, 0xB6, 0xE4, 0x99, 0xB3, 0x71, 0x63,
        0x64, 0xE1, 0x31, 0x7E, 0x34, 0x95, 0x96, 0x52,
        0x85, 0x27, 0xBE, 0x40, 0x10, 0x0A, 0x9E, 0x01,
        0x1C, 0xBB, 0xB2, 0x5B, 0x40, 0x85, 0x65, 0x6E,
        0xA0, 0x88, 0x73, 0xF6, 0x22, 0xCC, 0x23, 0x26,
        0x62, 0xAD, 0x92, 0x57, 0x57, 0xF4, 0xD4, 0xDF,
        0xD9, 0x7C, 0xDE, 0xAD, 0xD2, 0x1F, 0x32, 0x29,
        0xBA, 0xE7, 0xE2, 0x32, 0xA1, 0xA0, 0xBF, 0x6B
};
static const unsigned char RSA2048_DP[] = {
        0xB2, 0xF9, 0xD7, 0x66, 0xC5, 0x83, 0x05, 0x6A,
        0x77, 0xC8, 0xB5, 0xD0, 0x41, 0xA7, 0xBC, 0x0F,
        0xCB, 0x4B, 0xFD, 0xE4, 0x23, 0x2E, 0x84, 0x98,
        0x46, 0x1C, 0x88, 0x03, 0xD7, 0x2D, 0x8F, 0x39,
        0xDD, 0x98, 0xAA, 0xA9, 0x3D, 0x01, 0x9E, 0xA2,
        0xDE, 0x8A, 0x43, 0x48, 0x8B, 0xB2, 0xFE, 0xC4,
        0x43, 0xAE, 0x31, 0x65, 0x2C, 0x78, 0xEC, 0x39,
        0x8C, 0x60, 0x6C, 0xCD, 0xA4, 0xDF, 0x7C, 0xA2,
        0xCF, 0x6A, 0x12, 0x41, 0x1B, 0xD5, 0x11, 0xAA,
        0x8D, 0xE1, 0x7E, 0x49, 0xD1, 0xE7, 0xD0, 0x50,
        0x1E, 0x0A, 0x92, 0xC6, 0x4C, 0xA0, 0xA3, 0x47,
        0xC6, 0xE9, 0x07, 0x01, 0xE1, 0x53, 0x72, 0x23,
        0x9D, 0x4F, 0x82, 0x9F, 0xA1, 0x36, 0x0D, 0x63,
        0x76, 0x89, 0xFC, 0xF9, 0xF9, 0xDD, 0x0C, 0x8F,
        0xF7, 0x97, 0x79, 0x92, 0x75, 0x58, 0xE0, 0x7B,
        0x08, 0x61, 0x38, 0x2D, 0xDA, 0xEF, 0x2D, 0xA5
};
static const unsigned char RSA2048_DQ[] = {
        0x8B, 0x69, 0x56, 0x33, 0x08, 0x00, 0x8F, 0x3D,
        0xC3, 0x8F, 0x45, 0x52, 0x48, 0xC8, 0xCE, 0x34,
        0xDC, 0x9F, 0xEB, 0x23, 0xF5, 0xBB, 0x84, 0x62,
        0xDF, 0xDC, 0xBE, 0xF0, 0x98, 0xBF, 0xCE, 0x9A,
        0x68, 0x08, 0x4B, 0x2D, 0xA9, 0x83, 0xC9, 0xF7,
        0x5B, 0xAA, 0xF2, 0xD2, 0x1E, 0xF9, 0x99, 0xB1,
        0x6A, 0xBC, 0x9A, 0xE8, 0x44, 0x4A, 0x46, 0x9F,
        0xC6, 0x5A, 0x90, 0x49, 0x0F, 0xDF, 0x3C, 0x0A,
        0x07, 0x6E, 0xB9, 0x0D, 0x72, 0x90, 0x85, 0xF6,
        0x0B, 0x41, 0x7D, 0x17, 0x5C, 0x44, 0xEF, 0xA0,
        0xFC, 0x2C, 0x0A, 0xC5, 0x37, 0xC5, 0xBE, 0xC4,
        0x6C, 0x2D, 0xBB, 0x63, 0xAB, 0x5B, 0xDB, 0x67,
        0x9B, 0xAD, 0x90, 0x67, 0x9C, 0xBE, 0xDE, 0xF9,
        0xE4, 0x9E, 0x22, 0x31, 0x60, 0xED, 0x9E, 0xC7,
        0xD2, 0x48, 0xC9, 0x02, 0xAE, 0xBF, 0x8D, 0xA2,
        0xA8, 0xF8, 0x9D, 0x8B, 0xB1, 0x1F, 0xDA, 0xE3
};
static const unsigned char RSA2048_IQ[] = {
        0xB5, 0x48, 0xD4, 0x48, 0x5A, 0x33, 0xCD, 0x13,
        0xFE, 0xC6, 0xF7, 0x01, 0x0A, 0x3E, 0x40, 0xA3,
        0x45, 0x94, 0x6F, 0x85, 0xE4, 0x68, 0x66, 0xEC,
        0x69, 0x6A, 0x3E, 0xE0, 0x62, 0x3F, 0x0C, 0xEF,
        0x21, 0xCC, 0xDA, 0xAD, 0x75, 0x98, 0x12, 0xCA,
        0x9E, 0x31, 0xDD, 0x95, 0x0D, 0xBD, 0x55, 0xEB,
        0x92, 0xF7, 0x9E, 0xBD, 0xFC, 0x28, 0x35, 0x96,
        0x31, 0xDC, 0x53, 0x80, 0xA3, 0x57, 0x89, 0x3C,
        0x4A, 0xEC, 0x40, 0x75, 0x13, 0xAC, 0x4F, 0x36,
        0x3A, 0x86, 0x9A, 0xA6, 0x58, 0xC9, 0xED, 0xCB,
        0xD6, 0xBB, 0xB2, 0xD9, 0xAA, 0x04, 0xC4, 0xE8,
        0x47, 0x3E, 0xBD, 0x14, 0x9B, 0x8F, 0x61, 0x70,
        0x69, 0x66, 0x23, 0x62, 0x18, 0xE3, 0x52, 0x98,
        0xE3, 0x22, 0xE9, 0x6F, 0xDA, 0x28, 0x68, 0x08,
        0xB8, 0xB9, 0x8B, 0x97, 0x8B, 0x77, 0x3F, 0xCA,
        0x9D, 0x9D, 0xBE, 0xD5, 0x2D, 0x3E, 0xC2, 0x11
};

static const br_rsa_public_key RSA2048_PK = {
        (void *)RSA2048_N, sizeof RSA2048_N,
        (void *)RSA2048_E, sizeof RSA2048_E
};

static const br_rsa_private_key RSA2048_SK = {
        2048,
        (void *)RSA2048_P, sizeof RSA2048_P,
        (void *)RSA2048_Q, sizeof RSA2048_Q,
        (void *)RSA2048_DP, sizeof RSA2048_DP,
        (void *)RSA2048_DQ, sizeof RSA2048_DQ,
        (void *)RSA2048_IQ, sizeof RSA2048_IQ
};

/*
 * A 4096-bit RSA key, generated with OpenSSL.
 */
static const unsigned char RSA4096_N[] = {
        0xAA, 0x17, 0x71, 0xBC, 0x92, 0x3E, 0xB5, 0xBD,
        0x3E, 0x64, 0xCF, 0x03, 0x9B, 0x24, 0x65, 0x33,
        0x5F, 0xB4, 0x47, 0x89, 0xE5, 0x63, 0xE4, 0xA0,
        0x5A, 0x51, 0x95, 0x07, 0x73, 0xEE, 0x00, 0xF6,
        0x3E, 0x31, 0x0E, 0xDA, 0x15, 0xC3, 0xAA, 0x21,
        0x6A, 0xCD, 0xFF, 0x46, 0x6B, 0xDF, 0x0A, 0x7F,
        0x8A, 0xC2, 0x25, 0x19, 0x47, 0x44, 0xD8, 0x52,
        0xC1, 0x56, 0x25, 0x6A, 0xE0, 0xD2, 0x61, 0x11,
        0x2C, 0xF7, 0x73, 0x9F, 0x5F, 0x74, 0xAA, 0xDD,
        0xDE, 0xAF, 0x81, 0xF6, 0x0C, 0x1A, 0x3A, 0xF9,
        0xC5, 0x47, 0x82, 0x75, 0x1D, 0x41, 0xF0, 0xB2,
        0xFD, 0xBA, 0xE2, 0xA4, 0xA1, 0xB8, 0x32, 0x48,
        0x06, 0x0D, 0x29, 0x2F, 0x44, 0x14, 0xF5, 0xAC,
        0x54, 0x83, 0xC4, 0xB6, 0x85, 0x85, 0x9B, 0x1C,
        0x05, 0x61, 0x28, 0x62, 0x24, 0xA8, 0xF0, 0xE6,
        0x80, 0xA7, 0x91, 0xE8, 0xC7, 0x8E, 0x52, 0x17,
        0xBE, 0xAF, 0xC6, 0x0A, 0xA3, 0xFB, 0xD1, 0x04,
        0x15, 0x3B, 0x14, 0x35, 0xA5, 0x41, 0xF5, 0x30,
        0xFE, 0xEF, 0x53, 0xA7, 0x89, 0x91, 0x78, 0x30,
        0xBE, 0x3A, 0xB1, 0x4B, 0x2E, 0x4A, 0x0E, 0x25,
        0x1D, 0xCF, 0x51, 0x54, 0x52, 0xF1, 0x88, 0x85,
        0x36, 0x23, 0xDE, 0xBA, 0x66, 0x25, 0x60, 0x8D,
        0x45, 0xD7, 0xD8, 0x10, 0x41, 0x64, 0xC7, 0x4B,
        0xCE, 0x72, 0x13, 0xD7, 0x20, 0xF8, 0x2A, 0x74,
        0xA5, 0x05, 0xF4, 0x5A, 0x90, 0xF4, 0x9C, 0xE7,
        0xC9, 0xCF, 0x1E, 0xD5, 0x9C, 0xAC, 0xE5, 0x00,
        0x83, 0x73, 0x9F, 0xE7, 0xC6, 0x93, 0xC0, 0x06,
        0xA7, 0xB8, 0xF8, 0x46, 0x90, 0xC8, 0x78, 0x27,
        0x2E, 0xCC, 0xC0, 0x2A, 0x20, 0xC5, 0xFC, 0x63,
        0x22, 0xA1, 0xD6, 0x16, 0xAD, 0x9C, 0xD6, 0xFC,
        0x7A, 0x6E, 0x9C, 0x98, 0x51, 0xEE, 0x6B, 0x6D,
        0x8F, 0xEF, 0xCE, 0x7C, 0x5D, 0x16, 0xB0, 0xCE,
        0x9C, 0xEE, 0x92, 0xCF, 0xB7, 0xEB, 0x41, 0x36,
        0x3A, 0x6C, 0xF2, 0x0D, 0x26, 0x11, 0x2F, 0x6C,
        0x27, 0x62, 0xA2, 0xCC, 0x63, 0x53, 0xBD, 0xFC,
        0x9F, 0xBE, 0x9B, 0xBD, 0xE5, 0xA7, 0xDA, 0xD4,
        0xF8, 0xED, 0x5E, 0x59, 0x2D, 0xAC, 0xCD, 0x13,
        0xEB, 0xE5, 0x9E, 0x39, 0x82, 0x8B, 0xFD, 0xA8,
        0xFB, 0xCB, 0x86, 0x27, 0xC7, 0x4B, 0x4C, 0xD0,
        0xBA, 0x12, 0xD0, 0x76, 0x1A, 0xDB, 0x30, 0xC5,
        0xB3, 0x2C, 0x4C, 0xC5, 0x32, 0x03, 0x05, 0x67,
        0x8D, 0xD0, 0x14, 0x37, 0x59, 0x2B, 0xE3, 0x1C,
        0x25, 0x3E, 0xA5, 0xE4, 0xF1, 0x0D, 0x34, 0xBB,
        0xD5, 0xF6, 0x76, 0x45, 0x5B, 0x0F, 0x1E, 0x07,
        0x0A, 0xBA, 0x9D, 0x71, 0x87, 0xDE, 0x45, 0x50,
        0xE5, 0x0F, 0x32, 0xBB, 0x5C, 0x32, 0x2D, 0x40,
        0xCD, 0x19, 0x95, 0x4E, 0xC5, 0x54, 0x3A, 0x9A,
        0x46, 0x9B, 0x85, 0xFE, 0x53, 0xB7, 0xD8, 0x65,
        0x6D, 0x68, 0x0C, 0xBB, 0xE3, 0x3D, 0x8E, 0x64,
        0xBE, 0x27, 0x15, 0xAB, 0x12, 0x20, 0xD9, 0x84,
        0xF5, 0x02, 0xE4, 0xBB, 0xDD, 0xAB, 0x59, 0x51,
        0xF4, 0xE1, 0x79, 0xBE, 0xB8, 0xA3, 0x8E, 0xD1,
        0x1C, 0xB0, 0xFA, 0x48, 0x76, 0xC2, 0x9D, 0x7A,
        0x01, 0xA5, 0xAF, 0x8C, 0xBA, 0xAA, 0x4C, 0x06,
        0x2B, 0x0A, 0x62, 0xF0, 0x79, 0x5B, 0x42, 0xFC,
        0xF8, 0xBF, 0xD4, 0xDD, 0x62, 0x32, 0xE3, 0xCE,
        0xF1, 0x2C, 0xE6, 0xED, 0xA8, 0x8A, 0x41, 0xA3,
        0xC1, 0x1E, 0x07, 0xB6, 0x43, 0x10, 0x80, 0xB7,
        0xF3, 0xD0, 0x53, 0x2A, 0x9A, 0x98, 0xA7, 0x4F,
        0x9E, 0xA3, 0x3E, 0x1B, 0xDA, 0x93, 0x15, 0xF2,
        0xF4, 0x20, 0xA5, 0xA8, 0x4F, 0x8A, 0xBA, 0xED,
        0xB1, 0x17, 0x6C, 0x0F, 0xD9, 0x8F, 0x38, 0x11,
        0xF3, 0xD9, 0x5E, 0x88, 0xA1, 0xA1, 0x82, 0x8B,
        0x30, 0xD7, 0xC6, 0xCE, 0x4E, 0x30, 0x55, 0x57
};
static const unsigned char RSA4096_E[] = {
        0x01, 0x00, 0x01
};
static const unsigned char RSA4096_P[] = {
        0xD3, 0x7A, 0x22, 0xD8, 0x9B, 0xBF, 0x42, 0xB4,
        0x53, 0x04, 0x10, 0x6A, 0x84, 0xFD, 0x7C, 0x1D,
        0xF6, 0xF4, 0x10, 0x65, 0xAA, 0xE5, 0xE1, 0x4E,
        0xB4, 0x37, 0xF7, 0xAC, 0xF7, 0xD3, 0xB2, 0x3B,
        0xFE, 0xE7, 0x63, 0x42, 0xE9, 0xF0, 0x3C, 0xE0,
        0x42, 0xB4, 0xBB, 0x09, 0xD0, 0xB2, 0x7C, 0x70,
        0xA4, 0x11, 0x97, 0x90, 0x01, 0xD0, 0x0E, 0x7B,
        0xAF, 0x7D, 0x30, 0x4E, 0x6B, 0x3A, 0xCC, 0x50,
        0x4E, 0xAF, 0x2F, 0xC3, 0xC2, 0x4F, 0x7E, 0xC5,
        0xB3, 0x76, 0x33, 0xFB, 0xA7, 0xB1, 0x96, 0xA5,
        0x46, 0x41, 0xC6, 0xDA, 0x5A, 0xFD, 0x17, 0x0A,
        0x6A, 0x86, 0x54, 0x83, 0xE1, 0x57, 0xE7, 0xAF,
        0x8C, 0x42, 0xE5, 0x39, 0xF2, 0xC7, 0xFC, 0x4A,
        0x3D, 0x3C, 0x94, 0x89, 0xC2, 0xC6, 0x2D, 0x0A,
        0x5F, 0xD0, 0x21, 0x23, 0x5C, 0xC9, 0xC8, 0x44,
        0x8A, 0x96, 0x72, 0x4D, 0x96, 0xC6, 0x17, 0x0C,
        0x36, 0x43, 0x7F, 0xD8, 0xA0, 0x7A, 0x31, 0x7E,
        0xCE, 0x13, 0xE3, 0x13, 0x2E, 0xE0, 0x91, 0xC2,
        0x61, 0x13, 0x16, 0x8D, 0x99, 0xCB, 0xA9, 0x2C,
        0x4D, 0x9D, 0xDD, 0x1D, 0x03, 0xE7, 0xA7, 0x50,
        0xF4, 0x16, 0x43, 0xB1, 0x7F, 0x99, 0x61, 0x3F,
        0xA5, 0x59, 0x91, 0x16, 0xC3, 0x06, 0x63, 0x59,
        0xE9, 0xDA, 0xB5, 0x06, 0x2E, 0x0C, 0xD9, 0xAB,
        0x93, 0x89, 0x12, 0x82, 0xFB, 0x90, 0xD9, 0x30,
        0x60, 0xF7, 0x35, 0x2D, 0x18, 0x78, 0xEB, 0x2B,
        0xA1, 0x06, 0x67, 0x37, 0xDE, 0x72, 0x20, 0xD2,
        0x80, 0xE5, 0x2C, 0xD7, 0x5E, 0xC7, 0x67, 0x2D,
        0x40, 0xE7, 0x7A, 0xCF, 0x4A, 0x69, 0x9D, 0xA7,
        0x90, 0x9F, 0x3B, 0xDF, 0x07, 0x97, 0x64, 0x69,
        0x06, 0x4F, 0xBA, 0xF4, 0xE5, 0xBD, 0x71, 0x60,
        0x36, 0xB7, 0xA3, 0xDE, 0x76, 0xC5, 0x38, 0xD7,
        0x1D, 0x9A, 0xFC, 0x36, 0x3D, 0x3B, 0xDC, 0xCF
};
static const unsigned char RSA4096_Q[] = {
        0xCD, 0xE6, 0xC6, 0xA6, 0x42, 0x4C, 0x45, 0x65,
        0x8B, 0x85, 0x76, 0xFC, 0x21, 0xB6, 0x57, 0x79,
        0x3C, 0xE4, 0xE3, 0x85, 0x55, 0x2F, 0x59, 0xD3,
        0x3F, 0x74, 0xAF, 0x9F, 0x11, 0x04, 0x10, 0x8B,
        0xF9, 0x5F, 0x4D, 0x25, 0xEE, 0x20, 0xF9, 0x69,
        0x3B, 0x02, 0xB6, 0x43, 0x0D, 0x0C, 0xED, 0x30,
        0x31, 0x57, 0xE7, 0x9A, 0x57, 0x24, 0x6B, 0x4A,
        0x5E, 0xA2, 0xBF, 0xD4, 0x47, 0x7D, 0xFA, 0x78,
        0x51, 0x86, 0x80, 0x68, 0x85, 0x7C, 0x7B, 0x08,
        0x4A, 0x35, 0x24, 0x4F, 0x8B, 0x24, 0x49, 0xF8,
        0x16, 0x06, 0x9C, 0x57, 0x4E, 0x94, 0x4C, 0xBD,
        0x6E, 0x53, 0x52, 0xC9, 0xC1, 0x64, 0x43, 0x22,
        0x1E, 0xDD, 0xEB, 0xAC, 0x90, 0x58, 0xCA, 0xBA,
        0x9C, 0xAC, 0xCF, 0xDD, 0x08, 0x6D, 0xB7, 0x31,
        0xDB, 0x0D, 0x83, 0xE6, 0x50, 0xA6, 0x69, 0xB1,
        0x1C, 0x68, 0x92, 0xB4, 0xB5, 0x76, 0xDE, 0xBD,
        0x4F, 0xA5, 0x30, 0xED, 0x23, 0xFF, 0xE5, 0x80,
        0x21, 0xAB, 0xED, 0xE6, 0xDC, 0x32, 0x3D, 0xF7,
        0x45, 0xB8, 0x19, 0x3D, 0x8E, 0x15, 0x7C, 0xE5,
        0x0D, 0xC8, 0x9B, 0x7D, 0x1F, 0x7C, 0x14, 0x14,
        0x41, 0x09, 0xA7, 0xEB, 0xFB, 0xD9, 0x5F, 0x9A,
        0x94, 0xB6, 0xD5, 0xA0, 0x2C, 0xAF, 0xB5, 0xEF,
        0x5C, 0x5A, 0x8E, 0x34, 0xA1, 0x8F, 0xEB, 0x38,
        0x0F, 0x31, 0x6E, 0x45, 0x21, 0x7A, 0xAA, 0xAF,
        0x6C, 0xB1, 0x8E, 0xB2, 0xB9, 0xD4, 0x1E, 0xEF,
        0x66, 0xD8, 0x4E, 0x3D, 0xF2, 0x0C, 0xF1, 0xBA,
        0xFB, 0xA9, 0x27, 0xD2, 0x45, 0x54, 0x83, 0x4B,
        0x10, 0xC4, 0x9A, 0x32, 0x9C, 0xC7, 0x9A, 0xCF,
        0x4E, 0xBF, 0x07, 0xFC, 0x27, 0xB7, 0x96, 0x1D,
        0xDE, 0x9D, 0xE4, 0x84, 0x68, 0x00, 0x9A, 0x9F,
        0x3D, 0xE6, 0xC7, 0x26, 0x11, 0x48, 0x79, 0xFA,
        0x09, 0x76, 0xC8, 0x25, 0x3A, 0xE4, 0x70, 0xF9
};
static const unsigned char RSA4096_DP[] = {
        0x5C, 0xE3, 0x3E, 0xBF, 0x09, 0xD9, 0xFE, 0x80,
        0x9A, 0x1E, 0x24, 0xDF, 0xC4, 0xBE, 0x5A, 0x70,
        0x06, 0xF2, 0xB8, 0xE9, 0x0F, 0x21, 0x9D, 0xCF,
        0x26, 0x15, 0x97, 0x32, 0x60, 0x40, 0x99, 0xFF,
        0x04, 0x3D, 0xBA, 0x39, 0xBF, 0xEB, 0x87, 0xB1,
        0xB1, 0x5B, 0x14, 0xF4, 0x80, 0xB8, 0x85, 0x34,
        0x2C, 0xBC, 0x95, 0x67, 0xE9, 0x83, 0xEB, 0x78,
        0xA4, 0x62, 0x46, 0x7F, 0x8B, 0x55, 0xEE, 0x3C,
        0x2F, 0xF3, 0x7E, 0xF5, 0x6B, 0x39, 0xE3, 0xA3,
        0x0E, 0xEA, 0x92, 0x76, 0xAC, 0xF7, 0xB2, 0x05,
        0xB2, 0x50, 0x5D, 0xF9, 0xB7, 0x11, 0x87, 0xB7,
        0x49, 0x86, 0xEB, 0x44, 0x6A, 0x0C, 0x64, 0x75,
        0x95, 0x14, 0x24, 0xFF, 0x49, 0x06, 0x52, 0x68,
        0x81, 0x71, 0x44, 0x85, 0x26, 0x0A, 0x49, 0xEA,
        0x4E, 0x9F, 0x6A, 0x8E, 0xCF, 0xC8, 0xC9, 0xB0,
        0x61, 0x77, 0x27, 0x89, 0xB0, 0xFA, 0x1D, 0x51,
        0x7D, 0xDC, 0x34, 0x21, 0x80, 0x8B, 0x6B, 0x86,
        0x19, 0x1A, 0x5F, 0x19, 0x23, 0xF3, 0xFB, 0xD1,
        0xF7, 0x35, 0x9D, 0x28, 0x61, 0x2F, 0x35, 0x85,
        0x82, 0x2A, 0x1E, 0xDF, 0x09, 0xC2, 0x0C, 0x99,
        0xE0, 0x3C, 0x8F, 0x4B, 0x3D, 0x92, 0xAF, 0x46,
        0x77, 0x68, 0x59, 0xF4, 0x37, 0x81, 0x6C, 0xCE,
        0x27, 0x8B, 0xAB, 0x0B, 0xA5, 0xDA, 0x7B, 0x19,
        0x83, 0xDA, 0x27, 0x49, 0x65, 0x1A, 0x00, 0x6B,
        0xE1, 0x8B, 0x73, 0xCD, 0xF4, 0xFB, 0xD7, 0xBF,
        0xF8, 0x20, 0x89, 0xE1, 0xDE, 0x51, 0x1E, 0xDD,
        0x97, 0x44, 0x12, 0x68, 0x1E, 0xF7, 0x52, 0xF8,
        0x6B, 0x93, 0xC1, 0x3B, 0x9F, 0xA1, 0xB8, 0x5F,
        0xCB, 0x84, 0x45, 0x95, 0xF7, 0x0D, 0xA6, 0x4B,
        0x03, 0x3C, 0xAE, 0x0F, 0xB7, 0x81, 0x78, 0x75,
        0x1C, 0x53, 0x99, 0x24, 0xB3, 0xE2, 0x78, 0xCE,
        0xF3, 0xF0, 0x09, 0x6C, 0x01, 0x85, 0x73, 0xBD
};
static const unsigned char RSA4096_DQ[] = {
        0xCD, 0x88, 0xAC, 0x8B, 0x92, 0x6A, 0xA8, 0x6B,
        0x71, 0x16, 0xCD, 0x6B, 0x6A, 0x0B, 0xA6, 0xCD,
        0xF3, 0x27, 0x58, 0xA6, 0xE4, 0x1D, 0xDC, 0x40,
        0xAF, 0x7B, 0x3F, 0x44, 0x3D, 0xAC, 0x1D, 0x08,
        0x5C, 0xE9, 0xF1, 0x0D, 0x07, 0xE4, 0x0A, 0x94,
        0x2C, 0xBF, 0xCC, 0x48, 0xAA, 0x62, 0x58, 0xF2,
        0x5E, 0x8F, 0x2D, 0x36, 0x37, 0xFE, 0xB6, 0xCB,
        0x0A, 0x24, 0xD3, 0xF0, 0x87, 0x5D, 0x0E, 0x05,
        0xC4, 0xFB, 0xCA, 0x7A, 0x8B, 0xA5, 0x72, 0xFB,
        0x17, 0x78, 0x6C, 0xC2, 0xAA, 0x56, 0x93, 0x2F,
        0xFE, 0x6C, 0xA2, 0xEB, 0xD4, 0x18, 0xDD, 0x71,
        0xCB, 0x0B, 0x89, 0xFC, 0xB3, 0xFB, 0xED, 0xB7,
        0xC5, 0xB0, 0x29, 0x6D, 0x9C, 0xB9, 0xC5, 0xC4,
        0xFA, 0x58, 0xD7, 0x36, 0x01, 0x0F, 0xE4, 0x6A,
        0xF4, 0x0B, 0x4D, 0xBB, 0x3E, 0x8E, 0x9F, 0xBA,
        0x98, 0x6D, 0x1A, 0xE5, 0x20, 0xAF, 0x84, 0x30,
        0xDD, 0xAC, 0x3C, 0x66, 0xBC, 0x24, 0xD9, 0x67,
        0x4A, 0x35, 0x61, 0xC9, 0xAD, 0xCC, 0xC9, 0x66,
        0x68, 0x46, 0x19, 0x8C, 0x04, 0xA5, 0x16, 0x83,
        0x5F, 0x7A, 0xFD, 0x1B, 0xAD, 0xAE, 0x22, 0x2D,
        0x05, 0xAF, 0x29, 0xDC, 0xBB, 0x0E, 0x86, 0x0C,
        0xBC, 0x9E, 0xB6, 0x28, 0xA9, 0xF2, 0xCC, 0x5E,
        0x1F, 0x86, 0x95, 0xA5, 0x9C, 0x11, 0x19, 0xF0,
        0x5F, 0xDA, 0x2C, 0x04, 0xFE, 0x22, 0x80, 0xF7,
        0x94, 0x3C, 0xBA, 0x01, 0x56, 0xD6, 0x93, 0xFA,
        0xCE, 0x62, 0xE5, 0xD7, 0x98, 0x23, 0xAB, 0xB9,
        0xC7, 0x35, 0x57, 0xF6, 0xE2, 0x16, 0x36, 0xE9,
        0x5B, 0xD7, 0xA5, 0x45, 0x18, 0x93, 0x77, 0xC9,
        0xB1, 0x05, 0xA8, 0x66, 0xE1, 0x0E, 0xB5, 0xDF,
        0x23, 0x35, 0xE1, 0xC2, 0xFA, 0x3E, 0x80, 0x1A,
        0xAD, 0xA4, 0x0C, 0xEF, 0xC7, 0x18, 0xDE, 0x09,
        0xE6, 0x20, 0x98, 0x31, 0xF1, 0xD3, 0xCF, 0xA1
};
static const unsigned char RSA4096_IQ[] = {
        0x76, 0xD7, 0x75, 0xDF, 0xA3, 0x0C, 0x9D, 0x64,
        0x6E, 0x00, 0x82, 0x2E, 0x5C, 0x5E, 0x43, 0xC4,
        0xD2, 0x28, 0xB0, 0xB1, 0xA8, 0xD8, 0x26, 0x91,
        0xA0, 0xF5, 0xC8, 0x69, 0xFF, 0x24, 0x33, 0xAB,
        0x67, 0xC7, 0xA3, 0xAE, 0xBB, 0x17, 0x27, 0x5B,
        0x5A, 0xCD, 0x67, 0xA3, 0x70, 0x91, 0x9E, 0xD5,
        0xF1, 0x97, 0x00, 0x0A, 0x30, 0x64, 0x3D, 0x9B,
        0xBF, 0xB5, 0x8C, 0xAC, 0xC7, 0x20, 0x0A, 0xD2,
        0x76, 0x36, 0x36, 0x5D, 0xE4, 0xAC, 0x5D, 0xBC,
        0x44, 0x32, 0xB0, 0x76, 0x33, 0x40, 0xDD, 0x29,
        0x22, 0xE0, 0xFF, 0x55, 0x4C, 0xCE, 0x3F, 0x43,
        0x34, 0x95, 0x94, 0x7C, 0x22, 0x0D, 0xAB, 0x20,
        0x38, 0x70, 0xC3, 0x4A, 0x19, 0xCF, 0x81, 0xCE,
        0x79, 0x28, 0x6C, 0xC2, 0xA3, 0xB3, 0x48, 0x20,
        0x2D, 0x3E, 0x74, 0x45, 0x2C, 0xAA, 0x9F, 0xA5,
        0xC2, 0xE3, 0x2D, 0x41, 0x95, 0xBD, 0x78, 0xAB,
        0x6A, 0xA8, 0x7A, 0x45, 0x52, 0xE2, 0x66, 0xE7,
        0x6C, 0x38, 0x03, 0xA5, 0xDA, 0xAD, 0x94, 0x3C,
        0x6A, 0xA1, 0xA2, 0xD5, 0xCD, 0xDE, 0x05, 0xCC,
        0x6E, 0x3D, 0x8A, 0xF6, 0x9A, 0xA5, 0x0F, 0xA9,
        0x18, 0xC4, 0xF9, 0x9C, 0x2F, 0xB3, 0xF1, 0x30,
        0x38, 0x60, 0x69, 0x09, 0x67, 0x2C, 0xE9, 0x42,
        0x68, 0x3C, 0x70, 0x32, 0x1A, 0x44, 0x32, 0x02,
        0x82, 0x9F, 0x60, 0xE8, 0xA4, 0x42, 0x74, 0xA2,
        0xA2, 0x5A, 0x99, 0xDC, 0xC8, 0xCA, 0x15, 0x4D,
        0xFF, 0xF1, 0x8A, 0x23, 0xD8, 0xD3, 0xB1, 0x9A,
        0xB4, 0x0B, 0xBB, 0xE8, 0x38, 0x74, 0x0C, 0x52,
        0xC7, 0x8B, 0x63, 0x4C, 0xEA, 0x7D, 0x5F, 0x58,
        0x34, 0x53, 0x3E, 0x23, 0x10, 0xBB, 0x60, 0x6B,
        0x52, 0x9D, 0x89, 0x9F, 0xF0, 0x5F, 0xCE, 0xB3,
        0x9C, 0x0E, 0x75, 0x0F, 0x87, 0xF6, 0x66, 0xA5,
        0x4C, 0x94, 0x84, 0xFE, 0x94, 0xB9, 0x04, 0xB7
};

static const br_rsa_public_key RSA4096_PK = {
        (void *)RSA4096_N, sizeof RSA4096_N,
        (void *)RSA4096_E, sizeof RSA4096_E
};

static const br_rsa_private_key RSA4096_SK = {
        4096,
        (void *)RSA4096_P, sizeof RSA4096_P,
        (void *)RSA4096_Q, sizeof RSA4096_Q,
        (void *)RSA4096_DP, sizeof RSA4096_DP,
        (void *)RSA4096_DQ, sizeof RSA4096_DQ,
        (void *)RSA4096_IQ, sizeof RSA4096_IQ
};

static void
test_RSA_core(const char *name, br_rsa_public fpub, br_rsa_private fpriv)
{
    unsigned char t1[512], t2[512], t3[512];
    size_t len;

    printf("Test %s: ", name);
    fflush(stdout);

    /*
	 * A KAT test (computed with OpenSSL).
	 */
    len = hextobin(t1, "45A3DC6A106BCD3BD0E48FB579643AA3FF801E5903E80AA9B43A695A8E7F454E93FA208B69995FF7A6D5617C2FEB8E546375A664977A48931842AAE796B5A0D64393DCA35F3490FC157F5BD83B9D58C2F7926E6AE648A2BD96CAB8FCCD3D35BB11424AD47D973FF6D69CA774841AEC45DFAE99CCF79893E7047FDE6CB00AA76D");
    hextobin(t2, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003021300906052B0E03021A05000414A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
    memcpy(t3, t1, len);
    if (!fpub(t3, len, &RSA_PK)) {
        fprintf(stderr, "RSA public operation failed (1)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA pub", t2, t3, len);
    if (!fpriv(t3, &RSA_SK)) {
        fprintf(stderr, "RSA private operation failed (1)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA priv (1)", t1, t3, len);

    /*
	 * Another KAT test, with a (fake) hash value slightly different
	 * (last byte is 0xD9 instead of 0xD3).
	 */
    len = hextobin(t1, "32C2DB8B2C73BBCA9960CB3F11FEDEE7B699359EF2EEC3A632E56B7FF3DE2F371E5179BAB03F17E0BB20D2891ACAB679F95DA9B43A01DAAD192FADD25D8ACCF1498EC80F5BBCAC88EA59D60E3BC9D3CE27743981DE42385FFFFF04DD2D716E1A46C04A28ECAF6CD200DAB81083A830D61538D69BB39A183107BD50302AA6BC28");
    hextobin(t2, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003021300906052B0E03021A05000414A94A8FE5CCB19BA61C4C0873D391E987982FBBD9");
    memcpy(t3, t1, len);
    if (!fpub(t3, len, &RSA_PK)) {
        fprintf(stderr, "RSA public operation failed (2)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA pub", t2, t3, len);
    if (!fpriv(t3, &RSA_SK)) {
        fprintf(stderr, "RSA private operation failed (2)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA priv (2)", t1, t3, len);

    /*
	 * Third KAT vector is invalid, because the encrypted value is
	 * out of range: instead of x, value is x+n (where n is the
	 * modulus). Mathematically, this still works, but implementations
	 * are supposed to reject such cases.
	 */
    len = hextobin(t1, "F27781B9B3B358583A24F9BA6B34EE98B67A5AE8D8D4FA567BA773EB6B85EF88848680640A1E2F5FD117876E5FB928B64C6EFC7E03632A3F4C941E15657C0C705F3BB8D0B03A0249143674DB1FE6E5406D690BF2DA76EA7FF3AC6FCE12C7801252FAD52D332BE4AB41F9F8CF1728CDF98AB8E8C20E0C350E4F707A6402C01E0B");
    hextobin(t2, "BFB6A62E873F9C8DA0C42E7B59360FB0FFE12549E5E636B048C2086B77A7C051663506A959DF177F15F6B4E544EE723C531152C9C9614F923364704307F13F7F15ACF0C1547D55C029DC9ECCE41D117245F4D270FC34B21FF3AD6AEFE58633281540902F547F79F3461F44D33CCB2D094231ADCC76BE25511B4513BB70491DBC");
    memcpy(t3, t1, len);
    if (fpub(t3, len, &RSA_PK)) {
        size_t u;
        fprintf(stderr, "RSA public operation should have failed"
                        " (value out of range)\n");
        fprintf(stderr, "x = ");
        for (u = 0; u < len; u ++) {
            fprintf(stderr, "%02X", t3[u]);
        }
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }
    memcpy(t3, t2, len);
    if (fpriv(t3, &RSA_SK)) {
        size_t u;
        fprintf(stderr, "RSA private operation should have failed"
                        " (value out of range)\n");
        fprintf(stderr, "x = ");
        for (u = 0; u < len; u ++) {
            fprintf(stderr, "%02X", t3[u]);
        }
        fprintf(stderr, "\n");
        exit(EXIT_FAILURE);
    }

    /*
	 * RSA-2048 test vector.
	 */
    len = hextobin(t1, "B188ED4EF173A30AED3889926E3CF1CE03FE3BAA7AB122B119A8CD529062F235A7B321008FB898894A624B3E6C8C5374950E78FAC86651345FE2ABA0791968284F23B0D794F8DCDDA924518854822CB7FF2AA9F205AACD909BB5EA541534CC00DBC2EF7727B9FE1BAFE6241B931E8BD01E13632E5AF9E94F4A335772B61F24D6F6AA642AEABB173E36F546CB02B19A1E5D4E27E3EB67F2E986E9F084D4BD266543800B1DC96088A05DFA9AFA595398E9A766D41DD8DA4F74F36C9D74867F0BF7BFA8622EE43C79DA0CEAC14B5D39DE074BDB89D84145BC19D8B2D0EA74DBF2DC29E907BF7C7506A2603CD8BC25EFE955D0125EDB2685EF158B020C9FC539242A");
    hextobin(t2, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D060960864801650304020105000420A5A0A792A09438811584A68E240C6C89F1FB1C53C0C86E270B942635F4F6B24A");
    memcpy(t3, t1, len);
    if (!fpub(t3, len, &RSA2048_PK)) {
        fprintf(stderr, "RSA public operation failed (2048)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA pub", t2, t3, len);
    if (!fpriv(t3, &RSA2048_SK)) {
        fprintf(stderr, "RSA private operation failed (2048)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA priv (2048)", t1, t3, len);

    /*
	 * RSA-4096 test vector.
	 */
    len = hextobin(t1, "7D35B6B4D85252D08A2658C0B04126CC617B0E56B2A782A5FA2722AD05BD49538111682C12DA2C5FA1B9C30FB1AB8DA2C6A49EB4226A4D32290CF091FBB22EC499C7B18192C230B29F957DAF551F1EAD1917BA9E03D757100BD1F96B829708A6188A3927436113BB21E175D436BBB7A90E20162203FFB8F675313DFB21EFDA3EA0C7CC9B605AE7FB47E2DD2A9C4D5F124D7DE1B690AF9ADFEDC6055E0F9D2C9A891FB2501F3055D6DA7E94D51672BA1E86AEB782E4B020F70E0DF5399262909FC5B4770B987F2826EF2099A15F3CD5A0D6FE82E0C85FBA2C53C77305F534A7B0C7EA0D5244E37F1C1318EEF7079995F0642E4AB80EB0ED60DB4955FB652ED372DAC787581054A827C37A25C7B4DE7AE7EF3D099D47D6682ADF02BCC4DE04DDF2920F7124CF5B4955705E4BDB97A0BF341B584797878B4D3795134A9469FB391E4E4988F0AA451027CBC2ED6121FC23B26BF593E3C51DEDD53B62E23050D5B41CA34204679916A87AF1B17873A0867924D0C303942ADA478B769487FCEF861D4B20DCEE6942CCB84184833CDB258167258631C796BC1977D001354E2EE168ABE3B45FC969EA7F22B8E133C57A10FBB25ED19694E89C399CF7723B3C0DF0CC9F57A8ED0959EFC392FB31B8ADAEA969E2DEE8282CB245E5677368F00CCE4BA52C07C16BE7F9889D57191D5B2FE552D72B3415C64C09EE622457766EC809344A1EFE");
    hextobin(t2, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D0609608648016503040201050004205B60DD5AD5B3C62E0DA25FD0D8CB26325E1CE32CC9ED234B288235BCCF6ED2C8");
    memcpy(t3, t1, len);
    if (!fpub(t3, len, &RSA4096_PK)) {
        fprintf(stderr, "RSA public operation failed (4096)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA pub", t2, t3, len);
    if (!fpriv(t3, &RSA4096_SK)) {
        fprintf(stderr, "RSA private operation failed (4096)\n");
        exit(EXIT_FAILURE);
    }
    check_equals("KAT RSA priv (4096)", t1, t3, len);

    printf("done.\n");
    fflush(stdout);
}


/*
 * Fake RNG that returns exactly the provided bytes.
 */
typedef struct {
    const br_prng_class *vtable;
    unsigned char buf[128];
    size_t ptr, len;
} rng_fake_ctx;

static void rng_fake_init(rng_fake_ctx *cc,
                          const void *params, const void *seed, size_t len);
static void rng_fake_generate(rng_fake_ctx *cc, void *dst, size_t len);
static void rng_fake_update(rng_fake_ctx *cc, const void *src, size_t len);

static const br_prng_class rng_fake_vtable = {
        sizeof(rng_fake_ctx),
        (void (*)(const br_prng_class **,
                  const void *, const void *, size_t))&rng_fake_init,
        (void (*)(const br_prng_class **,
                  void *, size_t))&rng_fake_generate,
        (void (*)(const br_prng_class **,
                  const void *, size_t))&rng_fake_update
};

static void
rng_fake_init(rng_fake_ctx *cc, const void *params,
              const void *seed, size_t len)
{
    (void)params;
    if (len > sizeof cc->buf) {
        fprintf(stderr, "seed is too large (%lu bytes)\n",
                (unsigned long)len);
        exit(EXIT_FAILURE);
    }
    cc->vtable = &rng_fake_vtable;
    memcpy(cc->buf, seed, len);
    cc->ptr = 0;
    cc->len = len;
}

static void
rng_fake_generate(rng_fake_ctx *cc, void *dst, size_t len)
{
    if (len > (cc->len - cc->ptr)) {
        fprintf(stderr, "asking for more data than expected\n");
        exit(EXIT_FAILURE);
    }
    memcpy(dst, cc->buf + cc->ptr, len);
    cc->ptr += len;
}

static void
rng_fake_update(rng_fake_ctx *cc, const void *src, size_t len)
{
    (void)cc;
    (void)src;
    (void)len;
    fprintf(stderr, "unexpected update\n");
    exit(EXIT_FAILURE);
}

/*
 * Test vectors from pkcs-1v2-1d2-vec.zip (originally from ftp.rsa.com).
 * There are ten RSA keys, and for each RSA key, there are 6 messages,
 * each with an explicit salt.
 *
 * Field order:
 *    modulus (n)
 *    public exponent (e)
 *    first factor (p)
 *    second factor (q)
 *    first private exponent (dp)
 *    second private exponent (dq)
 *    CRT coefficient (iq)
 *    message 1
 *    salt 1 (20-byte random value)
 *    signature 1
 *    message 2
 *    salt 2 (20-byte random value)
 *    signature 2
 *    ...
 *    message 6
 *    salt 6 (20-byte random value)
 *    signature 6
 *
 * This pattern is repeated for all keys. The array stops on a NULL.
 */
static const char *KAT_RSA_PSS[] = {

        /* 1024-bit key */
        "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",
        "010001",
        "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",
        "e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",
        "b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",
        "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",
        "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",
        "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",

        "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0",
        "dee959c7e06411361420ff80185ed57f3e6776af",
        "9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c",

        "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f71a1cca582d43ecc72b1bca16dfc7013226b9e",
        "ef2869fa40c346cb183dab3d7bffc98fd56df42d",
        "3ef7f46e831bf92b32274142a585ffcefbdca7b32ae90d10fb0f0c729984f04ef29a9df0780775ce43739b97838390db0a5505e63de927028d9d29b219ca2c4517832558a55d694a6d25b9dab66003c4cccd907802193be5170d26147d37b93590241be51c25055f47ef62752cfbe21418fafe98c22c4d4d47724fdb5669e843",

        "a4b159941761c40c6a82f2b80d1b94f5aa2654fd17e12d588864679b54cd04ef8bd03012be8dc37f4b83af7963faff0dfa225477437c48017ff2be8191cf3955fc07356eab3f322f7f620e21d254e5db4324279fe067e0910e2e81ca2cab31c745e67a54058eb50d993cdb9ed0b4d029c06d21a94ca661c3ce27fae1d6cb20f4564d66ce4767583d0e5f060215b59017be85ea848939127bd8c9c4d47b51056c031cf336f17c9980f3b8f5b9b6878e8b797aa43b882684333e17893fe9caa6aa299f7ed1a18ee2c54864b7b2b99b72618fb02574d139ef50f019c9eef416971338e7d470",
        "710b9c4747d800d4de87f12afdce6df18107cc77",
        "666026fba71bd3e7cf13157cc2c51a8e4aa684af9778f91849f34335d141c00154c4197621f9624a675b5abc22ee7d5baaffaae1c9baca2cc373b3f33e78e6143c395a91aa7faca664eb733afd14d8827259d99a7550faca501ef2b04e33c23aa51f4b9e8282efdb728cc0ab09405a91607c6369961bc8270d2d4f39fce612b1",

        "bc656747fa9eafb3f0",
        "056f00985de14d8ef5cea9e82f8c27bef720335e",
        "4609793b23e9d09362dc21bb47da0b4f3a7622649a47d464019b9aeafe53359c178c91cd58ba6bcb78be0346a7bc637f4b873d4bab38ee661f199634c547a1ad8442e03da015b136e543f7ab07c0c13e4225b8de8cce25d4f6eb8400f81f7e1833b7ee6e334d370964ca79fdb872b4d75223b5eeb08101591fb532d155a6de87",

        "b45581547e5427770c768e8b82b75564e0ea4e9c32594d6bff706544de0a8776c7a80b4576550eee1b2acabc7e8b7d3ef7bb5b03e462c11047eadd00629ae575480ac1470fe046f13a2bf5af17921dc4b0aa8b02bee6334911651d7f8525d10f32b51d33be520d3ddf5a709955a3dfe78283b9e0ab54046d150c177f037fdccc5be4ea5f68b5e5a38c9d7edcccc4975f455a6909b4",
        "80e70ff86a08de3ec60972b39b4fbfdcea67ae8e",
        "1d2aad221ca4d31ddf13509239019398e3d14b32dc34dc5af4aeaea3c095af73479cf0a45e5629635a53a018377615b16cb9b13b3e09d671eb71e387b8545c5960da5a64776e768e82b2c93583bf104c3fdb23512b7b4e89f633dd0063a530db4524b01c3f384c09310e315a79dcd3d684022a7f31c865a664e316978b759fad",

        "10aae9a0ab0b595d0841207b700d48d75faedde3b775cd6b4cc88ae06e4694ec74ba18f8520d4f5ea69cbbe7cc2beba43efdc10215ac4eb32dc302a1f53dc6c4352267e7936cfebf7c8d67035784a3909fa859c7b7b59b8e39c5c2349f1886b705a30267d402f7486ab4f58cad5d69adb17ab8cd0ce1caf5025af4ae24b1fb8794c6070cc09a51e2f9911311e3877d0044c71c57a993395008806b723ac38373d395481818528c1e7053739282053529510e935cd0fa77b8fa53cc2d474bd4fb3cc5c672d6ffdc90a00f9848712c4bcfe46c60573659b11e6457e861f0f604b6138d144f8ce4e2da73",
        "a8ab69dd801f0074c2a1fc60649836c616d99681",
        "2a34f6125e1f6b0bf971e84fbd41c632be8f2c2ace7de8b6926e31ff93e9af987fbc06e51e9be14f5198f91f3f953bd67da60a9df59764c3dc0fe08e1cbef0b75f868d10ad3fba749fef59fb6dac46a0d6e504369331586f58e4628f39aa278982543bc0eeb537dc61958019b394fb273f215858a0a01ac4d650b955c67f4c58",

        /* 1025-bit key */
        "01d40c1bcf97a68ae7cdbd8a7bf3e34fa19dcca4ef75a47454375f94514d88fed006fb829f8419ff87d6315da68a1ff3a0938e9abb3464011c303ad99199cf0c7c7a8b477dce829e8844f625b115e5e9c4a59cf8f8113b6834336a2fd2689b472cbb5e5cabe674350c59b6c17e176874fb42f8fc3d176a017edc61fd326c4b33c9",
        "010001",
        "027d147e4673057377fd1ea201565772176a7dc38358d376045685a2e787c23c15576bc16b9f444402d6bfc5d98a3e88ea13ef67c353eca0c0ddba9255bd7b8bb50a644afdfd1dd51695b252d22e7318d1b6687a1c10ff75545f3db0fe602d5f2b7f294e3601eab7b9d1cecd767f64692e3e536ca2846cb0c2dd486a39fa75b1",
        "016601e926a0f8c9e26ecab769ea65a5e7c52cc9e080ef519457c644da6891c5a104d3ea7955929a22e7c68a7af9fcad777c3ccc2b9e3d3650bce404399b7e59d1",
        "014eafa1d4d0184da7e31f877d1281ddda625664869e8379e67ad3b75eae74a580e9827abd6eb7a002cb5411f5266797768fb8e95ae40e3e8a01f35ff89e56c079",
        "e247cce504939b8f0a36090de200938755e2444b29539a7da7a902f6056835c0db7b52559497cfe2c61a8086d0213c472c78851800b171f6401de2e9c2756f31",
        "b12fba757855e586e46f64c38a70c68b3f548d93d787b399999d4c8f0bbd2581c21e19ed0018a6d5d3df86424b3abcad40199d31495b61309f27c1bf55d487c1",
        "564b1e1fa003bda91e89090425aac05b91da9ee25061e7628d5f51304a84992fdc33762bd378a59f030a334d532bd0dae8f298ea9ed844636ad5fb8cbdc03cad",

        "daba032066263faedb659848115278a52c44faa3a76f37515ed336321072c40a9d9b53bc05014078adf520875146aae70ff060226dcb7b1f1fc27e9360",
        "57bf160bcb02bb1dc7280cf0458530b7d2832ff7",
        "014c5ba5338328ccc6e7a90bf1c0ab3fd606ff4796d3c12e4b639ed9136a5fec6c16d8884bdd99cfdc521456b0742b736868cf90de099adb8d5ffd1deff39ba4007ab746cefdb22d7df0e225f54627dc65466131721b90af445363a8358b9f607642f78fab0ab0f43b7168d64bae70d8827848d8ef1e421c5754ddf42c2589b5b3",

        "e4f8601a8a6da1be34447c0959c058570c3668cfd51dd5f9ccd6ad4411fe8213486d78a6c49f93efc2ca2288cebc2b9b60bd04b1e220d86e3d4848d709d032d1e8c6a070c6af9a499fcf95354b14ba6127c739de1bb0fd16431e46938aec0cf8ad9eb72e832a7035de9b7807bdc0ed8b68eb0f5ac2216be40ce920c0db0eddd3860ed788efaccaca502d8f2bd6d1a7c1f41ff46f1681c8f1f818e9c4f6d91a0c7803ccc63d76a6544d843e084e363b8acc55aa531733edb5dee5b5196e9f03e8b731b3776428d9e457fe3fbcb3db7274442d785890e9cb0854b6444dace791d7273de1889719338a77fe",
        "7f6dd359e604e60870e898e47b19bf2e5a7b2a90",
        "010991656cca182b7f29d2dbc007e7ae0fec158eb6759cb9c45c5ff87c7635dd46d150882f4de1e9ae65e7f7d9018f6836954a47c0a81a8a6b6f83f2944d6081b1aa7c759b254b2c34b691da67cc0226e20b2f18b42212761dcd4b908a62b371b5918c5742af4b537e296917674fb914194761621cc19a41f6fb953fbcbb649dea",

        "52a1d96c8ac39e41e455809801b927a5b445c10d902a0dcd3850d22a66d2bb0703e67d5867114595aabf5a7aeb5a8f87034bbb30e13cfd4817a9be76230023606d0286a3faf8a4d22b728ec518079f9e64526e3a0cc7941aa338c437997c680ccac67c66bfa1",
        "fca862068bce2246724b708a0519da17e648688c",
        "007f0030018f53cdc71f23d03659fde54d4241f758a750b42f185f87578520c30742afd84359b6e6e8d3ed959dc6fe486bedc8e2cf001f63a7abe16256a1b84df0d249fc05d3194ce5f0912742dbbf80dd174f6c51f6bad7f16cf3364eba095a06267dc3793803ac7526aebe0a475d38b8c2247ab51c4898df7047dc6adf52c6c4",

        "a7182c83ac18be6570a106aa9d5c4e3dbbd4afaeb0c60c4a23e1969d79ff",
        "8070ef2de945c02387684ba0d33096732235d440",
        "009cd2f4edbe23e12346ae8c76dd9ad3230a62076141f16c152ba18513a48ef6f010e0e37fd3df10a1ec629a0cb5a3b5d2893007298c30936a95903b6ba85555d9ec3673a06108fd62a2fda56d1ce2e85c4db6b24a81ca3b496c36d4fd06eb7c9166d8e94877c42bea622b3bfe9251fdc21d8d5371badad78a488214796335b40b",

        "86a83d4a72ee932a4f5630af6579a386b78fe88999e0abd2d49034a4bfc854dd94f1094e2e8cd7a179d19588e4aefc1b1bd25e95e3dd461f",
        "17639a4e88d722c4fca24d079a8b29c32433b0c9",
        "00ec430824931ebd3baa43034dae98ba646b8c36013d1671c3cf1cf8260c374b19f8e1cc8d965012405e7e9bf7378612dfcc85fce12cda11f950bd0ba8876740436c1d2595a64a1b32efcfb74a21c873b3cc33aaf4e3dc3953de67f0674c0453b4fd9f604406d441b816098cb106fe3472bc251f815f59db2e4378a3addc181ecf",

        "049f9154d871ac4a7c7ab45325ba7545a1ed08f70525b2667cf1",
        "37810def1055ed922b063df798de5d0aabf886ee",
        "00475b1648f814a8dc0abdc37b5527f543b666bb6e39d30e5b49d3b876dccc58eac14e32a2d55c2616014456ad2f246fc8e3d560da3ddf379a1c0bd200f10221df078c219a151bc8d4ec9d2fc2564467811014ef15d8ea01c2ebbff8c2c8efab38096e55fcbe3285c7aa558851254faffa92c1c72b78758663ef4582843139d7a6",

        /* 1026-bit key */
        "02f246ef451ed3eebb9a310200cc25859c048e4be798302991112eb68ce6db674e280da21feded1ae74880ca522b18db249385012827c515f0e466a1ffa691d98170574e9d0eadb087586ca48933da3cc953d95bd0ed50de10ddcb6736107d6c831c7f663e833ca4c097e700ce0fb945f88fb85fe8e5a773172565b914a471a443",
        "010001",
        "651451733b56de5ac0a689a4aeb6e6894a69014e076c88dd7a667eab3232bbccd2fc44ba2fa9c31db46f21edd1fdb23c5c128a5da5bab91e7f952b67759c7cff705415ac9fa0907c7ca6178f668fb948d869da4cc3b7356f4008dfd5449d32ee02d9a477eb69fc29266e5d9070512375a50fbbcc27e238ad98425f6ebbf88991",
        "01bd36e18ece4b0fdb2e9c9d548bd1a7d6e2c21c6fdc35074a1d05b1c6c8b3d558ea2639c9a9a421680169317252558bd148ad215aac550e2dcf12a82d0ebfe853",
        "01b1b656ad86d8e19d5dc86292b3a192fdf6e0dd37877bad14822fa00190cab265f90d3f02057b6f54d6ecb14491e5adeacebc48bf0ebd2a2ad26d402e54f61651",
        "1f2779fd2e3e5e6bae05539518fba0cd0ead1aa4513a7cba18f1cf10e3f68195693d278a0f0ee72f89f9bc760d80e2f9d0261d516501c6ae39f14a476ce2ccf5",
        "011a0d36794b04a854aab4b2462d439a5046c91d940b2bc6f75b62956fef35a2a6e63c5309817f307bbff9d59e7e331bd363f6d66849b18346adea169f0ae9aec1",
        "0b30f0ecf558752fb3a6ce4ba2b8c675f659eba6c376585a1b39712d038ae3d2b46fcb418ae15d0905da6440e1513a30b9b7d6668fbc5e88e5ab7a175e73ba35",

        "594b37333bbb2c84524a87c1a01f75fcec0e3256f108e38dca36d70d0057",
        "f31ad6c8cf89df78ed77feacbcc2f8b0a8e4cfaa",
        "0088b135fb1794b6b96c4a3e678197f8cac52b64b2fe907d6f27de761124964a99a01a882740ecfaed6c01a47464bb05182313c01338a8cd097214cd68ca103bd57d3bc9e816213e61d784f182467abf8a01cf253e99a156eaa8e3e1f90e3c6e4e3aa2d83ed0345b89fafc9c26077c14b6ac51454fa26e446e3a2f153b2b16797f",

        "8b769528884a0d1ffd090cf102993e796dadcfbddd38e44ff6324ca451",
        "fcf9f0e1f199a3d1d0da681c5b8606fc642939f7",
        "02a5f0a858a0864a4f65017a7d69454f3f973a2999839b7bbc48bf78641169179556f595fa41f6ff18e286c2783079bc0910ee9cc34f49ba681124f923dfa88f426141a368a5f5a930c628c2c3c200e18a7644721a0cbec6dd3f6279bde3e8f2be5e2d4ee56f97e7ceaf33054be7042bd91a63bb09f897bd41e81197dee99b11af",

        "1abdba489c5ada2f995ed16f19d5a94d9e6ec34a8d84f84557d26e5ef9b02b22887e3f9a4b690ad1149209c20c61431f0c017c36c2657b35d7b07d3f5ad8708507a9c1b831df835a56f831071814ea5d3d8d8f6ade40cba38b42db7a2d3d7a29c8f0a79a7838cf58a9757fa2fe4c40df9baa193bfc6f92b123ad57b07ace3e6ac068c9f106afd9eeb03b4f37c25dbfbcfb3071f6f9771766d072f3bb070af6605532973ae25051",
        "986e7c43dbb671bd41b9a7f4b6afc80e805f2423",
        "0244bcd1c8c16955736c803be401272e18cb990811b14f72db964124d5fa760649cbb57afb8755dbb62bf51f466cf23a0a1607576e983d778fceffa92df7548aea8ea4ecad2c29dd9f95bc07fe91ecf8bee255bfe8762fd7690aa9bfa4fa0849ef728c2c42c4532364522df2ab7f9f8a03b63f7a499175828668f5ef5a29e3802c",

        "8fb431f5ee792b6c2ac7db53cc428655aeb32d03f4e889c5c25de683c461b53acf89f9f8d3aabdf6b9f0c2a1de12e15b49edb3919a652fe9491c25a7fce1f722c2543608b69dc375ec",
        "f8312d9c8eea13ec0a4c7b98120c87509087c478",
        "0196f12a005b98129c8df13c4cb16f8aa887d3c40d96df3a88e7532ef39cd992f273abc370bc1be6f097cfebbf0118fd9ef4b927155f3df22b904d90702d1f7ba7a52bed8b8942f412cd7bd676c9d18e170391dcd345c06a730964b3f30bcce0bb20ba106f9ab0eeb39cf8a6607f75c0347f0af79f16afa081d2c92d1ee6f836b8",

        "fef4161dfaaf9c5295051dfc1ff3810c8c9ec2e866f7075422c8ec4216a9c4ff49427d483cae10c8534a41b2fd15fee06960ec6fb3f7a7e94a2f8a2e3e43dc4a40576c3097ac953b1de86f0b4ed36d644f23ae14425529622464ca0cbf0b1741347238157fab59e4de5524096d62baec63ac64",
        "50327efec6292f98019fc67a2a6638563e9b6e2d",
        "021eca3ab4892264ec22411a752d92221076d4e01c0e6f0dde9afd26ba5acf6d739ef987545d16683e5674c9e70f1de649d7e61d48d0caeb4fb4d8b24fba84a6e3108fee7d0705973266ac524b4ad280f7ae17dc59d96d3351586b5a3bdb895d1e1f7820ac6135d8753480998382ba32b7349559608c38745290a85ef4e9f9bd83",

        "efd237bb098a443aeeb2bf6c3f8c81b8c01b7fcb3feb",
        "b0de3fc25b65f5af96b1d5cc3b27d0c6053087b3",
        "012fafec862f56e9e92f60ab0c77824f4299a0ca734ed26e0644d5d222c7f0bde03964f8e70a5cb65ed44e44d56ae0edf1ff86ca032cc5dd4404dbb76ab854586c44eed8336d08d457ce6c03693b45c0f1efef93624b95b8ec169c616d20e5538ebc0b6737a6f82b4bc0570924fc6b35759a3348426279f8b3d7744e2d222426ce",

        /* 1027-bit key */
        "054adb7886447efe6f57e0368f06cf52b0a3370760d161cef126b91be7f89c421b62a6ec1da3c311d75ed50e0ab5fff3fd338acc3aa8a4e77ee26369acb81ba900fa83f5300cf9bb6c53ad1dc8a178b815db4235a9a9da0c06de4e615ea1277ce559e9c108de58c14a81aa77f5a6f8d1335494498848c8b95940740be7bf7c3705",
        "010001",
        "fa041f8cd9697ceed38ec8caa275523b4dd72b09a301d3541d72f5d31c05cbce2d6983b36183af10690bd46c46131e35789431a556771dd0049b57461bf060c1f68472e8a67c25f357e5b6b4738fa541a730346b4a07649a2dfa806a69c975b6aba64678acc7f5913e89c622f2d8abb1e3e32554e39df94ba60c002e387d9011",
        "029232336d2838945dba9dd7723f4e624a05f7375b927a87abe6a893a1658fd49f47f6c7b0fa596c65fa68a23f0ab432962d18d4343bd6fd671a5ea8d148413995",
        "020ef5efe7c5394aed2272f7e81a74f4c02d145894cb1b3cab23a9a0710a2afc7e3329acbb743d01f680c4d02afb4c8fde7e20930811bb2b995788b5e872c20bb1",
        "026e7e28010ecf2412d9523ad704647fb4fe9b66b1a681581b0e15553a89b1542828898f27243ebab45ff5e1acb9d4df1b051fbc62824dbc6f6c93261a78b9a759",
        "012ddcc86ef655998c39ddae11718669e5e46cf1495b07e13b1014cd69b3af68304ad2a6b64321e78bf3bbca9bb494e91d451717e2d97564c6549465d0205cf421",
        "010600c4c21847459fe576703e2ebecae8a5094ee63f536bf4ac68d3c13e5e4f12ac5cc10ab6a2d05a199214d1824747d551909636b774c22cac0b837599abcc75",

        "9fb03b827c8217d9",
        "ed7c98c95f30974fbe4fbddcf0f28d6021c0e91d",
        "0323d5b7bf20ba4539289ae452ae4297080feff4518423ff4811a817837e7d82f1836cdfab54514ff0887bddeebf40bf99b047abc3ecfa6a37a3ef00f4a0c4a88aae0904b745c846c4107e8797723e8ac810d9e3d95dfa30ff4966f4d75d13768d20857f2b1406f264cfe75e27d7652f4b5ed3575f28a702f8c4ed9cf9b2d44948",

        "0ca2ad77797ece86de5bf768750ddb5ed6a3116ad99bbd17edf7f782f0db1cd05b0f677468c5ea420dc116b10e80d110de2b0461ea14a38be68620392e7e893cb4ea9393fb886c20ff790642305bf302003892e54df9f667509dc53920df583f50a3dd61abb6fab75d600377e383e6aca6710eeea27156e06752c94ce25ae99fcbf8592dbe2d7e27453cb44de07100ebb1a2a19811a478adbeab270f94e8fe369d90b3ca612f9f",
        "22d71d54363a4217aa55113f059b3384e3e57e44",
        "049d0185845a264d28feb1e69edaec090609e8e46d93abb38371ce51f4aa65a599bdaaa81d24fba66a08a116cb644f3f1e653d95c89db8bbd5daac2709c8984000178410a7c6aa8667ddc38c741f710ec8665aa9052be929d4e3b16782c1662114c5414bb0353455c392fc28f3db59054b5f365c49e1d156f876ee10cb4fd70598",

        "288062afc08fcdb7c5f8650b29837300461dd5676c17a20a3c8fb5148949e3f73d66b3ae82c7240e27c5b3ec4328ee7d6ddf6a6a0c9b5b15bcda196a9d0c76b119d534d85abd123962d583b76ce9d180bce1ca",
        "4af870fbc6516012ca916c70ba862ac7e8243617",
        "03fbc410a2ced59500fb99f9e2af2781ada74e13145624602782e2994813eefca0519ecd253b855fb626a90d771eae028b0c47a199cbd9f8e3269734af4163599090713a3fa910fa0960652721432b971036a7181a2bc0cab43b0b598bc6217461d7db305ff7e954c5b5bb231c39e791af6bcfa76b147b081321f72641482a2aad",

        "6f4f9ab9501199cef55c6cf408fe7b36c557c49d420a4763d2463c8ad44b3cfc5be2742c0e7d9b0f6608f08c7f47b693ee",
        "40d2e180fae1eac439c190b56c2c0e14ddf9a226",
        "0486644bc66bf75d28335a6179b10851f43f09bded9fac1af33252bb9953ba4298cd6466b27539a70adaa3f89b3db3c74ab635d122f4ee7ce557a61e59b82ffb786630e5f9db53c77d9a0c12fab5958d4c2ce7daa807cd89ba2cc7fcd02ff470ca67b229fcce814c852c73cc93bea35be68459ce478e9d4655d121c8472f371d4f",

        "e17d20385d501955823c3f666254c1d3dd36ad5168b8f18d286fdcf67a7dad94097085fab7ed86fe2142a28771717997ef1a7a08884efc39356d76077aaf82459a7fad45848875f2819b098937fe923bcc9dc442d72d754d812025090c9bc03db3080c138dd63b355d0b4b85d6688ac19f4de15084a0ba4e373b93ef4a555096691915dc23c00e954cdeb20a47cd55d16c3d8681d46ed7f2ed5ea42795be17baed25f0f4d113b3636addd585f16a8b5aec0c8fa9c5f03cbf3b9b73",
        "2497dc2b4615dfae5a663d49ffd56bf7efc11304",
        "022a80045353904cb30cbb542d7d4990421a6eec16a8029a8422adfd22d6aff8c4cc0294af110a0c067ec86a7d364134459bb1ae8ff836d5a8a2579840996b320b19f13a13fad378d931a65625dae2739f0c53670b35d9d3cbac08e733e4ec2b83af4b9196d63e7c4ff1ddeae2a122791a125bfea8deb0de8ccf1f4ffaf6e6fb0a",

        "afbc19d479249018fdf4e09f618726440495de11ddeee38872d775fcea74a23896b5343c9c38d46af0dba224d047580cc60a65e9391cf9b59b36a860598d4e8216722f993b91cfae87bc255af89a6a199bca4a391eadbc3a24903c0bd667368f6be78e3feabfb4ffd463122763740ffbbefeab9a25564bc5d1c24c93e422f75073e2ad72bf45b10df00b52a147128e73fee33fa3f0577d77f80fbc2df1bed313290c12777f50",
        "a334db6faebf11081a04f87c2d621cdec7930b9b",
        "00938dcb6d583046065f69c78da7a1f1757066a7fa75125a9d2929f0b79a60b627b082f11f5b196f28eb9daa6f21c05e5140f6aef1737d2023075c05ecf04a028c686a2ab3e7d5a0664f295ce12995e890908b6ad21f0839eb65b70393a7b5afd9871de0caa0cedec5b819626756209d13ab1e7bb9546a26ff37e9a51af9fd562e",

        /* 1028-bit key */
        "0d10f661f29940f5ed39aa260966deb47843679d2b6fb25b3de370f3ac7c19916391fd25fb527ebfa6a4b4df45a1759d996c4bb4ebd18828c44fc52d0191871740525f47a4b0cc8da325ed8aa676b0d0f626e0a77f07692170acac8082f42faa7dc7cd123e730e31a87985204cabcbe6670d43a2dd2b2ddef5e05392fc213bc507",
        "010001",
        "03ce08b104fff396a979bd3e4e46925b6319ddb63acbcfd819f17d16b8077b3a87101ff34b77fe48b8b205a96e9151ba8ecea64d0cce7b23c3e6a6b83058bc49dae816ae736db5a4708e2ad435232b567f9096ce59ff28061e79ab1c02d717e6b23cea6db8eb5192fa7c1eab227dba74621c45601896eef13792c8440beb15aac1",
        "03f2f331f4142d4f24b43aa10279a89652d4e7537221a1a7b2a25deb551e5de9ac497411c227a94e45f91c2d1c13cc046cf4ce14e32d058734210d44a87ee1b73f",
        "034f090d73b55803030cf0361a5d8081bfb79f851523feac0a2124d08d4013ff08487771a870d0479dc0686c62f7718dfecf024b17c9267678059171339cc00839",
        "02aa663adbf51ab887a018cb426e78bc2fe182dcb2f7bcb50441d17fdf0f06798b5071c6e2f5feb4d54ad8182311c1ef62d4c49f18d1f51f54b2d2cffba4da1be5",
        "02bbe706078b5c0b391512d411db1b199b5a5664b84042ead37fe994ae72b9532dfbfb3e9e6981a0fbb806513141b7c2163fe56c395e4bfaee57e3833f9b918df9",
        "0242b6cd00d30a767aee9a898ead453c8eaea63d500b7d1e00713edae51ce36b23b664df26e63e266ec8f76e6e63ed1ba41eb033b120f7ea5212ae21a98fbc16",

        "30c7d557458b436decfdc14d06cb7b96b06718c48d7de57482a868ae7f065870a6216506d11b779323dfdf046cf5775129134b4d5689e4d9c0ce1e12d7d4b06cb5fc5820decfa41baf59bf257b32f025b7679b445b9499c92555145885992f1b76f84891ee4d3be0f5150fd5901e3a4c8ed43fd36b61d022e65ad5008dbf33293c22bfbfd07321f0f1d5fa9fdf0014c2fcb0358aad0e354b0d29",
        "081b233b43567750bd6e78f396a88b9f6a445151",
        "0ba373f76e0921b70a8fbfe622f0bf77b28a3db98e361051c3d7cb92ad0452915a4de9c01722f6823eeb6adf7e0ca8290f5de3e549890ac2a3c5950ab217ba58590894952de96f8df111b2575215da6c161590c745be612476ee578ed384ab33e3ece97481a252f5c79a98b5532ae00cdd62f2ecc0cd1baefe80d80b962193ec1d",

        "e7b32e1556ea1b2795046ac69739d22ac8966bf11c116f614b166740e96b90653e5750945fcf772186c03790a07fda323e1a61916b06ee2157db3dff80d67d5e39a53ae268c8f09ed99a732005b0bc6a04af4e08d57a00e7201b3060efaadb73113bfc087fd837093aa25235b8c149f56215f031c24ad5bde7f29960df7d524070f7449c6f785084be1a0f733047f336f9154738674547db02a9f44dfc6e60301081e1ce99847f3b5b601ff06b4d5776a9740b9aa0d34058fd3b906e4f7859dfb07d7173e5e6f6350adac21f27b2307469",
        "bd0ce19549d0700120cbe51077dbbbb00a8d8b09",
        "08180de825e4b8b014a32da8ba761555921204f2f90d5f24b712908ff84f3e220ad17997c0dd6e706630ba3e84add4d5e7ab004e58074b549709565d43ad9e97b5a7a1a29e85b9f90f4aafcdf58321de8c5974ef9abf2d526f33c0f2f82e95d158ea6b81f1736db8d1af3d6ac6a83b32d18bae0ff1b2fe27de4c76ed8c7980a34e",

        "8d8396e36507fe1ef6a19017548e0c716674c2fec233adb2f775665ec41f2bd0ba396b061a9daa7e866f7c23fd3531954300a342f924535ea1498c48f6c879932865fc02000c528723b7ad0335745b51209a0afed932af8f0887c219004d2abd894ea92559ee3198af3a734fe9b9638c263a728ad95a5ae8ce3eb15839f3aa7852bb390706e7760e43a71291a2e3f827237deda851874c517665f545f27238df86557f375d09ccd8bd15d8ccf61f5d78ca5c7f5cde782e6bf5d0057056d4bad98b3d2f9575e824ab7a33ff57b0ac100ab0d6ead7aa0b50f6e4d3e5ec0b966b",
        "815779a91b3a8bd049bf2aeb920142772222c9ca",
        "05e0fdbdf6f756ef733185ccfa8ced2eb6d029d9d56e35561b5db8e70257ee6fd019d2f0bbf669fe9b9821e78df6d41e31608d58280f318ee34f559941c8df13287574bac000b7e58dc4f414ba49fb127f9d0f8936638c76e85356c994f79750f7fa3cf4fd482df75e3fb9978cd061f7abb17572e6e63e0bde12cbdcf18c68b979",

        "328c659e0a6437433cceb73c14",
        "9aec4a7480d5bbc42920d7ca235db674989c9aac",
        "0bc989853bc2ea86873271ce183a923ab65e8a53100e6df5d87a24c4194eb797813ee2a187c097dd872d591da60c568605dd7e742d5af4e33b11678ccb63903204a3d080b0902c89aba8868f009c0f1c0cb85810bbdd29121abb8471ff2d39e49fd92d56c655c8e037ad18fafbdc92c95863f7f61ea9efa28fea401369d19daea1",

        "f37b962379a47d415a376eec8973150bcb34edd5ab654041b61430560c2144582ba133c867d852d6b8e23321901302ecb45b09ec88b1527178fa043263f3067d9ffe973032a99f4cb08ad2c7e0a2456cdd57a7df56fe6053527a5aeb67d7e552063c1ca97b1beffa7b39e997caf27878ea0f62cbebc8c21df4c889a202851e949088490c249b6e9acf1d8063f5be2343989bf95c4da01a2be78b4ab6b378015bc37957f76948b5e58e440c28453d40d7cfd57e7d690600474ab5e75973b1ea0c5f1e45d14190afe2f4eb6d3bdf71f1d2f8bb156a1c295d04aaeb9d689dce79ed62bc443e",
        "e20c1e9878512c39970f58375e1549a68b64f31d",
        "0aefa943b698b9609edf898ad22744ac28dc239497cea369cbbd84f65c95c0ad776b594740164b59a739c6ff7c2f07c7c077a86d95238fe51e1fcf33574a4ae0684b42a3f6bf677d91820ca89874467b2c23add77969c80717430d0efc1d3695892ce855cb7f7011630f4df26def8ddf36fc23905f57fa6243a485c770d5681fcd",

        "c6103c330c1ef718c141e47b8fa859be4d5b96259e7d142070ecd485839dba5a8369c17c1114035e532d195c74f44a0476a2d3e8a4da210016caced0e367cb867710a4b5aa2df2b8e5daf5fdc647807d4d5ebb6c56b9763ccdae4dea3308eb0ac2a89501cb209d2639fa5bf87ce790747d3cb2d295e84564f2f637824f0c13028129b0aa4a422d162282",
        "23291e4a3307e8bbb776623ab34e4a5f4cc8a8db",
        "02802dccfa8dfaf5279bf0b4a29ba1b157611faeaaf419b8919d15941900c1339e7e92e6fae562c53e6cc8e84104b110bce03ad18525e3c49a0eadad5d3f28f244a8ed89edbafbb686277cfa8ae909714d6b28f4bf8e293aa04c41efe7c0a81266d5c061e2575be032aa464674ff71626219bd74cc45f0e7ed4e3ff96eee758e8f",

        /* 1029-bit key */
        "164ca31cff609f3a0e7101b039f2e4fe6dd37519ab98598d179e174996598071f47d3a04559158d7be373cf1aa53f0aa6ef09039e5678c2a4c63900514c8c4f8aaed5de12a5f10b09c311af8c0ffb5b7a297f2efc63b8d6b0510931f0b98e48bf5fc6ec4e7b8db1ffaeb08c38e02adb8f03a48229c99e969431f61cb8c4dc698d1",
        "010001",
        "03b664ee3b7566723fc6eaf28abb430a3980f1126c81de8ad709eab39ac9dcd0b1550b3729d87068e952009df544534c1f50829a78f4591eb8fd57140426a6bb0405b6a6f51a57d9267b7bbc653391a699a2a90dac8ae226bcc60fa8cd934c73c7b03b1f6b818158631838a8612e6e6ea92be24f8324faf5b1fd8587225267ba6f",
        "04f0548c9626ab1ebf1244934741d99a06220efa2a5856aa0e75730b2ec96adc86be894fa2803b53a5e85d276acbd29ab823f80a7391bb54a5051672fb04eeb543",
        "0483e0ae47915587743ff345362b555d3962d98bb6f15f848b4c92b1771ca8ed107d8d3ee65ec44517dd0faa481a387e902f7a2e747c269e7ea44480bc538b8e5b",
        "03a8e8aea9920c1aa3b2f0d846e4b850d81ca306a51c83544f949f64f90dcf3f8e2661f07e561220a180388fbe273e70e2e5dca83a0e1348dd6490c731d6ece1ab",
        "0135bdcdb60bf2197c436ed34b32cd8b4fc77778832ba76703551fb242b301699593af77fd8fc394a8526ad23cc41a03806bd897fe4b0ea646558aaddcc99e8a25",
        "0304c03d9c736503a984abbd9ba22301407c4a2ab1dd85766481b60d45401152e692be14f4121d9aa3fd6e0b4d1d3a973538a31d42ee6e1e5ef620231a2bbaf35f",

        "0a20b774addc2fa51245ed7cb9da609e50cac6636a52543f97458eed7340f8d53ffc64918f949078ee03ef60d42b5fec246050bd5505cd8cb597bad3c4e713b0ef30644e76adabb0de01a1561efb255158c74fc801e6e919e581b46f0f0ddd08e4f34c7810b5ed8318f91d7c8c",
        "5b4ea2ef629cc22f3b538e016904b47b1e40bfd5",
        "04c0cfacec04e5badbece159a5a1103f69b3f32ba593cb4cc4b1b7ab455916a96a27cd2678ea0f46ba37f7fc9c86325f29733b389f1d97f43e7201c0f348fc45fe42892335362eee018b5b161f2f9393031225c713012a576bc88e23052489868d9010cbf033ecc568e8bc152bdc59d560e41291915d28565208e22aeec9ef85d1",

        "2aaff6631f621ce615760a9ebce94bb333077ad86488c861d4b76d29c1f48746c611ae1e03ced4445d7cfa1fe5f62e1b3f08452bde3b6ef81973bafbb57f97bceef873985395b8260589aa88cb7db50ab469262e551bdcd9a56f275a0ac4fe484700c35f3dbf2b469ede864741b86fa59172a360ba95a02e139be50ddfb7cf0b42faeabbfbbaa86a4497699c4f2dfd5b08406af7e14144427c253ec0efa20eaf9a8be8cd49ce1f1bc4e93e619cf2aa8ed4fb39bc8590d0f7b96488f7317ac9abf7bee4e3a0e715",
        "83146a9e782722c28b014f98b4267bda2ac9504f",
        "0a2314250cf52b6e4e908de5b35646bcaa24361da8160fb0f9257590ab3ace42b0dc3e77ad2db7c203a20bd952fbb56b1567046ecfaa933d7b1000c3de9ff05b7d989ba46fd43bc4c2d0a3986b7ffa13471d37eb5b47d64707bd290cfd6a9f393ad08ec1e3bd71bb5792615035cdaf2d8929aed3be098379377e777ce79aaa4773",

        "0f6195d04a6e6fc7e2c9600dbf840c39ea8d4d624fd53507016b0e26858a5e0aecd7ada543ae5c0ab3a62599cba0a54e6bf446e262f989978f9ddf5e9a41",
        "a87b8aed07d7b8e2daf14ddca4ac68c4d0aabff8",
        "086df6b500098c120f24ff8423f727d9c61a5c9007d3b6a31ce7cf8f3cbec1a26bb20e2bd4a046793299e03e37a21b40194fb045f90b18bf20a47992ccd799cf9c059c299c0526854954aade8a6ad9d97ec91a1145383f42468b231f4d72f23706d9853c3fa43ce8ace8bfe7484987a1ec6a16c8daf81f7c8bf42774707a9df456",

        "337d25fe9810ebca0de4d4658d3ceb8e0fe4c066aba3bcc48b105d3bf7e0257d44fecea6596f4d0c59a08402833678f70620f9138dfeb7ded905e4a6d5f05c473d55936652e2a5df43c0cfda7bacaf3087f4524b06cf42157d01539739f7fddec9d58125df31a32eab06c19b71f1d5bf",
        "a37932f8a7494a942d6f767438e724d6d0c0ef18",
        "0b5b11ad549863ffa9c51a14a1106c2a72cc8b646e5c7262509786105a984776534ca9b54c1cc64bf2d5a44fd7e8a69db699d5ea52087a4748fd2abc1afed1e5d6f7c89025530bdaa2213d7e030fa55df6f34bcf1ce46d2edf4e3ae4f3b01891a068c9e3a44bbc43133edad6ecb9f35400c4252a5762d65744b99cb9f4c559329f",

        "84ec502b072e8287789d8f9235829ea3b187afd4d4c785611bda5f9eb3cb96717efa7007227f1c08cbcb972e667235e0fb7d431a6570326d2ecce35adb373dc753b3be5f829b89175493193fab16badb41371b3aac0ae670076f24bef420c135add7cee8d35fbc944d79fafb9e307a13b0f556cb654a06f973ed22672330197ef5a748bf826a5db2383a25364b686b9372bb2339aeb1ac9e9889327d016f1670776db06201adbdcaf8a5e3b74e108b73",
        "7b790c1d62f7b84e94df6af28917cf571018110e",
        "02d71fa9b53e4654fefb7f08385cf6b0ae3a817942ebf66c35ac67f0b069952a3ce9c7e1f1b02e480a9500836de5d64cdb7ecde04542f7a79988787e24c2ba05f5fd482c023ed5c30e04839dc44bed2a3a3a4fee01113c891a47d32eb8025c28cb050b5cdb576c70fe76ef523405c08417faf350b037a43c379339fcb18d3a356b",

        "9906d89f97a9fdedd3ccd824db687326f30f00aa25a7fca2afcb3b0f86cd41e73f0e8ff7d2d83f59e28ed31a5a0d551523374de22e4c7e8ff568b386ee3dc41163f10bf67bb006261c9082f9af90bf1d9049a6b9fae71c7f84fbe6e55f02789de774f230f115026a4b4e96c55b04a95da3aacbb2cece8f81764a1f1c99515411087cf7d34aeded0932c183",
        "fbbe059025b69b89fb14ae2289e7aaafe60c0fcd",
        "0a40a16e2fe2b38d1df90546167cf9469c9e3c3681a3442b4b2c2f581deb385ce99fc6188bb02a841d56e76d301891e24560550fcc2a26b55f4ccb26d837d350a154bcaca8392d98fa67959e9727b78cad03269f56968fc56b68bd679926d83cc9cb215550645ccda31c760ff35888943d2d8a1d351e81e5d07b86182e751081ef",

        /* 1030-bit key */
        "37c9da4a66c8c408b8da27d0c9d79f8ccb1eafc1d2fe48746d940b7c4ef5dee18ad12647cefaa0c4b3188b221c515386759b93f02024b25ab9242f8357d8f3fd49640ee5e643eaf6c64deefa7089727c8ff03993333915c6ef21bf5975b6e50d118b51008ec33e9f01a0a545a10a836a43ddbca9d8b5c5d3548022d7064ea29ab3",
        "010001",
        "3bed999052d957bc06d651eef6e3a98094b1621bd38b5449bd6c4aea3de7e084679a4484ded25be0f0826cf3377825414b14d4d61db14de626fbb80e5f4faec956f9a0a2d24f99576380f084eb62e46a57d554278b535626193ce02060575eb66c5798d36f6c5d40fb00d809b42a73102c1c74ee95bd71420fffef6318b52c29",
        "07eefb424b0e3a40e4208ee5afb280b22317308114dde0b4b64f730184ec68da6ce2867a9f48ed7726d5e2614ed04a5410736c8c714ee702474298c6292af07535",
        "070830dbf947eac0228de26314b59b66994cc60e8360e75d3876298f8f8a7d141da064e5ca026a973e28f254738cee669c721b034cb5f8e244dadd7cd1e159d547",
        "0524d20c3d95cff75af2313483227d8702717aa576de155f960515501adb1d70e1c04de91b75b161dbf0398356127ededa7bbc19a32dc1621cc9f53c265d0ce331",
        "05f984a1f23c938d6a0e89724bcf3dd93f9946926037fe7c6b13a29e5284855f89089591d440975627bf5c9e3a8b5ca79c772ad273e40d321af4a6c97dfded78d3",
        "ddd918adada29dcab981ff9acba4257023c09a3801ccce098ce268f855d0df570cd6e7b9b14bd9a5a9254cbc315be6f8ba1e2546ddd569c5ea19eed8353bde5e",

        "9ead0e01945640674eb41cad435e2374eaefa8ad7197d97913c44957d8d83f40d76ee60e39bf9c0f9eaf3021421a074d1ade962c6e9d3dc3bb174fe4dfe652b09115495b8fd2794174020a0602b5ca51848cfc96ce5eb57fc0a2adc1dda36a7cc452641a14911b37e45bfa11daa5c7ecdb74f6d0100d1d3e39e752800e203397de0233077b9a88855537fae927f924380d780f98e18dcff39c5ea741b17d6fdd1885bc9d581482d771ceb562d78a8bf88f0c75b11363e5e36cd479ceb0545f9da84203e0e6e508375cc9e844b88b7ac7a0a201ea0f1bee9a2c577920ca02c01b9d8320e974a56f4efb5763b96255abbf8037bf1802cf018f56379493e569a9",
        "b7867a59958cb54328f8775e6546ec06d27eaa50",
        "187f390723c8902591f0154bae6d4ecbffe067f0e8b795476ea4f4d51ccc810520bb3ca9bca7d0b1f2ea8a17d873fa27570acd642e3808561cb9e975ccfd80b23dc5771cdb3306a5f23159dacbd3aa2db93d46d766e09ed15d900ad897a8d274dc26b47e994a27e97e2268a766533ae4b5e42a2fcaf755c1c4794b294c60555823",

        "8d80d2d08dbd19c154df3f14673a14bd03735231f24e86bf153d0e69e74cbff7b1836e664de83f680124370fc0f96c9b65c07a366b644c4ab3",
        "0c09582266df086310821ba7e18df64dfee6de09",
        "10fd89768a60a67788abb5856a787c8561f3edcf9a83e898f7dc87ab8cce79429b43e56906941a886194f137e591fe7c339555361fbbe1f24feb2d4bcdb80601f3096bc9132deea60ae13082f44f9ad41cd628936a4d51176e42fc59cb76db815ce5ab4db99a104aafea68f5d330329ebf258d4ede16064bd1d00393d5e1570eb8",

        "808405cdfc1a58b9bb0397c720722a81fffb76278f335917ef9c473814b3e016ba2973cd2765f8f3f82d6cc38aa7f8551827fe8d1e3884b7e61c94683b8f82f1843bdae2257eeec9812ad4c2cf283c34e0b0ae0fe3cb990cf88f2ef9",
        "28039dcfe106d3b8296611258c4a56651c9e92dd",
        "2b31fde99859b977aa09586d8e274662b25a2a640640b457f594051cb1e7f7a911865455242926cf88fe80dfa3a75ba9689844a11e634a82b075afbd69c12a0df9d25f84ad4945df3dc8fe90c3cefdf26e95f0534304b5bdba20d3e5640a2ebfb898aac35ae40f26fce5563c2f9f24f3042af76f3c7072d687bbfb959a88460af1",

        "f337b9bad937de22a1a052dff11134a8ce26976202981939b91e0715ae5e609649da1adfcef3f4cca59b238360e7d1e496c7bf4b204b5acff9bbd6166a1d87a36ef2247373751039f8a800b8399807b3a85f44893497c0d05fb7017b82228152de6f25e6116dcc7503c786c875c28f3aa607e94ab0f19863ab1b5073770b0cd5f533acde30c6fb953cf3da680264e30fc11bff9a19bffab4779b6223c3fb3fe0f71abade4eb7c09c41e24c22d23fa148e6a173feb63984d1bc6ee3a02d915b752ceaf92a3015eceb38ca586c6801b37c34cefb2cff25ea23c08662dcab26a7a93a285d05d3044c",
        "a77821ebbbef24628e4e12e1d0ea96de398f7b0f",
        "32c7ca38ff26949a15000c4ba04b2b13b35a3810e568184d7ecabaa166b7ffabddf2b6cf4ba07124923790f2e5b1a5be040aea36fe132ec130e1f10567982d17ac3e89b8d26c3094034e762d2e031264f01170beecb3d1439e05846f25458367a7d9c02060444672671e64e877864559ca19b2074d588a281b5804d23772fbbe19",

        "45013cebafd960b255476a8e2598b9aa32efbe6dc1f34f4a498d8cf5a2b4548d08c55d5f95f7bcc9619163056f2d58b52fa032",
        "9d5ad8eb452134b65dc3a98b6a73b5f741609cd6",
        "07eb651d75f1b52bc263b2e198336e99fbebc4f332049a922a10815607ee2d989db3a4495b7dccd38f58a211fb7e193171a3d891132437ebca44f318b280509e52b5fa98fcce8205d9697c8ee4b7ff59d4c59c79038a1970bd2a0d451ecdc5ef11d9979c9d35f8c70a6163717607890d586a7c6dc01c79f86a8f28e85235f8c2f1",

        "2358097086c899323e75d9c90d0c09f12d9d54edfbdf70a9c2eb5a04d8f36b9b2bdf2aabe0a5bda1968937f9d6ebd3b6b257efb3136d4131f9acb59b85e2602c2a3fcdc835494a1f4e5ec18b226c80232b36a75a45fdf09a7ea9e98efbde1450d1194bf12e15a4c5f9eb5c0bce5269e0c3b28cfab655d81a61a20b4be2f54459bb25a0db94c52218be109a7426de83014424789aaa90e5056e632a698115e282c1a56410f26c2072f193481a9dcd880572005e64f4082ecf",
        "3f2efc595880a7d47fcf3cba04983ea54c4b73fb",
        "18da3cdcfe79bfb77fd9c32f377ad399146f0a8e810620233271a6e3ed3248903f5cdc92dc79b55d3e11615aa056a795853792a3998c349ca5c457e8ca7d29d796aa24f83491709befcfb1510ea513c92829a3f00b104f655634f320752e130ec0ccf6754ff893db302932bb025eb60e87822598fc619e0e981737a9a4c4152d33",

        /* 1031-bit key */
        "495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f778a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e582de9f2a4a4e0a2d0900bef4753db3cee0ee06c7dfae8b1d53b5953218f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a2b8efab0561b0810344739ada0733f",
        "010001",
        "6c66ffe98980c38fcdeab5159898836165f4b4b817c4f6a8d486ee4ea9130fe9b9092bd136d184f95f504a607eac565846d2fdd6597a8967c7396ef95a6eeebb4578a643966dca4d8ee3de842de63279c618159c1ab54a89437b6a6120e4930afb52a4ba6ced8a4947ac64b30a3497cbe701c2d6266d517219ad0ec6d347dbe9",
        "08dad7f11363faa623d5d6d5e8a319328d82190d7127d2846c439b0ab72619b0a43a95320e4ec34fc3a9cea876422305bd76c5ba7be9e2f410c8060645a1d29edb",
        "0847e732376fc7900f898ea82eb2b0fc418565fdae62f7d9ec4ce2217b97990dd272db157f99f63c0dcbb9fbacdbd4c4dadb6df67756358ca4174825b48f49706d",
        "05c2a83c124b3621a2aa57ea2c3efe035eff4560f33ddebb7adab81fce69a0c8c2edc16520dda83d59a23be867963ac65f2cc710bbcfb96ee103deb771d105fd85",
        "04cae8aa0d9faa165c87b682ec140b8ed3b50b24594b7a3b2c220b3669bb819f984f55310a1ae7823651d4a02e99447972595139363434e5e30a7e7d241551e1b9",
        "07d3e47bf686600b11ac283ce88dbb3f6051e8efd04680e44c171ef531b80b2b7c39fc766320e2cf15d8d99820e96ff30dc69691839c4b40d7b06e45307dc91f3f",

        "81332f4be62948415ea1d899792eeacf6c6e1db1da8be13b5cea41db2fed467092e1ff398914c714259775f595f8547f735692a575e6923af78f22c6997ddb90fb6f72d7bb0dd5744a31decd3dc3685849836ed34aec596304ad11843c4f88489f209735f5fb7fdaf7cec8addc5818168f880acbf490d51005b7a8e84e43e54287977571dd99eea4b161eb2df1f5108f12a4142a83322edb05a75487a3435c9a78ce53ed93bc550857d7a9fb",
        "1d65491d79c864b373009be6f6f2467bac4c78fa",
        "0262ac254bfa77f3c1aca22c5179f8f040422b3c5bafd40a8f21cf0fa5a667ccd5993d42dbafb409c520e25fce2b1ee1e716577f1efa17f3da28052f40f0419b23106d7845aaf01125b698e7a4dfe92d3967bb00c4d0d35ba3552ab9a8b3eef07c7fecdbc5424ac4db1e20cb37d0b2744769940ea907e17fbbca673b20522380c5",

        "e2f96eaf0e05e7ba326ecca0ba7fd2f7c02356f3cede9d0faabf4fcc8e60a973e5595fd9ea08",
        "435c098aa9909eb2377f1248b091b68987ff1838",
        "2707b9ad5115c58c94e932e8ec0a280f56339e44a1b58d4ddcff2f312e5f34dcfe39e89c6a94dcee86dbbdae5b79ba4e0819a9e7bfd9d982e7ee6c86ee68396e8b3a14c9c8f34b178eb741f9d3f121109bf5c8172fada2e768f9ea1433032c004a8aa07eb990000a48dc94c8bac8aabe2b09b1aa46c0a2aa0e12f63fbba775ba7e",

        "e35c6ed98f64a6d5a648fcab8adb16331db32e5d15c74a40edf94c3dc4a4de792d190889f20f1e24ed12054a6b28798fcb42d1c548769b734c96373142092aed277603f4738df4dc1446586d0ec64da4fb60536db2ae17fc7e3c04bbfbbbd907bf117c08636fa16f95f51a6216934d3e34f85030f17bbbc5ba69144058aff081e0b19cf03c17195c5e888ba58f6fe0a02e5c3bda9719a7",
        "c6ebbe76df0c4aea32c474175b2f136862d04529",
        "2ad20509d78cf26d1b6c406146086e4b0c91a91c2bd164c87b966b8faa42aa0ca446022323ba4b1a1b89706d7f4c3be57d7b69702d168ab5955ee290356b8c4a29ed467d547ec23cbadf286ccb5863c6679da467fc9324a151c7ec55aac6db4084f82726825cfe1aa421bc64049fb42f23148f9c25b2dc300437c38d428aa75f96",

        "dbc5f750a7a14be2b93e838d18d14a8695e52e8add9c0ac733b8f56d2747e529a0cca532dd49b902aefed514447f9e81d16195c2853868cb9b30f7d0d495c69d01b5c5d50b27045db3866c2324a44a110b1717746de457d1c8c45c3cd2a92970c3d59632055d4c98a41d6e99e2a3ddd5f7f9979ab3cd18f37505d25141de2a1bff17b3a7dce9419ecc385cf11d72840f19953fd0509251f6cafde2893d0e75c781ba7a5012ca401a4fa99e04b3c3249f926d5afe82cc87dab22c3c1b105de48e34ace9c9124e59597ac7ebf8",
        "021fdcc6ebb5e19b1cb16e9c67f27681657fe20a",
        "1e24e6e58628e5175044a9eb6d837d48af1260b0520e87327de7897ee4d5b9f0df0be3e09ed4dea8c1454ff3423bb08e1793245a9df8bf6ab3968c8eddc3b5328571c77f091cc578576912dfebd164b9de5454fe0be1c1f6385b328360ce67ec7a05f6e30eb45c17c48ac70041d2cab67f0a2ae7aafdcc8d245ea3442a6300ccc7",

        "04dc251be72e88e5723485b6383a637e2fefe07660c519a560b8bc18bdedb86eae2364ea53ba9dca6eb3d2e7d6b806af42b3e87f291b4a8881d5bf572cc9a85e19c86acb28f098f9da0383c566d3c0f58cfd8f395dcf602e5cd40e8c7183f714996e2297ef",
        "c558d7167cbb4508ada042971e71b1377eea4269",
        "33341ba3576a130a50e2a5cf8679224388d5693f5accc235ac95add68e5eb1eec31666d0ca7a1cda6f70a1aa762c05752a51950cdb8af3c5379f18cfe6b5bc55a4648226a15e912ef19ad77adeea911d67cfefd69ba43fa4119135ff642117ba985a7e0100325e9519f1ca6a9216bda055b5785015291125e90dcd07a2ca9673ee",

        "0ea37df9a6fea4a8b610373c24cf390c20fa6e2135c400c8a34f5c183a7e8ea4c9ae090ed31759f42dc77719cca400ecdcc517acfc7ac6902675b2ef30c509665f3321482fc69a9fb570d15e01c845d0d8e50d2a24cbf1cf0e714975a5db7b18d9e9e9cb91b5cb16869060ed18b7b56245503f0caf90352b8de81cb5a1d9c6336092f0cd",
        "76fd4e64fdc98eb927a0403e35a084e76ba9f92a",
        "1ed1d848fb1edb44129bd9b354795af97a069a7a00d0151048593e0c72c3517ff9ff2a41d0cb5a0ac860d736a199704f7cb6a53986a88bbd8abcc0076a2ce847880031525d449da2ac78356374c536e343faa7cba42a5aaa6506087791c06a8e989335aed19bfab2d5e67e27fb0c2875af896c21b6e8e7309d04e4f6727e69463e",

        /* 1536-bit key */
        "e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd06c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee315ad4ccb1534268352691c524f6dd8e6c29d224cf246973aec86c5bf6b1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddbc2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8de3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6fd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b",
        "010001",
        "6a7fd84fb85fad073b34406db74f8d61a6abc12196a961dd79565e9da6e5187bce2d980250f7359575359270d91590bb0e427c71460b55d51410b191bcf309fea131a92c8e702738fa719f1e0041f52e40e91f229f4d96a1e6f172e15596b4510a6daec26105f2bebc53316b87bdf21311666070e8dfee69d52c71a976caae79c72b68d28580dc686d9f5129d225f82b3d615513a882b3db91416b48ce08888213e37eeb9af800d81cab328ce420689903c00c7b5fd31b75503a6d419684d629",
        "f8eb97e98df12664eefdb761596a69ddcd0e76daece6ed4bf5a1b50ac086f7928a4d2f8726a77e515b74da41988f220b1cc87aa1fc810ce99a82f2d1ce821edced794c6941f42c7a1a0b8c4d28c75ec60b652279f6154a762aed165d47dee367",
        "ed4d71d0a6e24b93c2e5f6b4bbe05f5fb0afa042d204fe3378d365c2f288b6a8dad7efe45d153eef40cacc7b81ff934002d108994b94a5e4728cd9c963375ae49965bda55cbf0efed8d6553b4027f2d86208a6e6b489c176128092d629e49d3d",
        "2bb68bddfb0c4f56c8558bffaf892d8043037841e7fa81cfa61a38c5e39b901c8ee71122a5da2227bd6cdeeb481452c12ad3d61d5e4f776a0ab556591befe3e59e5a7fddb8345e1f2f35b9f4cee57c32414c086aec993e9353e480d9eec6289f",
        "4ff897709fad079746494578e70fd8546130eeab5627c49b080f05ee4ad9f3e4b7cba9d6a5dff113a41c3409336833f190816d8a6bc42e9bec56b7567d0f3c9c696db619b245d901dd856db7c8092e77e9a1cccd56ee4dba42c5fdb61aec2669",
        "77b9d1137b50404a982729316efafc7dfe66d34e5a182600d5f30a0a8512051c560d081d4d0a1835ec3d25a60f4e4d6aa948b2bf3dbb5b124cbbc3489255a3a948372f6978496745f943e1db4f18382ceaa505dfc65757bb3f857a58dce52156",

        "a88e265855e9d7ca36c68795f0b31b591cd6587c71d060a0b3f7f3eaef43795922028bc2b6ad467cfc2d7f659c5385aa70ba3672cdde4cfe4970cc7904601b278872bf51321c4a972f3c95570f3445d4f57980e0f20df54846e6a52c668f1288c03f95006ea32f562d40d52af9feb32f0fa06db65b588a237b34e592d55cf979f903a642ef64d2ed542aa8c77dc1dd762f45a59303ed75e541ca271e2b60ca709e44fa0661131e8d5d4163fd8d398566ce26de8730e72f9cca737641c244159420637028df0a18079d6208ea8b4711a2c750f5",
        "c0a425313df8d7564bd2434d311523d5257eed80",
        "586107226c3ce013a7c8f04d1a6a2959bb4b8e205ba43a27b50f124111bc35ef589b039f5932187cb696d7d9a32c0c38300a5cdda4834b62d2eb240af33f79d13dfbf095bf599e0d9686948c1964747b67e89c9aba5cd85016236f566cc5802cb13ead51bc7ca6bef3b94dcbdbb1d570469771df0e00b1a8a06777472d2316279edae86474668d4e1efff95f1de61c6020da32ae92bbf16520fef3cf4d88f61121f24bbd9fe91b59caf1235b2a93ff81fc403addf4ebdea84934a9cdaf8e1a9e",

        "c8c9c6af04acda414d227ef23e0820c3732c500dc87275e95b0d095413993c2658bc1d988581ba879c2d201f14cb88ced153a01969a7bf0a7be79c84c1486bc12b3fa6c59871b6827c8ce253ca5fefa8a8c690bf326e8e37cdb96d90a82ebab69f86350e1822e8bd536a2e",
        "b307c43b4850a8dac2f15f32e37839ef8c5c0e91",
        "80b6d643255209f0a456763897ac9ed259d459b49c2887e5882ecb4434cfd66dd7e1699375381e51cd7f554f2c271704b399d42b4be2540a0eca61951f55267f7c2878c122842dadb28b01bd5f8c025f7e228418a673c03d6bc0c736d0a29546bd67f786d9d692ccea778d71d98c2063b7a71092187a4d35af108111d83e83eae46c46aa34277e06044589903788f1d5e7cee25fb485e92949118814d6f2c3ee361489016f327fb5bc517eb50470bffa1afa5f4ce9aa0ce5b8ee19bf5501b958",

        "0afad42ccd4fc60654a55002d228f52a4a5fe03b8bbb08ca82daca558b44dbe1266e50c0e745a36d9d2904e3408abcd1fd569994063f4a75cc72f2fee2a0cd893a43af1c5b8b487df0a71610024e4f6ddf9f28ad0813c1aab91bcb3c9064d5ff742deffea657094139369e5ea6f4a96319a5cc8224145b545062758fefd1fe3409ae169259c6cdfd6b5f2958e314faecbe69d2cace58ee55179ab9b3e6d1ecc14a557c5febe988595264fc5da1c571462eca798a18a1a4940cdab4a3e92009ccd42e1e947b1314e32238a2dece7d23a89b5b30c751fd0a4a430d2c548594",
        "9a2b007e80978bbb192c354eb7da9aedfc74dbf5",
        "484408f3898cd5f53483f80819efbf2708c34d27a8b2a6fae8b322f9240237f981817aca1846f1084daa6d7c0795f6e5bf1af59c38e1858437ce1f7ec419b98c8736adf6dd9a00b1806d2bd3ad0a73775e05f52dfef3a59ab4b08143f0df05cd1ad9d04bececa6daa4a2129803e200cbc77787caf4c1d0663a6c5987b605952019782caf2ec1426d68fb94ed1d4be816a7ed081b77e6ab330b3ffc073820fecde3727fcbe295ee61a050a343658637c3fd659cfb63736de32d9f90d3c2f63eca",

        "1dfd43b46c93db82629bdae2bd0a12b882ea04c3b465f5cf93023f01059626dbbe99f26bb1be949dddd16dc7f3debb19a194627f0b224434df7d8700e9e98b06e360c12fdbe3d19f51c9684eb9089ecbb0a2f0450399d3f59eac7294085d044f5393c6ce737423d8b86c415370d389e30b9f0a3c02d25d0082e8ad6f3f1ef24a45c3cf82b383367063a4d4613e4264f01b2dac2e5aa42043f8fb5f69fa871d14fb273e767a531c40f02f343bc2fb45a0c7e0f6be2561923a77211d66a6e2dbb43c366350beae22da3ac2c1f5077096fcb5c4bf255f7574351ae0b1e1f03632817c0856d4a8ba97afbdc8b85855402bc56926fcec209f9ea8",
        "70f382bddf4d5d2dd88b3bc7b7308be632b84045",
        "84ebeb481be59845b46468bafb471c0112e02b235d84b5d911cbd1926ee5074ae0424495cb20e82308b8ebb65f419a03fb40e72b78981d88aad143053685172c97b29c8b7bf0ae73b5b2263c403da0ed2f80ff7450af7828eb8b86f0028bd2a8b176a4d228cccea18394f238b09ff758cc00bc04301152355742f282b54e663a919e709d8da24ade5500a7b9aa50226e0ca52923e6c2d860ec50ff480fa57477e82b0565f4379f79c772d5c2da80af9fbf325ece6fc20b00961614bee89a183e",

        "1bdc6e7c98fb8cf54e9b097b66a831e9cfe52d9d4888448ee4b0978093ba1d7d73ae78b3a62ba4ad95cd289ccb9e005226bb3d178bccaa821fb044a4e21ee97696c14d0678c94c2dae93b0ad73922218553daa7e44ebe57725a7a45cc72b9b2138a6b17c8db411ce8279ee1241aff0a8bec6f77f87edb0c69cb27236e3435a800b192e4f11e519e3fe30fc30eaccca4fbb41769029bf708e817a9e683805be67fa100984683b74838e3bcffa79366eed1d481c76729118838f31ba8a048a93c1be4424598e8df6328b7a77880a3f9c7e2e8dfca8eb5a26fb86bdc556d42bbe01d9fa6ed80646491c9341",
        "d689257a86effa68212c5e0c619eca295fb91b67",
        "82102df8cb91e7179919a04d26d335d64fbc2f872c44833943241de8454810274cdf3db5f42d423db152af7135f701420e39b494a67cbfd19f9119da233a23da5c6439b5ba0d2bc373eee3507001378d4a4073856b7fe2aba0b5ee93b27f4afec7d4d120921c83f606765b02c19e4d6a1a3b95fa4c422951be4f52131077ef17179729cddfbdb56950dbaceefe78cb16640a099ea56d24389eef10f8fecb31ba3ea3b227c0a86698bb89e3e9363905bf22777b2a3aa521b65b4cef76d83bde4c",

        "88c7a9f1360401d90e53b101b61c5325c3c75db1b411fbeb8e830b75e96b56670ad245404e16793544ee354bc613a90cc9848715a73db5893e7f6d279815c0c1de83ef8e2956e3a56ed26a888d7a9cdcd042f4b16b7fa51ef1a0573662d16a302d0ec5b285d2e03ad96529c87b3d374db372d95b2443d061b6b1a350ba87807ed083afd1eb05c3f52f4eba5ed2227714fdb50b9d9d9dd6814f62f6272fcd5cdbce7a9ef797",
        "c25f13bf67d081671a0481a1f1820d613bba2276",
        "a7fdb0d259165ca2c88d00bbf1028a867d337699d061193b17a9648e14ccbbaadeacaacdec815e7571294ebb8a117af205fa078b47b0712c199e3ad05135c504c24b81705115740802487992ffd511d4afc6b854491eb3f0dd523139542ff15c3101ee85543517c6a3c79417c67e2dd9aa741e9a29b06dcb593c2336b3670ae3afbac7c3e76e215473e866e338ca244de00b62624d6b9426822ceae9f8cc460895f41250073fd45c5a1e7b425c204a423a699159f6903e710b37a7bb2bc8049f",

        /* 2048-bit key */
        "a5dd867ac4cb02f90b9457d48c14a770ef991c56c39c0ec65fd11afa8937cea57b9be7ac73b45c0017615b82d622e318753b6027c0fd157be12f8090fee2a7adcd0eef759f88ba4997c7a42d58c9aa12cb99ae001fe521c13bb5431445a8d5ae4f5e4c7e948ac227d3604071f20e577e905fbeb15dfaf06d1de5ae6253d63a6a2120b31a5da5dabc9550600e20f27d3739e2627925fea3cc509f21dff04e6eea4549c540d6809ff9307eede91fff58733d8385a237d6d3705a33e391900992070df7adf1357cf7e3700ce3667de83f17b8df1778db381dce09cb4ad058a511001a738198ee27cf55a13b754539906582ec8b174bd58d5d1f3d767c613721ae05",
        "010001",
        "2d2ff567b3fe74e06191b7fded6de112290c670692430d5969184047da234c9693deed1673ed429539c969d372c04d6b47e0f5b8cee0843e5c22835dbd3b05a0997984ae6058b11bc4907cbf67ed84fa9ae252dfb0d0cd49e618e35dfdfe59bca3ddd66c33cebbc77ad441aa695e13e324b518f01c60f5a85c994ad179f2a6b5fbe93402b11767be01bf073444d6ba1dd2bca5bd074d4a5fae3531ad1303d84b30d897318cbbba04e03c2e66de6d91f82f96ea1d4bb54a5aae102d594657f5c9789553512b296dea29d8023196357e3e3a6e958f39e3c2344038ea604b31edc6f0f7ff6e7181a57c92826a268f86768e96f878562fc71d85d69e448612f7048f",
        "cfd50283feeeb97f6f08d73cbc7b3836f82bbcd499479f5e6f76fdfcb8b38c4f71dc9e88bd6a6f76371afd65d2af1862b32afb34a95f71b8b132043ffebe3a952baf7592448148c03f9c69b1d68e4ce5cf32c86baf46fed301ca1ab403069b32f456b91f71898ab081cd8c4252ef5271915c9794b8f295851da7510f99cb73eb",
        "cc4e90d2a1b3a065d3b2d1f5a8fce31b544475664eab561d2971b99fb7bef844e8ec1f360b8c2ac8359692971ea6a38f723fcc211f5dbcb177a0fdac5164a1d4ff7fbb4e829986353cb983659a148cdd420c7d31ba3822ea90a32be46c030e8c17e1fa0ad37859e06b0aa6fa3b216d9cbe6c0e22339769c0a615913e5da719cf",
        "1c2d1fc32f6bc4004fd85dfde0fbbf9a4c38f9c7c4e41dea1aa88234a201cd92f3b7da526583a98ad85bb360fb983b711e23449d561d1778d7a515486bcbf47b46c9e9e1a3a1f77000efbeb09a8afe47e5b857cda99cb16d7fff9b712e3bd60ca96d9c7973d616d46934a9c050281c004399ceff1db7dda78766a8a9b9cb0873",
        "cb3b3c04caa58c60be7d9b2debb3e39643f4f57397be08236a1e9eafaa706536e71c3acfe01cc651f23c9e05858fee13bb6a8afc47df4edc9a4ba30bcecb73d0157852327ee789015c2e8dee7b9f05a0f31ac94eb6173164740c5c95147cd5f3b5ae2cb4a83787f01d8ab31f27c2d0eea2dd8a11ab906aba207c43c6ee125331",
        "12f6b2cf1374a736fad05616050f96ab4b61d1177c7f9d525a29f3d180e77667e99d99abf0525d0758660f3752655b0f25b8df8431d9a8ff77c16c12a0a5122a9f0bf7cfd5a266a35c159f991208b90316ff444f3e0b6bd0e93b8a7a2448e957e3dda6cfcf2266b106013ac46808d3b3887b3b00344baac9530b4ce708fc32b6",

        "883177e5126b9be2d9a9680327d5370c6f26861f5820c43da67a3ad609",
        "04e215ee6ff934b9da70d7730c8734abfcecde89",
        "82c2b160093b8aa3c0f7522b19f87354066c77847abf2a9fce542d0e84e920c5afb49ffdfdace16560ee94a1369601148ebad7a0e151cf16331791a5727d05f21e74e7eb811440206935d744765a15e79f015cb66c532c87a6a05961c8bfad741a9a6657022894393e7223739796c02a77455d0f555b0ec01ddf259b6207fd0fd57614cef1a5573baaff4ec00069951659b85f24300a25160ca8522dc6e6727e57d019d7e63629b8fe5e89e25cc15beb3a647577559299280b9b28f79b0409000be25bbd96408ba3b43cc486184dd1c8e62553fa1af4040f60663de7f5e49c04388e257f1ce89c95dab48a315d9b66b1b7628233876ff2385230d070d07e1666",

        "dd670a01465868adc93f26131957a50c52fb777cdbaa30892c9e12361164ec13979d43048118e4445db87bee58dd987b3425d02071d8dbae80708b039dbb64dbd1de5657d9fed0c118a54143742e0ff3c87f74e45857647af3f79eb0a14c9d75ea9a1a04b7cf478a897a708fd988f48e801edb0b7039df8c23bb3c56f4e821ac",
        "8b2bdd4b40faf545c778ddf9bc1a49cb57f9b71b",
        "14ae35d9dd06ba92f7f3b897978aed7cd4bf5ff0b585a40bd46ce1b42cd2703053bb9044d64e813d8f96db2dd7007d10118f6f8f8496097ad75e1ff692341b2892ad55a633a1c55e7f0a0ad59a0e203a5b8278aec54dd8622e2831d87174f8caff43ee6c46445345d84a59659bfb92ecd4c818668695f34706f66828a89959637f2bf3e3251c24bdba4d4b7649da0022218b119c84e79a6527ec5b8a5f861c159952e23ec05e1e717346faefe8b1686825bd2b262fb2531066c0de09acde2e4231690728b5d85e115a2f6b92b79c25abc9bd9399ff8bcf825a52ea1f56ea76dd26f43baafa18bfa92a504cbd35699e26d1dcc5a2887385f3c63232f06f3244c3",

        "48b2b6a57a63c84cea859d65c668284b08d96bdcaabe252db0e4a96cb1bac6019341db6fbefb8d106b0e90eda6bcc6c6262f37e7ea9c7e5d226bd7df85ec5e71efff2f54c5db577ff729ff91b842491de2741d0c631607df586b905b23b91af13da12304bf83eca8a73e871ff9db",
        "4e96fc1b398f92b44671010c0dc3efd6e20c2d73",
        "6e3e4d7b6b15d2fb46013b8900aa5bbb3939cf2c095717987042026ee62c74c54cffd5d7d57efbbf950a0f5c574fa09d3fc1c9f513b05b4ff50dd8df7edfa20102854c35e592180119a70ce5b085182aa02d9ea2aa90d1df03f2daae885ba2f5d05afdac97476f06b93b5bc94a1a80aa9116c4d615f333b098892b25fface266f5db5a5a3bcc10a824ed55aad35b727834fb8c07da28fcf416a5d9b2224f1f8b442b36f91e456fdea2d7cfe3367268de0307a4c74e924159ed33393d5e0655531c77327b89821bdedf880161c78cd4196b5419f7acc3f13e5ebf161b6e7c6724716ca33b85c2e25640192ac2859651d50bde7eb976e51cec828b98b6563b86bb",

        "0b8777c7f839baf0a64bbbdbc5ce79755c57a205b845c174e2d2e90546a089c4e6ec8adffa23a7ea97bae6b65d782b82db5d2b5a56d22a29a05e7c4433e2b82a621abba90add05ce393fc48a840542451a",
        "c7cd698d84b65128d8835e3a8b1eb0e01cb541ec",
        "34047ff96c4dc0dc90b2d4ff59a1a361a4754b255d2ee0af7d8bf87c9bc9e7ddeede33934c63ca1c0e3d262cb145ef932a1f2c0a997aa6a34f8eaee7477d82ccf09095a6b8acad38d4eec9fb7eab7ad02da1d11d8e54c1825e55bf58c2a23234b902be124f9e9038a8f68fa45dab72f66e0945bf1d8bacc9044c6f07098c9fcec58a3aab100c805178155f030a124c450e5acbda47d0e4f10b80a23f803e774d023b0015c20b9f9bbe7c91296338d5ecb471cafb032007b67a60be5f69504a9f01abb3cb467b260e2bce860be8d95bf92c0c8e1496ed1e528593a4abb6df462dde8a0968dffe4683116857a232f5ebf6c85be238745ad0f38f767a5fdbf486fb",

        "f1036e008e71e964dadc9219ed30e17f06b4b68a955c16b312b1eddf028b74976bed6b3f6a63d4e77859243c9cccdc98016523abb02483b35591c33aad81213bb7c7bb1a470aabc10d44256c4d4559d916",
        "efa8bff96212b2f4a3f371a10d574152655f5dfb",
        "7e0935ea18f4d6c1d17ce82eb2b3836c55b384589ce19dfe743363ac9948d1f346b7bfddfe92efd78adb21faefc89ade42b10f374003fe122e67429a1cb8cbd1f8d9014564c44d120116f4990f1a6e38774c194bd1b8213286b077b0499d2e7b3f434ab12289c556684deed78131934bb3dd6537236f7c6f3dcb09d476be07721e37e1ceed9b2f7b406887bd53157305e1c8b4f84d733bc1e186fe06cc59b6edb8f4bd7ffefdf4f7ba9cfb9d570689b5a1a4109a746a690893db3799255a0cb9215d2d1cd490590e952e8c8786aa0011265252470c041dfbc3eec7c3cbf71c24869d115c0cb4a956f56d530b80ab589acfefc690751ddf36e8d383f83cedd2cc",

        "25f10895a87716c137450bb9519dfaa1f207faa942ea88abf71e9c17980085b555aebab76264ae2a3ab93c2d12981191ddac6fb5949eb36aee3c5da940f00752c916d94608fa7d97ba6a2915b688f20323d4e9d96801d89a72ab5892dc2117c07434fcf972e058cf8c41ca4b4ff554f7d5068ad3155fced0f3125bc04f9193378a8f5c4c3b8cb4dd6d1cc69d30ecca6eaa51e36a05730e9e342e855baf099defb8afd7",
        "ad8b1523703646224b660b550885917ca2d1df28",
        "6d3b5b87f67ea657af21f75441977d2180f91b2c5f692de82955696a686730d9b9778d970758ccb26071c2209ffbd6125be2e96ea81b67cb9b9308239fda17f7b2b64ecda096b6b935640a5a1cb42a9155b1c9ef7a633a02c59f0d6ee59b852c43b35029e73c940ff0410e8f114eed46bbd0fae165e42be2528a401c3b28fd818ef3232dca9f4d2a0f5166ec59c42396d6c11dbc1215a56fa17169db9575343ef34f9de32a49cdc3174922f229c23e18e45df9353119ec4319cedce7a17c64088c1f6f52be29634100b3919d38f3d1ed94e6891e66a73b8fb849f5874df59459e298c7bbce2eee782a195aa66fe2d0732b25e595f57d3e061b1fc3e4063bf98f",

        NULL
};

/*
 * Test vectors from pkcs-1v2-1d2-vec.zip (originally from ftp.rsa.com).
 * There are ten RSA keys, and for each RSA key, there are 6 messages,
 * each with an explicit seed.
 *
 * Field order:
 *    modulus (n)
 *    public exponent (e)
 *    first factor (p)
 *    second factor (q)
 *    first private exponent (dp)
 *    second private exponent (dq)
 *    CRT coefficient (iq)
 *    cleartext 1
 *    seed 1 (20-byte random value)
 *    ciphertext 1
 *    cleartext 2
 *    seed 2 (20-byte random value)
 *    ciphertext 2
 *    ...
 *    cleartext 6
 *    seed 6 (20-byte random value)
 *    ciphertext 6
 *
 * This pattern is repeated for all keys. The array stops on a NULL.
 */
static const char *KAT_RSA_OAEP[] = {
        /* 1024-bit key, from oeap-int.txt */
        "BBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51FB8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807FAFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394EE0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB",
        "11",
        "EECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599",
        "C97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D869840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503",
        "54494CA63EBA0337E4E24023FCD69A5AEB07DDDC0183A4D0AC9B54B051F2B13ED9490975EAB77414FF59C1F7692E9A2E202B38FC910A474174ADC93C1F67C981",
        "471E0290FF0AF0750351B7F878864CA961ADBD3A8A7E991C5C0556A94C3146A7F9803F8F6F8AE342E931FD8AE47A220D1B99A495849807FE39F9245A9836DA3D",
        "B06C4FDABB6301198D265BDBAE9423B380F271F73453885093077FCD39E2119FC98632154F5883B167A967BF402B4E9E2E0F9656E698EA3666EDFB25798039F7",

        /* oaep-int.txt contains only one message, so we repeat it six
	   times to respect our array format. */
        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        "D436E99569FD32A7C8A05BBC90D32C49",
        "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
        "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

        /* 1024-bit key */
        "A8B3B284AF8EB50B387034A860F146C4919F318763CD6C5598C8AE4811A1E0ABC4C7E0B082D693A5E7FCED675CF4668512772C0CBC64A742C6C630F533C8CC72F62AE833C40BF25842E984BB78BDBF97C0107D55BDB662F5C4E0FAB9845CB5148EF7392DD3AAFF93AE1E6B667BB3D4247616D4F5BA10D4CFD226DE88D39F16FB",
        "010001",
        "D32737E7267FFE1341B2D5C0D150A81B586FB3132BED2F8D5262864A9CB9F30AF38BE448598D413A172EFB802C21ACF1C11C520C2F26A471DCAD212EAC7CA39D",
        "CC8853D1D54DA630FAC004F471F281C7B8982D8224A490EDBEB33D3E3D5CC93C4765703D1DD791642F1F116A0DD852BE2419B2AF72BFE9A030E860B0288B5D77",
        "0E12BF1718E9CEF5599BA1C3882FE8046A90874EEFCE8F2CCC20E4F2741FB0A33A3848AEC9C9305FBECBD2D76819967D4671ACC6431E4037968DB37878E695C1",
        "95297B0F95A2FA67D00707D609DFD4FC05C89DAFC2EF6D6EA55BEC771EA333734D9251E79082ECDA866EFEF13C459E1A631386B7E354C899F5F112CA85D71583",
        "4F456C502493BDC0ED2AB756A3A6ED4D67352A697D4216E93212B127A63D5411CE6FA98D5DBEFD73263E3728142743818166ED7DD63687DD2A8CA1D2F4FBD8E1",

        "6628194E12073DB03BA94CDA9EF9532397D50DBA79B987004AFEFE34",
        "18B776EA21069D69776A33E96BAD48E1DDA0A5EF",
        "354FE67B4A126D5D35FE36C777791A3F7BA13DEF484E2D3908AFF722FAD468FB21696DE95D0BE911C2D3174F8AFCC201035F7B6D8E69402DE5451618C21A535FA9D7BFC5B8DD9FC243F8CF927DB31322D6E881EAA91A996170E657A05A266426D98C88003F8477C1227094A0D9FA1E8C4024309CE1ECCCB5210035D47AC72E8A",

        "750C4047F547E8E41411856523298AC9BAE245EFAF1397FBE56F9DD5",
        "0CC742CE4A9B7F32F951BCB251EFD925FE4FE35F",
        "640DB1ACC58E0568FE5407E5F9B701DFF8C3C91E716C536FC7FCEC6CB5B71C1165988D4A279E1577D730FC7A29932E3F00C81515236D8D8E31017A7A09DF4352D904CDEB79AA583ADCC31EA698A4C05283DABA9089BE5491F67C1A4EE48DC74BBBE6643AEF846679B4CB395A352D5ED115912DF696FFE0702932946D71492B44",

        "D94AE0832E6445CE42331CB06D531A82B1DB4BAAD30F746DC916DF24D4E3C2451FFF59A6423EB0E1D02D4FE646CF699DFD818C6E97B051",
        "2514DF4695755A67B288EAF4905C36EEC66FD2FD",
        "423736ED035F6026AF276C35C0B3741B365E5F76CA091B4E8C29E2F0BEFEE603595AA8322D602D2E625E95EB81B2F1C9724E822ECA76DB8618CF09C5343503A4360835B5903BC637E3879FB05E0EF32685D5AEC5067CD7CC96FE4B2670B6EAC3066B1FCF5686B68589AAFB7D629B02D8F8625CA3833624D4800FB081B1CF94EB",

        "52E650D98E7F2A048B4F86852153B97E01DD316F346A19F67A85",
        "C4435A3E1A18A68B6820436290A37CEFB85DB3FB",
        "45EAD4CA551E662C9800F1ACA8283B0525E6ABAE30BE4B4ABA762FA40FD3D38E22ABEFC69794F6EBBBC05DDBB11216247D2F412FD0FBA87C6E3ACD888813646FD0E48E785204F9C3F73D6D8239562722DDDD8771FEC48B83A31EE6F592C4CFD4BC88174F3B13A112AAE3B9F7B80E0FC6F7255BA880DC7D8021E22AD6A85F0755",

        "8DA89FD9E5F974A29FEFFB462B49180F6CF9E802",
        "B318C42DF3BE0F83FEA823F5A7B47ED5E425A3B5",
        "36F6E34D94A8D34DAACBA33A2139D00AD85A9345A86051E73071620056B920E219005855A213A0F23897CDCD731B45257C777FE908202BEFDD0B58386B1244EA0CF539A05D5D10329DA44E13030FD760DCD644CFEF2094D1910D3F433E1C7C6DD18BC1F2DF7F643D662FB9DD37EAD9059190F4FA66CA39E869C4EB449CBDC439",

        "26521050844271",
        "E4EC0982C2336F3A677F6A356174EB0CE887ABC2",
        "42CEE2617B1ECEA4DB3F4829386FBD61DAFBF038E180D837C96366DF24C097B4AB0FAC6BDF590D821C9F10642E681AD05B8D78B378C0F46CE2FAD63F74E0AD3DF06B075D7EB5F5636F8D403B9059CA761B5C62BB52AA45002EA70BAACE08DED243B9D8CBD62A68ADE265832B56564E43A6FA42ED199A099769742DF1539E8255",

        /* 1025-bit key */
        "01947C7FCE90425F47279E70851F25D5E62316FE8A1DF19371E3E628E260543E4901EF6081F68C0B8141190D2AE8DABA7D1250EC6DB636E944EC3722877C7C1D0A67F14B1694C5F0379451A43E49A32DDE83670B73DA91A1C99BC23B436A60055C610F0BAF99C1A079565B95A3F1526632D1D4DA60F20EDA25E653C4F002766F45",
        "010001",
        "0159DBDE04A33EF06FB608B80B190F4D3E22BCC13AC8E4A081033ABFA416EDB0B338AA08B57309EA5A5240E7DC6E54378C69414C31D97DDB1F406DB3769CC41A43",
        "012B652F30403B38B40995FD6FF41A1ACC8ADA70373236B7202D39B2EE30CFB46DB09511F6F307CC61CC21606C18A75B8A62F822DF031BA0DF0DAFD5506F568BD7",
        "436EF508DE736519C2DA4C580D98C82CB7452A3FB5EFADC3B9C7789A1BC6584F795ADDBBD32439C74686552ECB6C2C307A4D3AF7F539EEC157248C7B31F1A255",
        "012B15A89F3DFB2B39073E73F02BDD0C1A7B379DD435F05CDDE2EFF9E462948B7CEC62EE9050D5E0816E0785A856B49108DCB75F3683874D1CA6329A19013066FF",
        "0270DB17D5914B018D76118B24389A7350EC836B0063A21721236FD8EDB6D89B51E7EEB87B611B7132CB7EA7356C23151C1E7751507C786D9EE1794170A8C8E8",

        "8FF00CAA605C702830634D9A6C3D42C652B58CF1D92FEC570BEEE7",
        "8C407B5EC2899E5099C53E8CE793BF94E71B1782",
        "0181AF8922B9FCB4D79D92EBE19815992FC0C1439D8BCD491398A0F4AD3A329A5BD9385560DB532683C8B7DA04E4B12AED6AACDF471C34C9CDA891ADDCC2DF3456653AA6382E9AE59B54455257EB099D562BBE10453F2B6D13C59C02E10F1F8ABB5DA0D0570932DACF2D0901DB729D0FEFCC054E70968EA540C81B04BCAEFE720E",

        "2D",
        "B600CF3C2E506D7F16778C910D3A8B003EEE61D5",
        "018759FF1DF63B2792410562314416A8AEAF2AC634B46F940AB82D64DBF165EEE33011DA749D4BAB6E2FCD18129C9E49277D8453112B429A222A8471B070993998E758861C4D3F6D749D91C4290D332C7A4AB3F7EA35FF3A07D497C955FF0FFC95006B62C6D296810D9BFAB024196C7934012C2DF978EF299ABA239940CBA10245",

        "74FC88C51BC90F77AF9D5E9A4A70133D4B4E0B34DA3C37C7EF8E",
        "A73768AEEAA91F9D8C1ED6F9D2B63467F07CCAE3",
        "018802BAB04C60325E81C4962311F2BE7C2ADCE93041A00719C88F957575F2C79F1B7BC8CED115C706B311C08A2D986CA3B6A9336B147C29C6F229409DDEC651BD1FDD5A0B7F610C9937FDB4A3A762364B8B3206B4EA485FD098D08F63D4AA8BB2697D027B750C32D7F74EAF5180D2E9B66B17CB2FA55523BC280DA10D14BE2053",

        "A7EB2A5036931D27D4E891326D99692FFADDA9BF7EFD3E34E622C4ADC085F721DFE885072C78A203B151739BE540FA8C153A10F00A",
        "9A7B3B0E708BD96F8190ECAB4FB9B2B3805A8156",
        "00A4578CBC176318A638FBA7D01DF15746AF44D4F6CD96D7E7C495CBF425B09C649D32BF886DA48FBAF989A2117187CAFB1FB580317690E3CCD446920B7AF82B31DB5804D87D01514ACBFA9156E782F867F6BED9449E0E9A2C09BCECC6AA087636965E34B3EC766F2FE2E43018A2FDDEB140616A0E9D82E5331024EE0652FC7641",

        "2EF2B066F854C33F3BDCBB5994A435E73D6C6C",
        "EB3CEBBC4ADC16BB48E88C8AEC0E34AF7F427FD3",
        "00EBC5F5FDA77CFDAD3C83641A9025E77D72D8A6FB33A810F5950F8D74C73E8D931E8634D86AB1246256AE07B6005B71B7F2FB98351218331CE69B8FFBDC9DA08BBC9C704F876DEB9DF9FC2EC065CAD87F9090B07ACC17AA7F997B27ACA48806E897F771D95141FE4526D8A5301B678627EFAB707FD40FBEBD6E792A25613E7AEC",

        "8A7FB344C8B6CB2CF2EF1F643F9A3218F6E19BBA89C0",
        "4C45CF4D57C98E3D6D2095ADC51C489EB50DFF84",
        "010839EC20C27B9052E55BEFB9B77E6FC26E9075D7A54378C646ABDF51E445BD5715DE81789F56F1803D9170764A9E93CB78798694023EE7393CE04BC5D8F8C5A52C171D43837E3ACA62F609EB0AA5FFB0960EF04198DD754F57F7FBE6ABF765CF118B4CA443B23B5AAB266F952326AC4581100644325F8B721ACD5D04FF14EF3A",

        /* 2048-bit key */
        "AE45ED5601CEC6B8CC05F803935C674DDBE0D75C4C09FD7951FC6B0CAEC313A8DF39970C518BFFBA5ED68F3F0D7F22A4029D413F1AE07E4EBE9E4177CE23E7F5404B569E4EE1BDCF3C1FB03EF113802D4F855EB9B5134B5A7C8085ADCAE6FA2FA1417EC3763BE171B0C62B760EDE23C12AD92B980884C641F5A8FAC26BDAD4A03381A22FE1B754885094C82506D4019A535A286AFEB271BB9BA592DE18DCF600C2AEEAE56E02F7CF79FC14CF3BDC7CD84FEBBBF950CA90304B2219A7AA063AEFA2C3C1980E560CD64AFE779585B6107657B957857EFDE6010988AB7DE417FC88D8F384C4E6E72C3F943E0C31C0C4A5CC36F879D8A3AC9D7D59860EAADA6B83BB",
        "010001",
        "ECF5AECD1E5515FFFACBD75A2816C6EBF49018CDFB4638E185D66A7396B6F8090F8018C7FD95CC34B857DC17F0CC6516BB1346AB4D582CADAD7B4103352387B70338D084047C9D9539B6496204B3DD6EA442499207BEC01F964287FF6336C3984658336846F56E46861881C10233D2176BF15A5E96DDC780BC868AA77D3CE769",
        "BC46C464FC6AC4CA783B0EB08A3C841B772F7E9B2F28BABD588AE885E1A0C61E4858A0FB25AC299990F35BE85164C259BA1175CDD7192707135184992B6C29B746DD0D2CABE142835F7D148CC161524B4A09946D48B828473F1CE76B6CB6886C345C03E05F41D51B5C3A90A3F24073C7D74A4FE25D9CF21C75960F3FC3863183",
        "C73564571D00FB15D08A3DE9957A50915D7126E9442DACF42BC82E862E5673FF6A008ED4D2E374617DF89F17A160B43B7FDA9CB6B6B74218609815F7D45CA263C159AA32D272D127FAF4BC8CA2D77378E8AEB19B0AD7DA3CB3DE0AE7314980F62B6D4B0A875D1DF03C1BAE39CCD833EF6CD7E2D9528BF084D1F969E794E9F6C1",
        "2658B37F6DF9C1030BE1DB68117FA9D87E39EA2B693B7E6D3A2F70947413EEC6142E18FB8DFCB6AC545D7C86A0AD48F8457170F0EFB26BC48126C53EFD1D16920198DC2A1107DC282DB6A80CD3062360BA3FA13F70E4312FF1A6CD6B8FC4CD9C5C3DB17C6D6A57212F73AE29F619327BAD59B153858585BA4E28B60A62A45E49",
        "6F38526B3925085534EF3E415A836EDE8B86158A2C7CBFECCB0BD834304FEC683BA8D4F479C433D43416E63269623CEA100776D85AFF401D3FFF610EE65411CE3B1363D63A9709EEDE42647CEA561493D54570A879C18682CD97710B96205EC31117D73B5F36223FADD6E8BA90DD7C0EE61D44E163251E20C7F66EB305117CB8",

        "8BBA6BF82A6C0F86D5F1756E97956870B08953B06B4EB205BC1694EE",
        "47E1AB7119FEE56C95EE5EAAD86F40D0AA63BD33",
        "53EA5DC08CD260FB3B858567287FA91552C30B2FEBFBA213F0AE87702D068D19BAB07FE574523DFB42139D68C3C5AFEEE0BFE4CB7969CBF382B804D6E61396144E2D0E60741F8993C3014B58B9B1957A8BABCD23AF854F4C356FB1662AA72BFCC7E586559DC4280D160C126785A723EBEEBEFF71F11594440AAEF87D10793A8774A239D4A04C87FE1467B9DAF85208EC6C7255794A96CC29142F9A8BD418E3C1FD67344B0CD0829DF3B2BEC60253196293C6B34D3F75D32F213DD45C6273D505ADF4CCED1057CB758FC26AEEFA441255ED4E64C199EE075E7F16646182FDB464739B68AB5DAFF0E63E9552016824F054BF4D3C8C90A97BB6B6553284EB429FCC",

        "E6AD181F053B58A904F2457510373E57",
        "6D17F5B4C1FFAC351D195BF7B09D09F09A4079CF",
        "A2B1A430A9D657E2FA1C2BB5ED43FFB25C05A308FE9093C01031795F5874400110828AE58FB9B581CE9DDDD3E549AE04A0985459BDE6C626594E7B05DC4278B2A1465C1368408823C85E96DC66C3A30983C639664FC4569A37FE21E5A195B5776EED2DF8D8D361AF686E750229BBD663F161868A50615E0C337BEC0CA35FEC0BB19C36EB2E0BBCC0582FA1D93AACDB061063F59F2CE1EE43605E5D89ECA183D2ACDFE9F81011022AD3B43A3DD417DAC94B4E11EA81B192966E966B182082E71964607B4F8002F36299844A11F2AE0FAEAC2EAE70F8F4F98088ACDCD0AC556E9FCCC511521908FAD26F04C64201450305778758B0538BF8B5BB144A828E629795",

        "510A2CF60E866FA2340553C94EA39FBC256311E83E94454B4124",
        "385387514DECCC7C740DD8CDF9DAEE49A1CBFD54",
        "9886C3E6764A8B9A84E84148EBD8C3B1AA8050381A78F668714C16D9CFD2A6EDC56979C535D9DEE3B44B85C18BE8928992371711472216D95DDA98D2EE8347C9B14DFFDFF84AA48D25AC06F7D7E65398AC967B1CE90925F67DCE049B7F812DB0742997A74D44FE81DBE0E7A3FEAF2E5C40AF888D550DDBBE3BC20657A29543F8FC2913B9BD1A61B2AB2256EC409BBD7DC0D17717EA25C43F42ED27DF8738BF4AFC6766FF7AFF0859555EE283920F4C8A63C4A7340CBAFDDC339ECDB4B0515002F96C932B5B79167AF699C0AD3FCCFDF0F44E85A70262BF2E18FE34B850589975E867FF969D48EABF212271546CDC05A69ECB526E52870C836F307BD798780EDE",

        "BCDD190DA3B7D300DF9A06E22CAAE2A75F10C91FF667B7C16BDE8B53064A2649A94045C9",
        "5CACA6A0F764161A9684F85D92B6E0EF37CA8B65",
        "6318E9FB5C0D05E5307E1683436E903293AC4642358AAA223D7163013ABA87E2DFDA8E60C6860E29A1E92686163EA0B9175F329CA3B131A1EDD3A77759A8B97BAD6A4F8F4396F28CF6F39CA58112E48160D6E203DAA5856F3ACA5FFED577AF499408E3DFD233E3E604DBE34A9C4C9082DE65527CAC6331D29DC80E0508A0FA7122E7F329F6CCA5CFA34D4D1DA417805457E008BEC549E478FF9E12A763C477D15BBB78F5B69BD57830FC2C4ED686D79BC72A95D85F88134C6B0AFE56A8CCFBC855828BB339BD17909CF1D70DE3335AE07039093E606D655365DE6550B872CD6DE1D440EE031B61945F629AD8A353B0D40939E96A3C450D2A8D5EEE9F678093C8",

        "A7DD6C7DC24B46F9DD5F1E91ADA4C3B3DF947E877232A9",
        "95BCA9E3859894B3DD869FA7ECD5BBC6401BF3E4",
        "75290872CCFD4A4505660D651F56DA6DAA09CA1301D890632F6A992F3D565CEE464AFDED40ED3B5BE9356714EA5AA7655F4A1366C2F17C728F6F2C5A5D1F8E28429BC4E6F8F2CFF8DA8DC0E0A9808E45FD09EA2FA40CB2B6CE6FFFF5C0E159D11B68D90A85F7B84E103B09E682666480C657505C0929259468A314786D74EAB131573CF234BF57DB7D9E66CC6748192E002DC0DEEA930585F0831FDCD9BC33D51F79ED2FFC16BCF4D59812FCEBCAA3F9069B0E445686D644C25CCF63B456EE5FA6FFE96F19CDF751FED9EAF35957754DBF4BFEA5216AA1844DC507CB2D080E722EBA150308C2B5FF1193620F1766ECF4481BAFB943BD292877F2136CA494ABA0",

        "EAF1A73A1B0C4609537DE69CD9228BBCFB9A8CA8C6C3EFAF056FE4A7F4634ED00B7C39EC6922D7B8EA2C04EBAC",
        "9F47DDF42E97EEA856A9BDBC714EB3AC22F6EB32",
        "2D207A73432A8FB4C03051B3F73B28A61764098DFA34C47A20995F8115AA6816679B557E82DBEE584908C6E69782D7DEB34DBD65AF063D57FCA76A5FD069492FD6068D9984D209350565A62E5C77F23038C12CB10C6634709B547C46F6B4A709BD85CA122D74465EF97762C29763E06DBC7A9E738C78BFCA0102DC5E79D65B973F28240CAAB2E161A78B57D262457ED8195D53E3C7AE9DA021883C6DB7C24AFDD2322EAC972AD3C354C5FCEF1E146C3A0290FB67ADF007066E00428D2CEC18CE58F9328698DEFEF4B2EB5EC76918FDE1C198CBB38B7AFC67626A9AEFEC4322BFD90D2563481C9A221F78C8272C82D1B62AB914E1C69F6AF6EF30CA5260DB4A46",

        NULL
};

static void
test_RSA_OAEP(const char *name,
              br_rsa_oaep_encrypt menc, br_rsa_oaep_decrypt mdec)
{
    size_t u;

    printf("Test %s: ", name);
    fflush(stdout);

    u = 0;
    while (KAT_RSA_OAEP[u] != NULL) {
        unsigned char n[512];
        unsigned char e[8];
        unsigned char p[256];
        unsigned char q[256];
        unsigned char dp[256];
        unsigned char dq[256];
        unsigned char iq[256];
        br_rsa_public_key pk;
        br_rsa_private_key sk;
        size_t v;

        pk.n = n;
        pk.nlen = hextobin(n, KAT_RSA_OAEP[u ++]);
        pk.e = e;
        pk.elen = hextobin(e, KAT_RSA_OAEP[u ++]);

        for (v = 0; n[v] == 0; v ++);
        sk.n_bitlen = BIT_LENGTH(n[v]) + ((pk.nlen - 1 - v) << 3);
        sk.p = p;
        sk.plen = hextobin(p, KAT_RSA_OAEP[u ++]);
        sk.q = q;
        sk.qlen = hextobin(q, KAT_RSA_OAEP[u ++]);
        sk.dp = dp;
        sk.dplen = hextobin(dp, KAT_RSA_OAEP[u ++]);
        sk.dq = dq;
        sk.dqlen = hextobin(dq, KAT_RSA_OAEP[u ++]);
        sk.iq = iq;
        sk.iqlen = hextobin(iq, KAT_RSA_OAEP[u ++]);

        for (v = 0; v < 6; v ++) {
            unsigned char plain[512], seed[128], cipher[512];
            size_t plain_len, seed_len, cipher_len;
            rng_fake_ctx rng;
            unsigned char tmp[513];
            size_t len;

            plain_len = hextobin(plain, KAT_RSA_OAEP[u ++]);
            seed_len = hextobin(seed, KAT_RSA_OAEP[u ++]);
            cipher_len = hextobin(cipher, KAT_RSA_OAEP[u ++]);
            rng_fake_init(&rng, NULL, seed, seed_len);

            len = menc(&rng.vtable, &br_sha1_vtable, NULL, 0, &pk,
                       tmp, sizeof tmp, plain, plain_len);
            if (len != cipher_len) {
                fprintf(stderr,
                        "wrong encrypted length: %lu vs %lu\n",
                        (unsigned long)len,
                        (unsigned long)cipher_len);
            }
            if (rng.ptr != rng.len) {
                fprintf(stderr, "seed not fully consumed\n");
                exit(EXIT_FAILURE);
            }
            check_equals("KAT RSA/OAEP encrypt", tmp, cipher, len);

            if (mdec(&br_sha1_vtable, NULL, 0,
                     &sk, tmp, &len) != 1)
            {
                fprintf(stderr, "decryption failed\n");
                exit(EXIT_FAILURE);
            }
            if (len != plain_len) {
                fprintf(stderr,
                        "wrong decrypted length: %lu vs %lu\n",
                        (unsigned long)len,
                        (unsigned long)plain_len);
            }
            check_equals("KAT RSA/OAEP decrypt", tmp, plain, len);

            /*
			 * Try with a different label; it should fail.
			 */
            memcpy(tmp, cipher, cipher_len);
            len = cipher_len;
            if (mdec(&br_sha1_vtable, "T", 1,
                     &sk, tmp, &len) != 0)
            {
                fprintf(stderr, "decryption should have failed"
                                " (wrong label)\n");
                exit(EXIT_FAILURE);
            }

            /*
			 * Try with a the wrong length; it should fail.
			 */
            tmp[0] = 0x00;
            memcpy(tmp + 1, cipher, cipher_len);
            len = cipher_len + 1;
            if (mdec(&br_sha1_vtable, "T", 1,
                     &sk, tmp, &len) != 0)
            {
                fprintf(stderr, "decryption should have failed"
                                " (wrong length)\n");
                exit(EXIT_FAILURE);
            }

            printf(".");
            fflush(stdout);
        }
    }

    printf(" done.\n");
    fflush(stdout);
}


static void
test_RSA_i15(void)
{
    test_RSA_core("RSA i15 core", &br_rsa_i15_public, &br_rsa_i15_private);
    test_RSA_OAEP("RSA i15 OAEP",
                  &br_rsa_i15_oaep_encrypt, &br_rsa_i15_oaep_decrypt);
}

static void
test_RSA_i31(void)
{
    test_RSA_core("RSA i31 core", &br_rsa_i31_public, &br_rsa_i31_private);
    test_RSA_OAEP("RSA i31 OAEP",
                  &br_rsa_i31_oaep_encrypt, &br_rsa_i31_oaep_decrypt);
}

static void
test_RSA_i32(void)
{
    test_RSA_core("RSA i32 core", &br_rsa_i32_public, &br_rsa_i32_private);
    test_RSA_OAEP("RSA i32 OAEP",
                  &br_rsa_i32_oaep_encrypt, &br_rsa_i32_oaep_decrypt);
}

static void
test_RSA_i62(void)
{
    br_rsa_public pub;
    br_rsa_private priv;
    br_rsa_pkcs1_sign sign;
    br_rsa_pkcs1_vrfy vrfy;
    br_rsa_pss_sign pss_sign;
    br_rsa_pss_vrfy pss_vrfy;
    br_rsa_oaep_encrypt menc;
    br_rsa_oaep_decrypt mdec;
    br_rsa_keygen kgen;

    pub = br_rsa_i62_public_get();
    priv = br_rsa_i62_private_get();
    sign = br_rsa_i62_pkcs1_sign_get();
    vrfy = br_rsa_i62_pkcs1_vrfy_get();
    pss_sign = br_rsa_i62_pss_sign_get();
    pss_vrfy = br_rsa_i62_pss_vrfy_get();
    menc = br_rsa_i62_oaep_encrypt_get();
    mdec = br_rsa_i62_oaep_decrypt_get();
    kgen = br_rsa_i62_keygen_get();
    if (pub) {
        if (!priv || !sign || !vrfy || !pss_sign || !pss_vrfy
            || !menc || !mdec || !kgen)
        {
            fprintf(stderr, "Inconsistent i62 availability\n");
            exit(EXIT_FAILURE);
        }
        test_RSA_core("RSA i62 core", pub, priv);
        test_RSA_OAEP("RSA i62 OAEP", menc, mdec);
    } else {
        if (priv || sign || vrfy || pss_sign || pss_vrfy
            || menc || mdec || kgen)
        {
            fprintf(stderr, "Inconsistent i62 availability\n");
            exit(EXIT_FAILURE);
        }
        printf("Test RSA i62: UNAVAILABLE\n");
    }
}

#if 0
static void
test_RSA_signatures(void)
{
	uint32_t n[40], e[2], p[20], q[20], dp[20], dq[20], iq[20], x[40];
	unsigned char hv[20], sig[128];
	unsigned char ref[128], tmp[128];
	br_sha1_context hc;

	printf("Test RSA signatures: ");
	fflush(stdout);

	/*
	 * Decode RSA key elements.
	 */
	br_int_decode(n, sizeof n / sizeof n[0], RSA_N, sizeof RSA_N);
	br_int_decode(e, sizeof e / sizeof e[0], RSA_E, sizeof RSA_E);
	br_int_decode(p, sizeof p / sizeof p[0], RSA_P, sizeof RSA_P);
	br_int_decode(q, sizeof q / sizeof q[0], RSA_Q, sizeof RSA_Q);
	br_int_decode(dp, sizeof dp / sizeof dp[0], RSA_DP, sizeof RSA_DP);
	br_int_decode(dq, sizeof dq / sizeof dq[0], RSA_DQ, sizeof RSA_DQ);
	br_int_decode(iq, sizeof iq / sizeof iq[0], RSA_IQ, sizeof RSA_IQ);

	/*
	 * Decode reference signature (computed with OpenSSL).
	 */
	hextobin(ref, "45A3DC6A106BCD3BD0E48FB579643AA3FF801E5903E80AA9B43A695A8E7F454E93FA208B69995FF7A6D5617C2FEB8E546375A664977A48931842AAE796B5A0D64393DCA35F3490FC157F5BD83B9D58C2F7926E6AE648A2BD96CAB8FCCD3D35BB11424AD47D973FF6D69CA774841AEC45DFAE99CCF79893E7047FDE6CB00AA76D");

	/*
	 * Recompute signature. Since PKCS#1 v1.5 signatures are
	 * deterministic, we should get the same as the reference signature.
	 */
	br_sha1_init(&hc);
	br_sha1_update(&hc, "test", 4);
	br_sha1_out(&hc, hv);
	if (!br_rsa_sign(sig, sizeof sig, p, q, dp, dq, iq, br_sha1_ID, hv)) {
		fprintf(stderr, "RSA-1024/SHA-1 sig generate failed\n");
		exit(EXIT_FAILURE);
	}
	check_equals("KAT RSA-sign 1", sig, ref, sizeof sig);

	/*
	 * Verify signature.
	 */
	if (!br_rsa_verify(sig, sizeof sig, n, e, br_sha1_ID, hv)) {
		fprintf(stderr, "RSA-1024/SHA-1 sig verify failed\n");
		exit(EXIT_FAILURE);
	}
	hv[5] ^= 0x01;
	if (br_rsa_verify(sig, sizeof sig, n, e, br_sha1_ID, hv)) {
		fprintf(stderr, "RSA-1024/SHA-1 sig verify should have failed\n");
		exit(EXIT_FAILURE);
	}
	hv[5] ^= 0x01;

	/*
	 * Generate a signature with the alternate encoding (no NULL) and
	 * verify it.
	 */
	hextobin(tmp, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00301F300706052B0E03021A0414A94A8FE5CCB19BA61C4C0873D391E987982FBBD3");
	br_int_decode(x, sizeof x / sizeof x[0], tmp, sizeof tmp);
	x[0] = n[0];
	br_rsa_private_core(x, p, q, dp, dq, iq);
	br_int_encode(sig, sizeof sig, x);
	if (!br_rsa_verify(sig, sizeof sig, n, e, br_sha1_ID, hv)) {
		fprintf(stderr, "RSA-1024/SHA-1 sig verify (alt) failed\n");
		exit(EXIT_FAILURE);
	}
	hv[5] ^= 0x01;
	if (br_rsa_verify(sig, sizeof sig, n, e, br_sha1_ID, hv)) {
		fprintf(stderr, "RSA-1024/SHA-1 sig verify (alt) should have failed\n");
		exit(EXIT_FAILURE);
	}
	hv[5] ^= 0x01;

	printf("done.\n");
	fflush(stdout);
}
#endif

static int
eq_name(const char *s1, const char *s2)
{
    for (;;) {
        int c1, c2;

        for (;;) {
            c1 = *s1 ++;
            if (c1 >= 'A' && c1 <= 'Z') {
                c1 += 'a' - 'A';
            } else {
                switch (c1) {
                    case '-': case '_': case '.': case ' ':
                        continue;
                }
            }
            break;
        }
        for (;;) {
            c2 = *s2 ++;
            if (c2 >= 'A' && c2 <= 'Z') {
                c2 += 'a' - 'A';
            } else {
                switch (c2) {
                    case '-': case '_': case '.': case ' ':
                        continue;
                }
            }
            break;
        }
        if (c1 != c2) {
            return 0;
        }
        if (c1 == 0) {
            return 1;
        }
    }
}

#define STU(x)   { &test_ ## x, #x }

static const struct {
    void (*fn)(void);
    const char *name;
} tfns[] = {
        STU(RSA_i62),
        { 0, 0 }
};

int
main(int argc, char *argv[])
{
    size_t u;
    for (u = 0; tfns[u].name; u ++) {
        tfns[u].fn();
    }
    return 0;
}