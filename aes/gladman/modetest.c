/*
---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#define DUAL_CORE

#if defined( _MSC_VER ) && (defined( DUAL_CORE ) || defined( DLL_IMPORT ) && defined( DLL_DYNAMIC_LOAD ))
#include <windows.h>
#elif defined(__GNUC__)
#  define _GNU_SOURCE
#  include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "aesopt.h"
#include "aestst.h"
#include "aesaux.h"

#if defined( USE_VIA_ACE_IF_PRESENT )

#include "aes_via_ace.h"

#else

#define aligned_array(type, name, no, stride) type name[no]
#define aligned_auto(type, name, no, stride)  type name[no]

#endif

#define TEST_ECB
#define TEST_CBC
#define TEST_CFB
#define TEST_OFB
#define TEST_CTR

//#define WHOLE_BLOCKS
#define VALIDATE_IN_TIMING

#if defined( DLL_IMPORT ) && defined( DLL_DYNAMIC_LOAD )
fn_ptrs fn;
#endif

#define SAMPLE1  1000
#define SAMPLE2 10000

void ECBenc(unsigned char *buf, int len, f_ectx cx[1])
{   int cnt = len / AES_BLOCK_SIZE;

    while(cnt--)
        f_enc_blk(cx, buf, buf), buf += AES_BLOCK_SIZE;
}

void ECBdec(unsigned char *buf, int len, f_dctx cx[1])
{   int cnt = len / AES_BLOCK_SIZE;

    while(cnt--)
        f_dec_blk(cx, buf, buf), buf += AES_BLOCK_SIZE;
}

void CBCenc(unsigned char *buf, int len, unsigned char *iv, f_ectx cx[1])
{   int cnt = len / AES_BLOCK_SIZE, i;

    while(cnt--)
    {
        for(i = 0; i < AES_BLOCK_SIZE; i++)
            buf[i] ^= iv[i];

        f_enc_blk(cx, buf, buf);
        memcpy(iv, buf, AES_BLOCK_SIZE);
        buf += AES_BLOCK_SIZE;
    }
}

void CBCdec(unsigned char *buf, int len, unsigned char *iv, f_dctx cx[1])
{   unsigned char temp[AES_BLOCK_SIZE];
    int cnt = len / AES_BLOCK_SIZE, i;

    while( cnt-- )
    {
        memcpy(temp, buf, AES_BLOCK_SIZE);
        f_dec_blk(cx, buf, buf);

        for(i = 0; i < AES_BLOCK_SIZE; i++)
            buf[i] ^= iv[i];

        memcpy(iv, temp, AES_BLOCK_SIZE);
        buf += AES_BLOCK_SIZE;
    }
}

void CFBenc(unsigned char *buf, int len, unsigned char *iv, f_ectx cx[1])
{   int i, nb, cnt = f_info(cx);

    if(cnt)
    {
        nb = AES_BLOCK_SIZE - cnt;
        if(len < nb) nb = len;

        for(i = 0; i < nb; i++)
            buf[i] ^= iv[i + cnt];

        memcpy(iv + cnt, buf, nb);
        len -= nb, buf += nb, cnt += nb;
    }

    while(len)
    {
        cnt = (len > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : len;
        f_enc_blk(cx, iv, iv);
        for(i = 0; i < cnt; i++)
            buf[i] ^= iv[i];
        memcpy(iv, buf, cnt);
        len -= cnt, buf += cnt;
    }

    f_info(cx) = (cnt % AES_BLOCK_SIZE);
}

void CFBdec(unsigned char *buf, int len, unsigned char *iv, f_ectx cx[1])
{   unsigned char temp[AES_BLOCK_SIZE];
    int i, nb, cnt = f_info(cx);

    if(cnt)
    {
        nb = AES_BLOCK_SIZE - cnt;
        if(len < nb) nb = len;
        memcpy(temp, buf, nb);

        for(i = 0; i < nb; i++)
            buf[i] ^= iv[i + cnt];

        memcpy(iv + cnt, temp, nb);
        len -= nb, buf += nb, cnt += nb;
    }

    while(len)
    {
        cnt = (len > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : len;
        f_enc_blk(cx, iv, iv);
        memcpy(temp, buf, cnt);

        for(i = 0; i < cnt; i++)
            buf[i] ^= iv[i];

        memcpy(iv, temp, cnt);
        len -= cnt, buf += cnt;
    }
    f_info(cx) = (cnt % AES_BLOCK_SIZE);
}

void OFBenc(unsigned char *buf, int len, unsigned char *iv, f_ectx cx[1])
{   int i, nb, cnt = f_info(cx);

    if(cnt)
    {
        nb = AES_BLOCK_SIZE - cnt;
        if(len < nb) nb = len;

        for(i = 0; i < nb; i++)
            buf[i] ^= iv[i + cnt];

        len -= nb, buf += nb, cnt += nb;
    }

    while(len)
    {
        cnt = (len > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : len;
        f_enc_blk(cx, iv, iv);

        for(i = 0; i < cnt; i++)
            buf[i] ^= iv[i];

        len -= cnt, buf += cnt;
    }

    f_info(cx) = (cnt % AES_BLOCK_SIZE);
}

void OFBdec(unsigned char *buf, int len, unsigned char *iv, f_ectx cx[1])
{   int i, nb, cnt = f_info(cx);

    if( cnt )
    {
        nb = AES_BLOCK_SIZE - cnt;
        if(len < nb) nb = len;

        for(i = 0; i < nb; i++)
            buf[i] ^= iv[i + cnt];

        len -= nb, buf += nb, cnt += nb;
    }

    while(len)
    {
        cnt = (len > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : len;
        f_enc_blk(cx, iv, iv);

        for(i = 0; i < cnt; i++)
            buf[i] ^= iv[i];

        len -= cnt, buf += cnt;
    }

    f_info(cx) = (cnt % AES_BLOCK_SIZE);
}

void CTRcry(unsigned char *buf, int len, unsigned char *cbuf, cbuf_inc *incf, f_ectx cx[1])
{   int i, cnt;
    uint8_t ecbuf[AES_BLOCK_SIZE];

    while(len)
    {
        cnt = (len > AES_BLOCK_SIZE) ? AES_BLOCK_SIZE : len;
        f_enc_blk(cx, cbuf, ecbuf);
        if(cnt == AES_BLOCK_SIZE)
            incf(cbuf);

        for(i = 0; i < cnt; i++)
            buf[i] ^= ecbuf[i];

        len -= cnt, buf += cnt;
    }
}

void ctr_inc(unsigned char x[AES_BLOCK_SIZE])
{
    if(!(++(x[0])))
        if(!(++(x[1])))
            if(!(++(x[2])))
                ++(x[3]);
}

#define BUFLEN  (1000 * AES_BLOCK_SIZE)

int main(void)
{   int     i, k, err, blocks, len, len2;
    double  a0, av, sig, td;
    // 1000 * 16
    unsigned char   buf1[BUFLEN];
    unsigned char   buf2[BUFLEN];
    //16 byte 128 bit
    unsigned char   iv1[AES_BLOCK_SIZE];
    unsigned char   iv2[AES_BLOCK_SIZE];
    unsigned char   key[32];
    f_ectx ecx1[1];
    f_dctx dcx1[1];
    aligned_auto(unsigned char, buf3, BUFLEN, 16);
    aligned_auto(unsigned char, iv3, AES_BLOCK_SIZE, 16);
    aligned_auto(f_ectx, ecx2, 1, 16);
    aligned_auto(f_dctx, dcx2, 1, 16);

    if(f_talign(0,16) != EXIT_SUCCESS)
        return -1;

    printf("\nRun tests for the AES algorithm");


    for(k = 128; k <= 256; k += 64)
    {
        printf("\n\n%03i Bit Keys", k);
#ifdef TEST_ECB
        err = 0;
        for(i = 0; i < 100; ++i)
        {
            block_rndfill(key, 2 * AES_BLOCK_SIZE);
            f_enc_key(ecx1, key, k);
            f_enc_key(ecx2, key, k);
            f_dec_key(dcx1, key, k);
            f_dec_key(dcx2, key, k);

            block_rndfill(buf1, BUFLEN);
            memcpy(buf2, buf1, BUFLEN);
            memcpy(buf3, buf1, BUFLEN);

            td = rand32() / ((double)UINT32_MAX);
            len = (unsigned int)(0.5 * BUFLEN * (1.0 + td));
            len = AES_BLOCK_SIZE * (len / AES_BLOCK_SIZE);

            ECBenc(buf2, len, ecx1);
            f_ecb_enc(ecx2, buf3, buf3, len);

            if(memcmp(buf2, buf3, len)) err |= 1;
            if((err & 1) && !(err & 256))
                printf("\nECB encryption FAILURE");

            ECBdec(buf2, len, dcx1);
            f_ecb_dec(dcx2, buf3, buf3, len);

            if(memcmp(buf1, buf2, len)) err |= 2;
            if(memcmp(buf1, buf3, len)) err |= 4;
            if((err & 4) && !(err & 512))
                printf("\nECB decryption FAILURE");
            if(err & 1)
                err |= 256;
            if(err & 4)
                err |= 512;
        }
        if(!err)
            printf("\nECB encrypt and decrypt of data correct");
#endif

#ifdef TEST_CBC
        err = 0;
        for(i = 0; i < 100; ++i)
        {
            block_rndfill(key, 2 * AES_BLOCK_SIZE);
            f_enc_key(ecx1, key, k);
            f_enc_key(ecx2, key, k);
            f_dec_key(dcx1, key, k);
            f_dec_key(dcx2, key, k);

            block_rndfill(iv1, AES_BLOCK_SIZE);
            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            block_rndfill(buf1, BUFLEN);
            memcpy(buf2, buf1, BUFLEN);
            memcpy(buf3, buf1, BUFLEN);

            td = rand32() / ((double)UINT32_MAX);
            len = (unsigned int)(0.5 * BUFLEN * (1.0 + td));
            len = AES_BLOCK_SIZE * (len / AES_BLOCK_SIZE);

            CBCenc(buf2, len, iv2, ecx1);
            f_cbc_enc(ecx2, buf3, buf3, len, iv3);

            if(memcmp(buf2, buf3, len)) err |= 1;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 2;
            if((err & 1) && !(err & 256))
                printf("\nCBC encryption FAILURE");

            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);
            CBCdec(buf2, len, iv2, dcx1);
            f_cbc_dec(dcx2, buf3, buf3, len, iv3);

            if(memcmp(buf1, buf2, len)) err |= 4;
            if(memcmp(buf1, buf3, len)) err |= 8;
            if(memcmp(buf2, buf3, len)) err |= 16;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 32;
            if((err & 16) && !(err & 512))
                printf("\nCBC decryption FAILURE");
            if(err & 1)
                err |= 256;
            if(err & 16)
                err |= 512;
        }
        if(!(err & ~(2 | 4 | 16 | 32)))
            printf("\nCBC encrypt and decrypt of data correct");
        if(err & (2 | 32))
        {
            printf(" (mismatch of final IV on ");
            if(err & 2)
                printf("encrypt");
            if((err & (2 | 32)) == 34)
                printf(" and ");
            if(err & 32)
                printf("decrypt");
            printf(")");
        }
#endif

#ifdef TEST_CFB
        err = 0;
        for(i = 0; i < 100; ++i)
        {
            block_rndfill(key, 2 * AES_BLOCK_SIZE);
            f_enc_key(ecx1, key, k);
            f_enc_key(ecx2, key, k);
            f_dec_key(dcx1, key, k);
            f_dec_key(dcx2, key, k);

            block_rndfill(iv1, AES_BLOCK_SIZE);
            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            block_rndfill(buf1, BUFLEN);
            memcpy(buf2, buf1, BUFLEN);
            memcpy(buf3, buf1, BUFLEN);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            td = rand32() / ((double)UINT32_MAX);
            len = (unsigned int)(0.5 * BUFLEN * (1.0 + td));
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
#ifdef WHOLE_BLOCKS
            len = AES_BLOCK_SIZE * (len / AES_BLOCK_SIZE);
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_cfb_enc(ecx2, buf3, buf3, len2, iv3);
            f_cfb_enc(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3);

            CFBenc(buf2, len, iv2, ecx1);
            if(memcmp(buf2, buf3, len)) err |= 1;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 2;
            if((err & 1) && !(err & 256))
                printf("\nCFB encryption FAILURE");

            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            CFBdec(buf2, len, iv2, ecx1);
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
#ifdef WHOLE_BLOCKS
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_cfb_dec(ecx2, buf3, buf3, len2, iv3);
            f_cfb_dec(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3);

            if(memcmp(buf1, buf2, len)) err |= 4;
            if(memcmp(buf1, buf3, len)) err |= 8;
            if(memcmp(buf2, buf3, len)) err |= 16;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 32;
            if((err & 16) && !(err & 512))
                printf("\nCFB decryption FAILURE");
            if(err & 1)
                err |= 256;
            if(err & 16)
                err |= 512;
        }
        if(!(err & ~(2 | 4 | 16 | 32)))
            printf("\nCFB encrypt and decrypt of data correct");
        if(err & (2 | 32))
        {
            printf(" (mismatch of final IV on ");
            if(err & 2)
                printf("encrypt");
            if((err & (2 | 32)) == 34)
                printf(" and ");
            if(err & 32)
                printf("decrypt");
            printf(")");
        }
#endif

#ifdef TEST_OFB
        err = 0;
        for(i = 0; i < 100; ++i)
        {
            block_rndfill(key, 2 * AES_BLOCK_SIZE);
            f_enc_key(ecx1, key, k);
            f_enc_key(ecx2, key, k);
            f_dec_key(dcx1, key, k);
            f_dec_key(dcx2, key, k);

            block_rndfill(iv1, AES_BLOCK_SIZE);
            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            block_rndfill(buf1, BUFLEN);
            memcpy(buf2, buf1, BUFLEN);
            memcpy(buf3, buf1, BUFLEN);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            td = rand32() / ((double)UINT32_MAX);
            len = (unsigned int)(0.5 * BUFLEN * (1.0 + td));
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
#ifdef WHOLE_BLOCKS
            len = AES_BLOCK_SIZE * (len / AES_BLOCK_SIZE);
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_ofb_cry(ecx2, buf3, buf3, len2, iv3);
            f_ofb_cry(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3);

            OFBenc(buf2, len, iv2, ecx1);
            if(memcmp(buf2, buf3, len)) err |= 1;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 2;
            if((err & 1) && !(err & 256))
                printf("\nOFB encryption FAILURE");

            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            OFBdec(buf2, len, iv2, ecx1);
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
#ifdef WHOLE_BLOCKS
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_ofb_cry(ecx2, buf3, buf3, len2, iv3);
            f_ofb_cry(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3);

            if(memcmp(buf1, buf2, len)) err |= 4;
            if(memcmp(buf1, buf3, len)) err |= 8;
            if(memcmp(buf2, buf3, len)) err |= 16;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 32;
            if((err & 16) && !(err & 512))
                printf("\nOFB decryption FAILURE");
            if(err & 1)
                err |= 256;
            if(err & 16)
                err |= 512;
        }
        if(!(err & ~(2 | 4 | 16 | 32)))
            printf("\nOFB encrypt and decrypt of data correct");
        if(err & (2 | 32))
        {
            printf(" (mismatch of final IV on ");
            if(err & 2)
                printf("encrypt");
            if((err & (2 | 32)) == 34)
                printf(" and ");
            if(err & 32)
                printf("decrypt");
            printf(")");
        }
#endif

#ifdef TEST_CTR
        err = 0;
        for(i = 0; i < 100; ++i)
        {
            block_rndfill(key, 2 * AES_BLOCK_SIZE);
            f_enc_key(ecx1, key, k);
            f_enc_key(ecx2, key, k);
            f_dec_key(dcx1, key, k);
            f_dec_key(dcx2, key, k);

            block_rndfill(iv1, AES_BLOCK_SIZE);
            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            block_rndfill(buf1, BUFLEN);
            memcpy(buf2, buf1, BUFLEN);
            memcpy(buf3, buf1, BUFLEN);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            td = rand32() / ((double)UINT32_MAX);
            len = (unsigned int)(0.5 * BUFLEN * (1.0 + td));
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
#ifdef WHOLE_BLOCKS
            len = AES_BLOCK_SIZE * (len / AES_BLOCK_SIZE);
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_ctr_cry(ecx2, buf3, buf3, len2, iv3, ctr_inc);
            f_ctr_cry(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3, ctr_inc);

            CTRcry(buf2, len, iv2, ctr_inc, ecx1);
            if(memcmp(buf2, buf3, len)) err |= 1;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 2;
            if((err & 1) && !(err & 256))
                printf("\nCTR encryption FAILURE");

            memcpy(iv2, iv1, AES_BLOCK_SIZE);
            memcpy(iv3, iv1, AES_BLOCK_SIZE);

            f_info(ecx1) = 0;
            f_mode_reset(ecx2);
            td = rand32() / ((double)UINT32_MAX);
            len2 = (unsigned int)(td * len);
            CTRcry(buf2, len, iv2, ctr_inc, ecx1);
#ifdef WHOLE_BLOCKS
            len2 = AES_BLOCK_SIZE * (len2 / AES_BLOCK_SIZE);
#endif
            f_ctr_cry(ecx2, buf3, buf3, len2, iv3, ctr_inc);
            f_ctr_cry(ecx2, buf3 + len2, buf3 + len2, len - len2, iv3, ctr_inc);

            if(memcmp(buf1, buf2, len)) err |= 4;
            if(memcmp(buf1, buf3, len)) err |= 8;
            if(memcmp(buf2, buf3, len)) err |= 16;
            if(memcmp(iv2, iv3, AES_BLOCK_SIZE)) err |= 32;
            if((err & 16) && !(err & 512))
                printf("\nCTR decryption FAILURE");
            if(err & 1)
                err |= 256;
            if(err & 16)
                err |= 512;
        }
        if(!(err & ~(2 | 4 | 16 | 32)))
            printf("\nCTR encrypt and decrypt of data correct");
        if(err & (2 | 32))
        {
            printf(" (mismatch of final IV on ");
            if(err & 2)
                printf("encrypt");
            if((err & (2 | 32)) == 34)
                printf(" and ");
            if(err & 32)
                printf("decrypt");
            printf(")");
        }
#endif
    }
    printf("\n\n");
    return 0;
}
