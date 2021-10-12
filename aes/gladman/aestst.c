/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The redistribution and use of this software (with or without changes)
 is allowed without the payment of fees or royalties provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007
*/

// Correct Output (for variable block size - AES_BLOCK_SIZE undefined):

// lengths:  block = 16 bytes, key = 16 bytes
// key     = 2b7e151628aed2a6abf7158809cf4f3c
// input   = 3243f6a8885a308d313198a2e0370734
// encrypt = 3925841d02dc09fbdc118597196a0b32
// decrypt = 3243f6a8885a308d313198a2e0370734

// lengths:  block = 16 bytes, key = 24 bytes
// key     = 2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da5
// input   = 3243f6a8885a308d313198a2e0370734
// encrypt = f9fb29aefc384a250340d833b87ebc00
// decrypt = 3243f6a8885a308d313198a2e0370734

// lengths:  block = 16 bytes, key = 32 bytes
// key     = 2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe
// input   = 3243f6a8885a308d313198a2e0370734
// encrypt = 1a6e6c2c662e7da6501ffb62bc9e93f3
// decrypt = 3243f6a8885a308d313198a2e0370734

#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "aestst.h"

void oblk(char m[], unsigned char v[], unsigned long n)
{   unsigned long i;
    
    printf("\n%s", m);

    for(i = 0; i < n; ++i)
        printf("%02x", v[i]);
}

void message(const char *s)   { printf("%s", s); }

unsigned char pih[32];
unsigned char exh[32];
unsigned char res[32];

void gladman_init(uint8_t *key, uint8_t *pt, uint8_t* ct, long n) {

    //init key
    for(int i = 0; i < n; i++) {
        exh[i] = key[i];
    }

    //init plain text
    for(int i = 0; i < 16; i++) {
        pih[i] = pt[i];
    }

    for(int i = 0; i < 16; i++) {
        res[i] = ct[i];
    }
}

#if defined( AES_128 )
int aes_gladman_128(unsigned char *key, unsigned char *pt, unsigned char *ct) {
    unsigned char   out[32] , ret[32], err = 0;
    f_ectx          alge[1];
    f_dctx          algd[1];

    message("\nRun tests for the Gladman AES 128 algorithm");

    memset(&alge, 0, sizeof(aes_encrypt_ctx));
    memset(&algd, 0, sizeof(aes_decrypt_ctx));
    printf("\n\n// lengths:  block = 16, bytes, key = 16 bytes");
    gladman_init(key, pt, ct, 16);
    f_enc_key128(alge, exh);
    oblk("// key     = ", exh, 16);
    oblk("// input   = ", pih, 16);
    do_enc(alge, pih, out, 1);
    oblk("// encrypt = ", out, 16);
    if(memcmp(out, res, 16)) { message (" error"); err += 1; }
    f_dec_key128(algd, exh);
    do_dec(algd, out, ret, 1);
    oblk("// decrypt = ", ret, 16);
    if(memcmp(ret, pih, 16)) { message (" error"); err += 2; }
    return 0;

}
#endif

#if defined( AES_192 )
int aes_gladman_192(unsigned char *key, unsigned char *pt, unsigned char *ct) {
    unsigned char   out[32] , ret[32], err = 0;
    f_ectx          alge[1];
    f_dctx          algd[1];

    message("\nRun tests for the Gladman AES 196 algorithm");
    memset(&alge, 0, sizeof(aes_encrypt_ctx));
    memset(&algd, 0, sizeof(aes_decrypt_ctx));

    memset(out, 0xcc, 16); memset(ret, 0xcc, 16);
    printf("\n\n// lengths:  block = 16, bytes, key = 24 bytes");
    gladman_init(key, pt, ct, 24);
    f_enc_key192(alge, exh);
    oblk("// key     = ", exh, 24);
    oblk("// input   = ", pih, 16);
    do_enc(alge, pih, out, 1);
    oblk("// encrypt = ", out, 16);
    if(memcmp(out, res, 16))  { message (" error"); err += 4; }
    f_dec_key192(algd, exh);
    do_dec(algd, out, ret, 1);
    oblk("// decrypt = ", ret, 16);
    if(memcmp(ret, pih, 16))  { message (" error"); err += 8; }

    return 0;
}
#endif

#if defined( AES_256 )
int aes_gladman_256(unsigned char *key, unsigned char *pt, unsigned char *ct) {
    unsigned char   out[32] , ret[32], err = 0;
    f_ectx          alge[1];
    f_dctx          algd[1];

    message("\nRun tests for the Gladman AES 256 algorithm");
    memset(&alge, 0, sizeof(aes_encrypt_ctx));
    memset(&algd, 0, sizeof(aes_decrypt_ctx));
    printf("\n\n// lengths:  block = 16, bytes, key = 32 bytes");
    gladman_init(key, pt, ct, 32);
    f_enc_key256(alge, exh);
    oblk("// key     = ", exh, 32);
    oblk("// input   = ", pih, 16);
    do_enc(alge, pih, out, 1);
    oblk("// encrypt = ", out, 16);
    if(memcmp(out, res, 16))  { message (" error"); err += 16; }
    f_dec_key256(algd, exh);
    do_dec(algd, out, ret, 1);
    oblk("// decrypt = ", ret, 16);
    if(memcmp(ret, pih, 16))  { message (" error"); err += 32; }

    return 0;
}
#endif
