/*
 * aes.c
 *
 *  Created on: Oct 20, 2021
 *      Author: zeezooryu
 */

#include "aes.h"

mbedtls_aes_context aes;

//unsigned char key[32];
//unsigned char iv[16];

//unsigned char input [128];
//unsigned char output[128];

//size_t input_len = 40;
//size_t output_len = 0;

void mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
{
    mbedtls_aes_setkey_enc( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 48, iv, in, out );
}
