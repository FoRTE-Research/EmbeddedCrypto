#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>
#include "../config.h"

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES_256) && (AES_256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES_192) && (AES_192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

void AES_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // _AES_H_
