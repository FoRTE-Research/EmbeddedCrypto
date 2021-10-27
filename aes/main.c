/** need to choose which AES implementation to run **/
//#define gladman_aes
//#define tiny_aes
#define mbedtls_aes

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/** need to define key size **/
#define AES_128 1
//#define AES_192 1
//#define AES_256 1

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#include <stdint.h>
#include <string.h>

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

#ifdef tiny_aes
#include "tiny_aes/aes.h"
#endif

#ifdef mbedtls_aes
#include "mbedtls/aes.h"
#endif

#ifdef msp432p401r
#include "msp.h"
#endif

/** Globals (test inputs) **/
/** key, ciphertext **/
uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73,
                  0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
                  0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
                  0xdf, 0xf4 };
uint8_t ct[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b,
                 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
uint8_t pt[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
/** contexts **/
#ifdef tiny_aes
struct AES_ctx ctx;
#endif
#ifdef mbedtls_aes
struct mbedtls_aes_context ctx;
#endif

/** define keysizes **/
#if defined AES_128
long keysize = 128;
#elif defined AES_192
long keysize = 192;
#else
long keysize = 256;
#endif

/** Call initialization functions for different AES implementations **/
void init_aes() {
#ifdef gladman_aes
    gladman_init(key, pt, ct, keysize);
#endif
#ifdef tiny_aes
    AES_init_ctx(&ctx, key);
#endif
#ifdef mbedtls_aes
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, keysize);
#endif
}

void test_encrypt() {
    /** Gladman AES **/
    #ifdef gladman_aes
    #ifdef AES_128
    aes_gladman_128_encrypt(key, pt, ct);
    #elif AES_192
    aes_gladman_192_encrypt(key, pt, ct);
    #else // AES_256
    aes_gladman_256_encrypt(key, pt, ct);
    #endif
    #endif

    /** tiny AES **/
    #ifdef tiny_aes
    AES_encrypt(&ctx, key, pt, ct);
    #endif

    /** MbedTLS AES **/
    #ifdef mbedtls_aes
    mbedtls_internal_aes_encrypt(&ctx, pt, ct);
    #endif
}

void test_decrypt() {
    /** Gladman AES **/
    #ifdef gladman_aes
    #ifdef AES_128
    aes_gladman_128_decrypt(key, ct, pt);
    #elif AES_192
    aes_gladman_192_decrypt(key, ct, pt);
    #else // AES_256
    aes_gladman_256_decrypt(key, ct, pt);
    #endif
    #endif

    /** tiny AES **/
    #ifdef tiny_aes
    AES_decrypt(&ctx, key, ct, pt);
    #endif

    /** MbedTLS AES **/
    #ifdef mbedtls_aes
    mbedtls_internal_aes_decrypt(&ctx, pt, ct);
    #endif
}

int main(void)
{
    /** initialize AES **/
    init_aes();

    /** Choose the function to be called **/
    /** Encrypt or decrypt possibly many times **/
    test_encrypt();
    // test_decrypt();

    /** Check the result to see whether AES algorithm is correctly working or not **/
    if (0 == memcmp((char*) ct, (char*) pt, 16))
    {
        return 0; // Success
    }
    else
    {
        return 1; // Failure
    }
}
