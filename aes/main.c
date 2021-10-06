/** need to choose which AES implementation to run **/
#define gladman_aes
//#define tiny_aes
//#define mbedtls_aes

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r

/** key size should be chosen in config.h **/

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#include <stdint.h>
#include "config.h"

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

#ifdef tiny_aes
#include "tiny_aes/aes.h"
#endif

#ifdef mbedtls_aes
#include "mbedtls/aes.c"
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

#if defined( gladman_aes )
#ifdef AES_128
#define test_encrypt(a, b, c) aes_gladman_128(a, b, c);
#endif
#ifdef AES_192
#define test_encrypt(a, b, c) aes_gladman_192(a, b, c);
#endif
#ifdef AES_256
#define test_encrypt(a, b, c) aes_gladman_256(a, b, c);
#endif
#endif

#if defined( tiny_aes )
#define test_encrypt(a, b, c) test_AES_encrypt(a, b, c);
#endif

#if defined( mbedtls-aes )
#define test_encrypt(a, b, c) mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16] )
#endif

int main(void)
{
    uint8_t pt[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                     0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    test_encrypt(key, pt, ct)
    return 0;
}
