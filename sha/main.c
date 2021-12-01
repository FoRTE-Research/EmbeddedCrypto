/** need to choose which AES implementation to run **/
#define gladman_sha
//#define saddi_sha
//#define mbedtls_sha

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef gladman_sha
#include <memory.h>
#include <ctype.h>
#include "gladman/sha1.h"
#include "gladman/sha2.h"
#endif
#ifdef saddi_sha
#include "saddi/sha256.h"
#include <stdlib.h>
#endif
#ifdef mbedtls_sha
#include "mbedtls/sha256.h"
#endif

/** Globals (test inputs) **/
unsigned char hval[32];
unsigned char data[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop"; // Data you want to hash
unsigned char check_sha256[] = "aa353e009edbaebfc6e494c8d847696896cb8b398e0173a4b5c1b636292d87c7";
size_t len = 55; // Length of the data

/** contexts **/
#ifdef gladman_sha
    sha256_ctx cx[1];
#endif
#ifdef saddi_sha
    SHA256_CTX ctx;
#endif
#ifdef mbedtls_sha
    mbedtls_sha256_context ctx;
#endif

/** Call initialization functions for different SHA implementations **/
void init_sha() {
#ifdef gladman_sha
    sha256_begin(cx);
#endif
#ifdef saddi_sha
    sha256_init (&ctx);
#endif
#ifdef mbedtls_aes
    mbedtls_sha256_init(&ctx);
#endif
}

int test_sha256() {
#ifdef gladman_sha
    sha256(hval, data, len, cx);
    // hval now contains SHA256(data)
#endif
#ifdef saddi_sha
    uint8_t hash[SHA256_HASH_SIZE];
    sha256_update (&ctx, data, len);
    sha256_final (&ctx, hash);
#endif
#ifdef mbedtls_sha
    mbedtls_sha256(data, len, hval, 0, ctx);
    // hval now contains SHA256(data)
#endif
}

int check_result() {
    if (0 == memcmp((char*) hval, (char*) check_sha256, 64)) {
        return 0; // Success
    } else {
        return 1; // Failure
    }
}

int main (int argc, char *argv[]) {

  /** initialize SHA **/
  init_sha();

  /** test SHA-256 **/
  test_sha256();

  /** Check the result to see whether AES algorithm is correctly working or not **/
  check_result();

}
