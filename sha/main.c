/** need to choose which AES implementation to run **/
//#define gladman_sha
//#define saddi_sha
#define mbedtls_sha

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/** Globals (test inputs) **/
// NEED TO BE DONE BY ZEEZOO

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#endif

#ifdef gladman_sha
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include "gladman/sha1.h"
#include "gladman/sha2.h"
#endif
#ifdef saddi_sha
#include "saddi/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#ifdef mbedtls_sha
#include "mbedtls/sha256.h"
#endif

int run_sha256() {
#ifdef gladman_sha
    unsigned char x[32];
    unsigned char y[256];
    size_t y_len = sizeof(y);
    memset(x, 0, sizeof(x));
    memset(y, 0, sizeof(y));

    // Here you should fill Y with the data you want to hash!
    y[0]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    // y_len should be set to the length of the data you put in Y.
    y_len=56;

    sha256(x, y, y_len);

    // x now contains SHA256(y)

    return(0);
#endif
#ifdef saddi_sha
    SHA256_CTX foo;
    uint8_t hash[SHA256_HASH_SIZE];
    char buf[1000];
    int i;

    sha256_init (&foo);
    sha256_update (&foo, "abc", 3);
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      if (!(i % 4))
    }

    sha256_init (&foo);
    sha256_update (&foo,
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          56);
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      if (!(i % 4))
    }

    sha256_init (&foo);
    memset (buf, 'a', sizeof (buf));
    for (i = 0; i < 1000; i++)
      sha256_update (&foo, buf, sizeof (buf));
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      if (!(i % 4))
    }

    return (0);
#endif
#ifdef mbedtls_sha
    unsigned char x[32];
    unsigned char y[256];
    size_t y_len = sizeof(y);
    memset(x, 0, sizeof(x));
    memset(y, 0, sizeof(y));

    // Here you should fill Y with the data you want to hash!
    y[0]="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    // y_len should be set to the length of the data you put in Y.
    y_len=56;

    mbedtls_sha256(y, y_len, x, 0);

    // x now contains SHA256(y)

    return(0);
#endif
}

int main (int argc, char *argv[]) {
  run_sha256();
}
