/** need to choose which AES implementation to run **/
//#define gladman_sha
#define saddi_sha

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#endif

#ifdef saddi_sha
#include "saddi/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif
#ifdef gladman_sha
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include "gladman/sha1.h"
#include "gladman/sha2.h"
#endif

int run_sha256() {
#ifdef saddi_sha
    SHA256_CTX foo;
    uint8_t hash[SHA256_HASH_SIZE];
    char buf[1000];
    int i;

    sha256_init (&foo);
    sha256_update (&foo, "abc", 3);
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      printf ("%02x", hash[i++]);
      if (!(i % 4))
        printf (" ");
    }
    printf ("\n");

    sha256_init (&foo);
    sha256_update (&foo,
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          56);
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      printf ("%02x", hash[i++]);
      if (!(i % 4))
        printf (" ");
    }
    printf ("\n");

    sha256_init (&foo);
    memset (buf, 'a', sizeof (buf));
    for (i = 0; i < 1000; i++)
      sha256_update (&foo, buf, sizeof (buf));
    sha256_final (&foo, hash);

    for (i = 0; i < SHA256_HASH_SIZE;) {
      printf ("%02x", hash[i++]);
      if (!(i % 4))
        printf (" ");
    }
    printf ("\n");

    return (0);
#endif
#ifdef gladman_sha
    FILE *fo;
    enum hash alg;
    enum hash bits = 0;
    enum test tests;
    /*  tests = basic_byte | cs_bits | cs_bytes | gg_easy_bi | gg_hard_bi;  */

    alg = SHA256 | (SHA2_BITS ? BITS : 0);
    do_tests(fo, alg, tests);
    return (0);
#endif
}

int main (int argc, char *argv[]) {
  run_sha256();
}
