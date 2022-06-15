/** need to choose which SHA implementation to run **/
// #define gladman_sha
#define saddi_sha
// #define mbedtls_sha

/** need to uncomment if the board you are using is MSP432P401R **/
// #define msp432p401r
//#define riscv
#define adafruitm0express

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#include "rom_map.h"
#include "rom.h"
#include "systick.h"
#endif

#ifdef msp430g2553
#include "msp430.h"
#endif

#ifdef msp430fr5994
#include "msp430.h"
#endif

#include "experiment_time.h"

#include <stdio.h>
#include <string.h>

#ifdef gladman_sha
#include <memory.h>
#include <ctype.h>
#include "gladman/sha2.h"
#include "gladman/sha2.c"
#endif
#ifdef saddi_sha
#include "saddi/sha256.h"
#include "saddi/sha256.c"
#include <stdlib.h>
#endif
#ifdef mbedtls_sha
#include "mbedtls/sha256.h"
#include "mbedtls/sha256.c"
#endif

#define DIGEST_BYTES (256/8)

/** Globals (test inputs) **/
unsigned char hval[DIGEST_BYTES];
unsigned char data[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop"; // Data you want to hash
unsigned char check_sha256[] =
        "aa353e009edbaebfc6e494c8d847696896cb8b398e0173a4b5c1b636292d87c7";
size_t len = sizeof(data);

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
void init_sha()
{
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

void test_sha256()
{
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

int check_result()
{
    return memcmp((char*) hval, (char*) check_sha256, DIGEST_BYTES);
}

void setup() {
  Serial.begin(9600);
}

void loop() {
#ifdef msp432p401r
  /** Initialize the board **/
  board_init();

  /** Starting the timer to measure elapsed time **/
  startTimer();
#endif
#ifdef adafruitm0express
  /** Measure the starting time **/
  setup();
  unsigned long start, finished, elapsed;
  start = micros();
#endif

    /** initialize SHA **/
    init_sha();

    /** test SHA-256 **/
    test_sha256();

    /** Check the result to see whether SHA algorithm is correctly working or not **/
    check_result();

#ifdef msp432p401r
  volatile unsigned int elapsed = getElapsedTime();
#endif
#ifdef adafruitm0express
  /** Calculate the elapsed time **/
  finished = micros();
  elapsed = finished - start;
  Serial.print("Time taken by the task: ");
  Serial.println(elapsed);
  
  // wait a second so as not to send massive amounts of data
  delay(1000);
#endif

    // while (1);

}
