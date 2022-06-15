/***************
  STILL IN PRIGRESS
  Comments are left in places where it needs work one.
  Those comments will be removed once relevant information is filled.
 ***************/

/** need to choose which RSA implementation to run **/
//#define tiny_rsa
//#define codebase
//#define navin
#define bearssl_rsa

/** the two implementations are what me and William are struggling with **/
//#define mbedtls_rsa

/** need to uncomment the board you are using **/
//#define msp432p401r
//#define riscv
#define adafruitm0express

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

#ifdef tiny_rsa
#include "tiny_rsa/rsa_test.h"
#endif
#ifdef codebase
#include "codebase/rsa.h"
#include "codebase/rsa.c"
#endif
#ifdef navin
#include "navin/rsa.h"
#include "navin/rsa.c"
#endif
#ifdef bearssl_rsa
//#include the header files needed for bearssl_sha here
#include "bearssl/bearssl.h"
#include "bearssl/inner.h"
#endif
#ifdef  mbedtls_rsa
//#include the header files needed for mbedtls_rsa here
#include "mbedtls/pk.h"
#endif

/** Globals (test inputs) **/
//define the global variables here
#ifdef tiny_rsa

char resultBuffer[1024];
char publickey[257] = "a15f36fc7f8d188057fc51751962a5977118fa2ad4ced249c039ce36c8d1bd275273f1edd821892fa75680b1ae38749fff9268bf06b3c2af02bbdb52a0d05c2ae2384aa1002391c4b16b87caea8296cfd43757bb51373412e8fe5df2e56370505b692cf8d966e3f16bc62629874a0464a9710e4a0718637a68442e0eb1648ec5";
char privatekey[257] = "3f5cc8956a6bf773e598604faf71097e265d5d55560c038c0bdb66ba222e20ac80f69fc6f93769cb795440e2037b8d67898d6e6d9b6f180169fc6348d5761ac9e81f6b8879529bc07c28dc92609eb8a4d15ac4ba3168a331403c689b1e82f62518c38601d58fd628fcb7009f139fb98e61ef7a23bee4e3d50af709638c24133d";
char cipher[257] = "1cb1c5e45e584cb1b627cac7b0de0812dac7c1d1638785a7660f6772d219f62aa0ce3e8a853abadebe0a293d76a17d321da8b1fd25ddf807ce96006f73a0aed014b990d6025c42b6c216d8553b66e724270b6dbd654d55e368edeacbc8da30f0cbe5ccbb72a3fe44d29543a5bbb5255a404234ce53bf70f52a78170685a6e391";
int plain_text = 54321;

#endif
#ifdef navin

uint64_t x[20] = { 0 }, y[20] = { 0 }, z[20] = { 0 }, e[18] = { 0 };

int i;
uint64_t data[150] = { 0xbc, 0xd8, 0xb9, 0x11, 0x5b, 0x57, 0xc6, 0x8f, 0x90,
                      0xc2, 0xed, 0x97, 0x62, 0x84, 0x2e, 0x21, 0x99, 0x4c,
                      0xb0, 0x2d, 0xe5, 0x75, 0x9f, 0x87, 0x38, 0x23, 0xad,
                      0xa4, 0x74, 0xdb, 0x16, 0x5a, 0x29, 0x39, 0xd8, 0xad,
                      0x21, 0xcb, 0x9c, 0x7b, 0xbc, 0x99, 0xc2, 0x83, 0x5e,
                      0x0d, 0x7c, 0xd6, 0xc5, 0x29, 0xd2, 0xd0, 0x71, 0xf6,
                      0xa5, 0x42, 0xc9, 0xe0, 0x5c, 0x5c, 0xe2, 0xa3, 0x91,
                      0x9b, 0x1a, 0x2d, 0x60, 0x14, 0x0b, 0x7c, 0x0a, 0xfd,
                      0x54, 0x5f, 0xc7, 0xc1, 0x0c, 0xeb, 0xe9, 0x59, 0x23,
                      0x51, 0xf0, 0x3e, 0x95, 0x8f, 0xcf, 0xf6, 0x43, 0xcc,
                      0x08, 0xf4, 0x58, 0x62, 0xcc, 0xe9, 0x49, 0x6a, 0x46,
                      0xb6, 0x5a, 0x72, 0xb4, 0x0c, 0x38, 0xf0, 0xc0, 0x82,
                      0xd7, 0x2e, 0xf9, 0x9e, 0x97, 0x2d, 0xe6, 0xee, 0xa9,
                      0xb9, 0xe0, 0xda, 0x9d, 0xaa, 0xe3, 0xd1, 0x32, 0xd9,
                      0xea, 0xf9
                    };

#endif
#ifdef bearssl_rsa

/*
   Test vectors from pkcs-1v2-1d2-vec.zip (originally from ftp.rsa.com).
   There are ten RSA keys, and for each RSA key, there are 6 messages,
   each with an explicit seed.
*/
static const char *KAT_RSA_OAEP[] =
{
  /* 1024-bit key, from oeap-int.txt */
  //public key
  "BBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51FB8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807FAFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394EE0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB",
  "11",
  //private
  "EECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599",
  "C97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D869840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503",
  "54494CA63EBA0337E4E24023FCD69A5AEB07DDDC0183A4D0AC9B54B051F2B13ED9490975EAB77414FF59C1F7692E9A2E202B38FC910A474174ADC93C1F67C981",
  "471E0290FF0AF0750351B7F878864CA961ADBD3A8A7E991C5C0556A94C3146A7F9803F8F6F8AE342E931FD8AE47A220D1B99A495849807FE39F9245A9836DA3D",
  "B06C4FDABB6301198D265BDBAE9423B380F271F73453885093077FCD39E2119FC98632154F5883B167A967BF402B4E9E2E0F9656E698EA3666EDFB25798039F7",

  /* oaep-int.txt contains only one message, so we repeat it six
    times to respect our array format. */

  //plain text
  "D436E99569FD32A7C8A05BBC90D32C49",
  // seed
  "AAFD12F659CAE63489B479E5076DDEC2F06CB58F",
  //cipher text
  "1253E04DC0A5397BB44A7AB87E9BF2A039A33D1E996FC82A94CCD30074C95DF763722017069E5268DA5D1C0B4F872CF653C11DF82314A67968DFEAE28DEF04BB6D84B1C31D654A1970E5783BD6EB96A024C2CA2F4A90FE9F2EF5C9C140E5BB48DA9536AD8700C84FC9130ADEA74E558D51A74DDF85D8B50DE96838D6063E0955",

  NULL
};

unsigned char resultBuffer[1024];
unsigned char plain[512], seed[128], cipher[512];
size_t check_result_len;

#endif

/** Initialization for different RSA implementations **/

#ifdef tiny_rsa
//    char pub[] = "a15f36fc7f8d188057fc51751962a5977118fa2ad4ced249c039ce36c8d1bd275273f1edd821892fa75680b1ae38749fff9268bf06b3c2af02bbdb52a0d05c2ae2384aa1002391c4b16b87caea8296cfd43757bb51373412e8fe5df2e56370505b692cf8d966e3f16bc62629874a0464a9710e4a0718637a68442e0eb1648ec5";
//    char pri[] = "3f5cc8956a6bf773e598604faf71097e265d5d55560c038c0bdb66ba222e20ac80f69fc6f93769cb795440e2037b8d67898d6e6d9b6f180169fc6348d5761ac9e81f6b8879529bc07c28dc92609eb8a4d15ac4ba3168a331403c689b1e82f62518c38601d58fd628fcb7009f139fb98e61ef7a23bee4e3d50af709638c24133d";
//    char cip[] = "1cb1c5e45e584cb1b627cac7b0de0812dac7c1d1638785a7660f6772d219f62aa0ce3e8a853abadebe0a293d76a17d321da8b1fd25ddf807ce96006f73a0aed014b990d6025c42b6c216d8553b66e724270b6dbd654d55e368edeacbc8da30f0cbe5ccbb72a3fe44d29543a5bbb5255a404234ce53bf70f52a78170685a6e391";
//    plain_text = 54321;
//
//    for(int i = 0; i < strlen(pub); i++) {
//        publickey[i] = pub[i];
//    }
//
//    for(int i = 0; i < strlen(pri); i++) {
//        privatekey[i] = pri[i];
//    }
//
//    for(int i = 0; i < strlen(cip); i++) {
//        cipher[i] = cip[i];
//    }
//    int a = 0;
#endif
#ifdef navin
void init_navin() {
for (i = 0; i < 16; i++)
{
  x[i] = (uint64_t) rand() * (uint64_t) rand();
  y[i] = (uint64_t) rand() * (uint64_t) rand();
}

for (i = 0; i < 64; i++)
{
  uint64_t temp = data[i];
  data[i] = data[127 - i];
  data[127 - i] = temp;
}

for (i = 128; i < 150; i++)
{
  data[i] = 0;
}

e[0] = 0x10001;
}

#endif
#ifdef bearssl_rsa

static size_t hextobin(unsigned char *dst, const char *src)
{
  size_t num;
  unsigned acc;
  int z;

  num = 0;
  z = 0;
  acc = 0;
  while (*src != 0)
  {
    int c = *src++;
    if (c >= '0' && c <= '9')
    {
      c -= '0';
    }
    else if (c >= 'A' && c <= 'F')
    {
      c -= ('A' - 10);
    }
    else if (c >= 'a' && c <= 'f')
    {
      c -= ('a' - 10);
    }
    else
    {
      continue;
    }
    if (z)
    {
      *dst++ = (acc << 4) + c;
      num++;
    }
    else
    {
      acc = c;
    }
    z = !z;
  }
  return num;
}

/*
   Fake RNG that returns exactly the provided bytes.
*/
typedef struct
{
  const br_prng_class *vtable;
  unsigned char buf[128];
  size_t ptr, len;
} rng_fake_ctx;

static void rng_fake_init(rng_fake_ctx *cc, const void *params,
                          const void *seed, size_t len);
static void rng_fake_generate(rng_fake_ctx *cc, void *dst, size_t len);
static void rng_fake_update(rng_fake_ctx *cc, const void *src, size_t len);

static const br_prng_class rng_fake_vtable =
{ sizeof(rng_fake_ctx),
  (void (*)(const br_prng_class**, const void*, const void*, size_t)) &rng_fake_init,
  (void (*)(const br_prng_class**, void*, size_t)) &rng_fake_generate,
  (void (*)(const br_prng_class**, const void*, size_t)) &rng_fake_update
};

static void rng_fake_init(rng_fake_ctx *cc, const void *params,
                          const void *seed, size_t len)
{
  (void) params;
  if (len > sizeof cc->buf)
  {
    fprintf(stderr, "seed is too large (%lu bytes)\n", (unsigned long) len);
    exit(EXIT_FAILURE);
  }
  cc->vtable = &rng_fake_vtable;
  memcpy(cc->buf, seed, len);
  cc->ptr = 0;
  cc->len = len;
}

static void rng_fake_generate(rng_fake_ctx *cc, void *dst, size_t len)
{
  if (len > (cc->len - cc->ptr))
  {
    fprintf(stderr, "asking for more data than expected\n");
    exit(EXIT_FAILURE);
  }
  memcpy(dst, cc->buf + cc->ptr, len);
  cc->ptr += len;
}

static void rng_fake_update(rng_fake_ctx *cc, const void *src, size_t len)
{
  (void) cc;
  (void) src;
  (void) len;
  fprintf(stderr, "unexpected update\n");
  exit(EXIT_FAILURE);
}

#endif
#ifdef mbedtls_rsa
//call for init function here
#endif

void test_encrypt()
{
#ifdef tiny_rsa
  rsa1024_encrypt(&publickey, &privatekey, &resultBuffer, &plain_text);
#endif
#ifdef codebase
  rsaTest();
#endif
#ifdef navin
  // encryption
  for (i = 0; i < 10; i++)
  {
    rsa1024(z, x, e, data);
  }
#endif
#ifdef bearssl_rsa

  size_t u;
  u = 0;

  unsigned char n[512];
  unsigned char e[8];
  unsigned char p[256];
  unsigned char q[256];
  unsigned char dp[256];
  unsigned char dq[256];
  unsigned char iq[256];
  br_rsa_public_key pk;
  br_rsa_private_key sk;
  size_t v;

  pk.n = n;
  pk.nlen = hextobin(n, KAT_RSA_OAEP[u++]);
  pk.e = e;
  pk.elen = hextobin(e, KAT_RSA_OAEP[u++]);

  for (v = 0; n[v] == 0; v++)
    ;
  sk.n_bitlen = BIT_LENGTH(n[v]) + ((pk.nlen - 1 - v) << 3);
  sk.p = p;
  sk.plen = hextobin(p, KAT_RSA_OAEP[u++]);
  sk.q = q;
  sk.qlen = hextobin(q, KAT_RSA_OAEP[u++]);
  sk.dp = dp;
  sk.dplen = hextobin(dp, KAT_RSA_OAEP[u++]);
  sk.dq = dq;
  sk.dqlen = hextobin(dq, KAT_RSA_OAEP[u++]);
  sk.iq = iq;
  sk.iqlen = hextobin(iq, KAT_RSA_OAEP[u++]);

  size_t plain_len, seed_len, cipher_len;
  rng_fake_ctx rng;

  plain_len = hextobin(plain, KAT_RSA_OAEP[u++]);
  seed_len = hextobin(seed, KAT_RSA_OAEP[u++]);
  cipher_len = hextobin(cipher, KAT_RSA_OAEP[u++]);
  rng_fake_init(&rng, NULL, seed, seed_len);

  check_result_len = br_rsa_i15_oaep_encrypt(&rng.vtable, &br_sha1_vtable,
                     NULL, 0, &pk, resultBuffer,
                     sizeof resultBuffer, plain,
                     plain_len);
  if (check_result_len != cipher_len)
  {
    fprintf(stderr, "wrong encrypted length: %lu vs %lu\n",
            (unsigned long) check_result_len, (unsigned long) cipher_len);
  }
  if (rng.ptr != rng.len)
  {
    fprintf(stderr, "seed not fully consumed\n");
    exit(EXIT_FAILURE);
  }

#endif
#ifdef mbedtls_rsa
  // Call the function to test the rsa here
#endif
}

int check_result()
{
#if defined(tiny_rsa)
  return memcmp((char*) cipher, (char*) resultBuffer, strlen(cipher));
#elif defined(bearssl_rsa)
  return memcmp((char*) cipher, (char*) resultBuffer, check_result_len);
#endif
  return 0;
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

  /** initialize navin RSA **/
//  init_navin();
  
  /** test rsa **/
  test_encrypt();
  //test_decrypt();

  /** Check the result to see whether RSA algorithm is correctly working or not **/
//  check_result();

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
