/***************
 STILL IN PRIGRESS
 Comments are left in places where it needs work one.
 Those comments will be removed once relevant information is filled.
 ***************/





/** need to choose which RSA implementation to run **/
//#define tiny_rsa
//#define bearssl_rsa
//#define libtomcrypt_rsa
//#define mbedtls_rsa

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/// DO NOT EDIT BELOW  //////////////////////////////////////////
#ifdef msp432p401r
#include "msp.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef tiny_rsa
#include "bn.h"
#endif
#ifdef  mbedtls_rsa
//#include the header files needed for mbedtls_rsa here
#include "mbedtls/pk.h"
#endif
#ifdef bearssl_sha
//#include the header files needed for bearssl_sha here
#endif


/** Globals (test inputs) **/
//define the global variables here


/** Call initialization functions for different RSA implementations **/
void init_rsa() {
#ifdef tiny_rsa
    //call for init function here
#endif
#ifdef mbedtls_rsa
    //call for init function here
#endif
#ifdef bearssl_rsa
    //call for init function here
#endif
}

int test_rsa() {
#ifdef tiny_rsa
    // Call the function to test the rsa here
#endif
#ifdef mbedtls_rsa
    // Call the function to test the rsa here
#endif
#ifdef bearssl_rsa
    // Call the function to test the rsa here
#endif
}

int check_result() {
//    return memcmp((char*) hval, (char*) check_sha256, DIGEST_BYTES);
//    NEED TO CHANGE THIS BASED ON THE VARIABLES DEFINED
}

int main (int argc, char *argv[]) {

  /** initialize RSA **/
  init_rsa();

  /** test rsa **/
  test_rsa();

  /** Check the result to see whether RSA algorithm is correctly working or not **/
  check_result();

}
