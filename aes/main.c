/* need to choose which AES implementation to run */
#define gladman_aes
#define tiny_aes

/* need to uncomment if the board you are using is MSP432P401R */
// #define msp432p401r

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

#ifdef tiny_aes
#include "tiny_aes/aes.h"
#endif

#ifdef msp432p401r
#include "msp.h"
#endif

int main(void) {

#if defined( gladman_aes )
    aes_gladman_test();
#endif

#if defined( tiny_aes )
    test_AES_encrypt();
    test_AES_decrypt();
#endif

    return 0;
}

