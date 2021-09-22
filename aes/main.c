/* need to choose which AES implementation to run */
#define gladman_aes
//#define tiny_aes

/* need to uncomment if the board you are using is MSP432P401R */
// #define msp432p401r

/// DO NOT EDIT BELOW  //////////////////////////////////////////

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

#ifdef tiny_aes
#include "tiny_aes/aes.h"
#endif

#ifdef msp432p401r
#include "msp.h"
#endif

#if defined( gladman_aes )
#define test_encrypt_192(a,b,c)    aes_gladman_test_192(a,b,c);
#endif

#if defined( tiny_aes )
    test_AES_encrypt();
    test_AES_decrypt();
#endif

// Globals (test inputs)
// key, plaintext, key_size

int main(void) {
    test_encrypt_key_size(&key, &pt, &ct);
    return 0;
}

