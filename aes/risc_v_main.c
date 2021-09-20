
#define gladman_aes
#define tiny_aes

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

#ifdef tiny_aes
#include "tiny_aes/aes.h"
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

