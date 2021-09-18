
#define gladman_aes

#ifdef gladman_aes
#include "gladman/aestst.h"
#endif

int main(void) {

#if defined( gladman_aes )
    aes_gladman_test();
#endif

    return 0;
}

