//#define BSD
#define TINY_ECC


#include "tiny_ecc/ecdh.h"
#include <assert.h>

#if defined(TINY_ECC)
 #define ECC_PUB_SIZE ECC_PUB_KEY_SIZE
 #define ECC_PRV_SIZE ECC_PRV_KEY_SIZE
#elif defined(BSD)
 #define ECC_PUB_SIZE 64
 #define ECC_PRV_SIZE 32
#endif

uint8_t pub_a[ECC_PUB_SIZE];
uint8_t prv_a[ECC_PRV_SIZE];
uint8_t sec_a[ECC_PUB_SIZE];
uint8_t pub_b[ECC_PUB_SIZE];
uint8_t prv_b[ECC_PRV_SIZE];
uint8_t sec_b[ECC_PUB_SIZE];
uint32_t i;

void init_ecc() {
#if defined(TINY_ECC)
    
    static int initialized = 0;
    if (!initialized)
    {
        prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
        initialized = 1;
    }

    for (i = 0; i < ECC_PRV_SIZE; ++i)
    {
        prv_a[i] = prng_next();
    }
    ecdh_generate_keys(pub_a, prv_a);

    for (i = 0; i < ECC_PRV_SIZE; ++i)
    {
        prv_b[i] = prng_next();
    }
    ecdh_generate_keys(pub_b, prv_b);
#elif defined(BSD)

#endif
}

void generate_share_secret(){
#if defined(TINY_ECC)
    ecdh_shared_secret(prv_a, pub_b, sec_a);
    ecdh_shared_secret(prv_b, pub_a, sec_b);
#elif defined(BSD)

#endif
}

void check_result() {

    for (i = 0; i < ECC_PUB_KEY_SIZE; ++i)
    {
        assert(sec_a[i] == sec_b[i]);
    }
}

int main(){

    init_ecc();
    generate_share_secret();
    check_result();

    return 0;
}