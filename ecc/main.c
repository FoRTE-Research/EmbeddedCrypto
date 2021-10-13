//#define bsd
#define tiny_ecc


#include <stdio.h>
#include "tiny_ecc/ecdh.h"

#ifdef tiny_ecc
uint8_t pub_a[ECC_PUB_KEY_SIZE];
uint8_t prva[ECC_PRV_KEY_SIZE];
uint8_t seca[ECC_PUB_KEY_SIZE];
uint8_t pubb[ECC_PUB_KEY_SIZE];
uint8_t prvb[ECC_PRV_KEY_SIZE];
uint8_t secb[ECC_PUB_KEY_SIZE];
uint32_t i;
#endif

#ifdef bsd
uint8_t pub_a[ECC_PUB_KEY_SIZE];
uint8_t prva[ECC_PRV_KEY_SIZE];
uint8_t seca[ECC_PUB_KEY_SIZE];
uint8_t pubb[ECC_PUB_KEY_SIZE];
uint8_t prvb[ECC_PRV_KEY_SIZE];
uint8_t secb[ECC_PUB_KEY_SIZE];
uint32_t i;
#endif

int main(){

    // init_aes()
    // encrypt() or decrypt() possibly many times
    // check_result()
    // You should verify the returned ct to make sure everything is working
    return 0;
}