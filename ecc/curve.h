//
// Created by 廖哲賢 on 2021/10/12.
//

#ifndef CURVE_H
#define CURVE_H

/* BSD Support Curve. Set to 0 to remove that curve. */
#ifndef uECC_SUPPORTS_secp160r1
#define uECC_SUPPORTS_secp160r1 0
#endif
#ifndef uECC_SUPPORTS_secp192r1
#define uECC_SUPPORTS_secp192r1 0
#endif
#ifndef uECC_SUPPORTS_secp224r1
#define uECC_SUPPORTS_secp224r1 0
#endif
#ifndef uECC_SUPPORTS_secp256r1
#define uECC_SUPPORTS_secp256r1 0
#endif
#ifndef uECC_SUPPORTS_secp256k1
#define uECC_SUPPORTS_secp256k1 1
#endif


/*Tiny ECC Support Curve*/
#define NIST_B163  1
#define NIST_K163  2
#define NIST_B233  3
#define NIST_K233  4
#define NIST_B283  5
#define NIST_K283  6
#define NIST_B409  7
#define NIST_K409  8
#define NIST_B571  9
#define NIST_K571 10

/* What is the default curve to use? */
#ifndef ECC_CURVE
 #define ECC_CURVE NIST_B163
#endif


#endif //AES_TEST_CURVE_H
