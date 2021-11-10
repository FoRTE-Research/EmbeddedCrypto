/*
 * test.h
 *
 *  Created on: Nov 10, 2021
 *      Author: zeezooryu
 */

#ifndef AES_TEST_H_
#define AES_TEST_H_

/** need to choose which AES implementation to run **/
//#define gladman_aes
#define tiny_aes
//#define mbedtls_aes

/** need to uncomment if the board you are using is MSP432P401R **/
#define msp432p401r
//#define riscv

/** need to define key size **/
//#define AES_128 1
#define AES_192 1
//#define AES_256 1

#endif /* AES_TEST_H_ */
