# FoRTE-Research - EmbeddedCrypto

This project measures the efficiency of different crypto algorithms installed in different microcontrollers. We identify the "best of breed" crypto for ultra-low SWaP devices in an energy harvesting context.
- Quantify the performance vs. energy trade space
- Identify device features that impact this trade space the most
- Assess the security impact when the attacker has access to intermediate results

## Board Support 

Candidate Boards  | ISA
------------- | -------------
MSP432P401R  | ARM
SiFive HiFive1 Rev B  | RISC-V 

## Cryptographic Algorithm

Algorithm  | key size
------------- | -------------
AES  | 128 bit / 192 bit / 256 bit
SHA  | 256 bit
ECC  | 

## Curve Support

SEC Group | Type | strength
------------- | -------------
sect163k1  | GF(2^m) | 80 bit
sect163r2  | GF(2^m) | 80 bit
sect233k1  | GF(2^m) | 112 bit
sect233r1  | GF(2^m) | 112 bit
sect283k1  | GF(2^m) | 128 bit
sect283r1  | GF(2^m) | 128 bit
sect409k1  | GF(2^m) | 192 bit
sect409r1  | GF(2^m) | 192 bit
sect571k1  | GF(2^m) | 256 bit
sect571r1  | GF(2^m) | 256 bit
secp160r1  | GF(P) | 80 bit
secp192r1  | GF(P) | 96 bit
secp224r1  | GF(P) | 112 bit
secp256r1  | GF(P) | 128 bit
secp256k1  | GF(P) | 128 bit

## Getting Started

Download ARM GCC commandline tools: https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads

Select the algorithm you want to use and copy all the file inside the folder to your root folder of board.

    .
    ├── ...
    ├── AES                    
    │   ├── all.c          
    │   ├── all.h         
    │   └── xxx.c                
    └── ...

**RISC-V :**
Change file name ".risc_Makefile" to "Makefile".\
**MSP432P401R :**
Uncomment the definition in the file containing the main function.
