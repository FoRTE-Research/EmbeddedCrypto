#include <string.h>

#include "cmac.h"
#include "utils.h"

void run();

int main()
{
    run();
    return 0;
}

void run()
{
    unsigned char key[] = {
        0x31, 0x50, 0x10, 0x47,
        0x17, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    unsigned char message[] = {
        "Information Security is a multidisciplinary area of study and professional activity which is concerned with the development and implementation of security mechanisms of all available types (technical, organizational, human-oriented and legal) to keep information in all its locations (within and outside the organization's perimeter) and, consequently, information systems, where information is created, processed, stored, transmitted and destroyed, free from threats. This project is finished by GUORUI XU."
    };

    unsigned char out[16];

    aes_cmac(message, strlen((char*)message) + 1, (unsigned char*)out, key);
//    printf("%sAES-128-CMAC Result%s\n", ACCENTCOLOR, DEFAULT);
//    print_bytes(out, 16);

}

