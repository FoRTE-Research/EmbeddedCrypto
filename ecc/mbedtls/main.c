#include <stdio.h>
#include "ecdh.h"
#include "ecp.h"

int main() {
    mbedtls_ecdh_context *ctx;

    mbedtls_ecp_keypair our_key;
    mbedtls_ecp_keypair their_key;

    unsigned char shared_secret[MBEDTLS_ECP_MAX_BYTES];
    size_t shared_secret_length = 0;

    mbedtls_ecdh_init(ctx);
    mbedtls_ecp_group_id group_id = MBEDTLS_ECP_DP_SECP256R1;
    mbedtls_ecdh_setup(ctx, group_id);

    mbedtls_ecdh_side side = MBEDTLS_ECDH_OURS;
    mbedtls_ecp_keypair_init( &our_key );
    mbedtls_ecp_keypair_init( &their_key );

    int a = 1;

    return 0;
}
