/*
 * Public domain
 * HMAC-SHA256 implementation
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"

#define INNER_PADDING '\x36'
#define OUTER_PADDING '\x5c'

#define BLOCK_LENGTH 64

static void normalize_key( uint8_t * const key, const char * const input_key ) {
    const size_t len = strlen( input_key );

    if( len <= BLOCK_LENGTH ) {
        memcpy( key, input_key, len );
        memset( key + len, '\0', BLOCK_LENGTH - len );
    }
    else {
        struct sha256 s;
        sha256_init( &s );
        sha256_update( &s, input_key, len );
        sha256_sum( &s, key );
        memset( key + SHA256_DIGEST_LENGTH, '\0', BLOCK_LENGTH - SHA256_DIGEST_LENGTH );
    }
}

char *hs256( char *data, char *key ) {


    uint8_t _key[ BLOCK_LENGTH ];
    normalize_key( _key, key );

    struct sha256 inner_s;
    sha256_init( &inner_s );

    int offset = 0;
    char hash[SHA256_DIGEST_LENGTH + 1];
    char *result = hash;

    uint8_t inner_key[ BLOCK_LENGTH ];
    uint8_t outer_key[ BLOCK_LENGTH ];
    for( size_t i = 0; i < BLOCK_LENGTH; i++ ) {
        inner_key[ i ] = _key[ i ] ^ INNER_PADDING;
        outer_key[ i ] = _key[ i ] ^ OUTER_PADDING;
    }

    sha256_update( &inner_s, inner_key, BLOCK_LENGTH );


    size_t n = strlen(data);
    sha256_update( &inner_s, data, n );

    uint8_t inner_hash[ SHA256_DIGEST_LENGTH ];
    sha256_sum( &inner_s, inner_hash );

    struct sha256 outer_s;
    sha256_init( &outer_s );
    sha256_update( &outer_s, outer_key, BLOCK_LENGTH );
    sha256_update( &outer_s, inner_hash, SHA256_DIGEST_LENGTH );

    uint8_t hmac[ SHA256_DIGEST_LENGTH ];
    sha256_sum( &outer_s, hmac );

    for( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ )
    {
        offset += sprintf( hash+offset, "%02x%s", hmac[ i ], "" );
    }

    hash[SHA256_DIGEST_LENGTH] = '\0';

    return result;
}