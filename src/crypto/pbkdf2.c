/*
 * Based on RFC 8018
 */

#include "gecko.h"
#include <string.h>
#include <stdlib.h>

/* PBKDF2-HMAC-SHA256 */
gecko_error_t gecko_pbkdf2(const void *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *key, size_t key_len) {
    if (!password || !salt || !key || iterations == 0 || password_len == 0) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    uint8_t u[32];      /* HMAC output */
    uint8_t t[32];      /* XOR accumulator */
    uint8_t *salt_block;
    size_t salt_block_len = salt_len + 4;
    uint32_t block_num = 1;
    size_t offset = 0;
    
    /* Allocate salt || INT(i) buffer */
    salt_block = (uint8_t *)malloc(salt_block_len);
    if (!salt_block) {
        return GECKO_ERR_NO_MEMORY;
    }
    memcpy(salt_block, salt, salt_len);
    
    while (offset < key_len) {
        /* Set block number (big-endian) */
        salt_block[salt_len]     = (block_num >> 24) & 0xff;
        salt_block[salt_len + 1] = (block_num >> 16) & 0xff;
        salt_block[salt_len + 2] = (block_num >> 8) & 0xff;
        salt_block[salt_len + 3] = block_num & 0xff;
        
        /* U_1 = PRF(Password, Salt || INT(i)) */
        gecko_hmac_sha256((const uint8_t *)password, password_len,
                          salt_block, salt_block_len, u);
        memcpy(t, u, 32);
        
        /* U_2 ... U_c */
        for (uint32_t j = 1; j < iterations; j++) {
            gecko_hmac_sha256((const uint8_t *)password, password_len,
                              u, 32, u);
            for (int k = 0; k < 32; k++) {
                t[k] ^= u[k];
            }
        }
        
        /* Copy to output */
        size_t copy_len = key_len - offset;
        if (copy_len > 32) copy_len = 32;
        memcpy(key + offset, t, copy_len);
        
        offset += 32;
        block_num++;
    }
    
    /* Clear sensitive data */
    gecko_secure_zero(salt_block, salt_block_len);
    gecko_secure_zero(u, sizeof(u));
    gecko_secure_zero(t, sizeof(t));
    
    free(salt_block);
    
    return GECKO_OK;
}
