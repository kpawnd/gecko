/*
 * Based on NIST SP 800-38D
 */

#include "gecko.h"
#include <string.h>

/* GF(2^128) multiplication for GHASH */
static void gf128_mul(uint8_t *x, const uint8_t *h) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    
    memcpy(v, h, 16);
    
    for (int i = 0; i < 128; i++) {
        /* If bit i of x is set, z = z XOR v */
        if (x[i / 8] & (0x80 >> (i % 8))) {
            for (int j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        
        /* v = v * P (multiply by polynomial) */
        uint8_t carry = v[15] & 1;
        
        /* Shift right by 1 */
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        }
        v[0] >>= 1;
        
        /* If carry, XOR with R = 0xe1 || 0^120 */
        if (carry) {
            v[0] ^= 0xe1;
        }
    }
    
    memcpy(x, z, 16);
}

/* GHASH function */
static void ghash(const uint8_t *h, const uint8_t *data, size_t len, uint8_t *out) {
    uint8_t x[16] = {0};
    
    /* Process complete blocks */
    while (len >= 16) {
        for (int i = 0; i < 16; i++) {
            x[i] ^= data[i];
        }
        gf128_mul(x, h);
        data += 16;
        len -= 16;
    }
    
    /* Process remaining bytes */
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            x[i] ^= data[i];
        }
        gf128_mul(x, h);
    }
    
    memcpy(out, x, 16);
}

/* Increment counter block */
static void inc32(uint8_t *block) {
    for (int i = 15; i >= 12; i--) {
        if (++block[i] != 0) {
            break;
        }
    }
}

/* Initialize GCM context */
void gecko_gcm_init(gecko_gcm_ctx_t *ctx, const uint8_t key[32]) {
    uint8_t zero[16] = {0};
    
    /* Initialize AES */
    gecko_aes_init(&ctx->aes, key);
    
    /* Compute H = AES_K(0^128) */
    gecko_aes_encrypt_block(&ctx->aes, zero, ctx->h);
    
    /* Reset state */
    memset(ctx->j0, 0, 16);
    memset(ctx->ghash, 0, 16);
    ctx->aad_len = 0;
    ctx->ct_len = 0;
}

/* Set nonce (IV) */
void gecko_gcm_set_nonce(gecko_gcm_ctx_t *ctx, const uint8_t nonce[12]) {
    /* For 96-bit nonce: J0 = nonce || 0^31 || 1 */
    memcpy(ctx->j0, nonce, 12);
    ctx->j0[12] = 0;
    ctx->j0[13] = 0;
    ctx->j0[14] = 0;
    ctx->j0[15] = 1;
    
    /* Reset GHASH */
    memset(ctx->ghash, 0, 16);
    ctx->aad_len = 0;
    ctx->ct_len = 0;
}

/* Process additional authenticated data */
void gecko_gcm_aad(gecko_gcm_ctx_t *ctx, const uint8_t *aad, size_t len) {
    /* XOR AAD into GHASH */
    while (len >= 16) {
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= aad[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        aad += 16;
        len -= 16;
        ctx->aad_len += 16;
    }
    
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            ctx->ghash[i] ^= aad[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        ctx->aad_len += len;
    }
}

/* Encrypt data in place */
void gecko_gcm_encrypt(gecko_gcm_ctx_t *ctx, uint8_t *data, size_t len) {
    uint8_t counter[16];
    uint8_t keystream[16];
    
    /* Start from J0 + 1 */
    memcpy(counter, ctx->j0, 16);
    inc32(counter);
    
    while (len >= 16) {
        /* Generate keystream block */
        gecko_aes_encrypt_block(&ctx->aes, counter, keystream);
        inc32(counter);
        
        /* XOR with plaintext */
        for (int i = 0; i < 16; i++) {
            data[i] ^= keystream[i];
        }
        
        /* Update GHASH with ciphertext */
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        
        data += 16;
        len -= 16;
        ctx->ct_len += 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        gecko_aes_encrypt_block(&ctx->aes, counter, keystream);
        
        for (size_t i = 0; i < len; i++) {
            data[i] ^= keystream[i];
            ctx->ghash[i] ^= data[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        
        ctx->ct_len += len;
    }
}

/* Decrypt data in place */
void gecko_gcm_decrypt(gecko_gcm_ctx_t *ctx, uint8_t *data, size_t len) {
    uint8_t counter[16];
    uint8_t keystream[16];
    
    /* Start from J0 + 1 */
    memcpy(counter, ctx->j0, 16);
    inc32(counter);
    
    while (len >= 16) {
        /* Update GHASH with ciphertext first */
        for (int i = 0; i < 16; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        
        /* Generate keystream block */
        gecko_aes_encrypt_block(&ctx->aes, counter, keystream);
        inc32(counter);
        
        /* XOR with ciphertext */
        for (int i = 0; i < 16; i++) {
            data[i] ^= keystream[i];
        }
        
        data += 16;
        len -= 16;
        ctx->ct_len += 16;
    }
    
    /* Handle remaining bytes */
    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            ctx->ghash[i] ^= data[i];
        }
        gf128_mul(ctx->ghash, ctx->h);
        
        gecko_aes_encrypt_block(&ctx->aes, counter, keystream);
        
        for (size_t i = 0; i < len; i++) {
            data[i] ^= keystream[i];
        }
        
        ctx->ct_len += len;
    }
}

/* Compute authentication tag */
void gecko_gcm_finish(gecko_gcm_ctx_t *ctx, uint8_t tag[16]) {
    uint8_t len_block[16];
    uint8_t s[16];
    
    /* Construct length block: len(A) || len(C) in bits */
    uint64_t aad_bits = ctx->aad_len * 8;
    uint64_t ct_bits = ctx->ct_len * 8;
    
    len_block[0] = (aad_bits >> 56) & 0xff;
    len_block[1] = (aad_bits >> 48) & 0xff;
    len_block[2] = (aad_bits >> 40) & 0xff;
    len_block[3] = (aad_bits >> 32) & 0xff;
    len_block[4] = (aad_bits >> 24) & 0xff;
    len_block[5] = (aad_bits >> 16) & 0xff;
    len_block[6] = (aad_bits >> 8) & 0xff;
    len_block[7] = aad_bits & 0xff;
    
    len_block[8] = (ct_bits >> 56) & 0xff;
    len_block[9] = (ct_bits >> 48) & 0xff;
    len_block[10] = (ct_bits >> 40) & 0xff;
    len_block[11] = (ct_bits >> 32) & 0xff;
    len_block[12] = (ct_bits >> 24) & 0xff;
    len_block[13] = (ct_bits >> 16) & 0xff;
    len_block[14] = (ct_bits >> 8) & 0xff;
    len_block[15] = ct_bits & 0xff;
    
    /* Final GHASH */
    for (int i = 0; i < 16; i++) {
        ctx->ghash[i] ^= len_block[i];
    }
    gf128_mul(ctx->ghash, ctx->h);
    
    /* T = GCTR_K(J0, S) */
    gecko_aes_encrypt_block(&ctx->aes, ctx->j0, s);
    
    for (int i = 0; i < 16; i++) {
        tag[i] = ctx->ghash[i] ^ s[i];
    }
}

/* Verify authentication tag */
bool gecko_gcm_verify(gecko_gcm_ctx_t *ctx, const uint8_t tag[16]) {
    uint8_t computed[16];
    gecko_gcm_finish(ctx, computed);
    return gecko_secure_compare(computed, tag, 16) == 0;
}

/* High-level encrypt: nonce || ciphertext || tag */
gecko_error_t gecko_encrypt(const uint8_t key[32],
                            const uint8_t *plaintext, size_t pt_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *output, size_t *out_len) {
    gecko_gcm_ctx_t ctx;
    uint8_t nonce[12];
    
    /* Generate random nonce */
    gecko_error_t err = gecko_random_bytes(nonce, 12);
    if (err != GECKO_OK) {
        return err;
    }
    
    /* Check output size */
    size_t required = 12 + pt_len + 16;  /* nonce + ciphertext + tag */
    if (*out_len < required) {
        *out_len = required;
        return GECKO_ERR_INVALID_PARAM;
    }
    
    /* Initialize */
    gecko_gcm_init(&ctx, key);
    gecko_gcm_set_nonce(&ctx, nonce);
    
    /* Copy nonce to output */
    memcpy(output, nonce, 12);
    
    /* Copy plaintext and encrypt in place */
    memcpy(output + 12, plaintext, pt_len);
    
    /* Process AAD */
    if (aad && aad_len > 0) {
        gecko_gcm_aad(&ctx, aad, aad_len);
    }
    
    /* Encrypt */
    gecko_gcm_encrypt(&ctx, output + 12, pt_len);
    
    /* Compute tag */
    gecko_gcm_finish(&ctx, output + 12 + pt_len);
    
    *out_len = required;
    
    /* Clear sensitive data */
    gecko_secure_zero(&ctx, sizeof(ctx));
    
    return GECKO_OK;
}

/* High-level decrypt */
gecko_error_t gecko_decrypt(const uint8_t key[32],
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *output, size_t *out_len) {
    gecko_gcm_ctx_t ctx;
    
    /* Check minimum size: nonce + tag */
    if (ct_len < 28) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    size_t data_len = ct_len - 12 - 16;  /* Remove nonce and tag */
    
    if (*out_len < data_len) {
        *out_len = data_len;
        return GECKO_ERR_INVALID_PARAM;
    }
    
    /* Extract components */
    const uint8_t *nonce = ciphertext;
    const uint8_t *data = ciphertext + 12;
    const uint8_t *tag = ciphertext + ct_len - 16;
    
    /* Initialize */
    gecko_gcm_init(&ctx, key);
    gecko_gcm_set_nonce(&ctx, nonce);
    
    /* Copy ciphertext to output */
    memcpy(output, data, data_len);
    
    /* Process AAD */
    if (aad && aad_len > 0) {
        gecko_gcm_aad(&ctx, aad, aad_len);
    }
    
    /* Decrypt */
    gecko_gcm_decrypt(&ctx, output, data_len);
    
    /* Verify tag */
    if (!gecko_gcm_verify(&ctx, tag)) {
        gecko_secure_zero(output, data_len);
        gecko_secure_zero(&ctx, sizeof(ctx));
        return GECKO_ERR_CRYPTO;
    }
    
    *out_len = data_len;
    
    /* Clear sensitive data */
    gecko_secure_zero(&ctx, sizeof(ctx));
    
    return GECKO_OK;
}

/*
 * GCM encryption function for vault
 * 
 * REMINDER -> Parameters:
 *   key: 32-byte encryption key
 *   plaintext: data to encrypt
 *   pt_len: plaintext length
 *   aad: additional authenticated data (can be NULL)
 *   aad_len: AAD length
 *   iv: 12-byte initialization vector
 *   ciphertext: output buffer (same size as plaintext)
 *   tag: 16-byte authentication tag output
 */
gecko_error_t gecko_gcm_encrypt_simple(const uint8_t key[32],
                                        const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t iv[12],
                                        uint8_t *ciphertext,
                                        uint8_t tag[16]) {
    gecko_gcm_ctx_t ctx;
    
    gecko_gcm_init(&ctx, key);
    gecko_gcm_set_nonce(&ctx, iv);
    
    /* Process AAD */
    if (aad && aad_len > 0) {
        gecko_gcm_aad(&ctx, aad, aad_len);
    }
    
    /* Copy plaintext and encrypt in place */
    memcpy(ciphertext, plaintext, pt_len);
    gecko_gcm_encrypt(&ctx, ciphertext, pt_len);
    
    /* Compute tag */
    gecko_gcm_finish(&ctx, tag);
    
    /* Clear sensitive data */
    gecko_secure_zero(&ctx, sizeof(ctx));
    
    return GECKO_OK;
}

/*
 * Simple GCM decrypt function for vault
 */
gecko_error_t gecko_gcm_decrypt_simple(const uint8_t key[32],
                                        const uint8_t *ciphertext, size_t ct_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t iv[12],
                                        const uint8_t tag[16],
                                        uint8_t *plaintext) {
    gecko_gcm_ctx_t ctx;
    
    gecko_gcm_init(&ctx, key);
    gecko_gcm_set_nonce(&ctx, iv);
    
    /* Process AAD */
    if (aad && aad_len > 0) {
        gecko_gcm_aad(&ctx, aad, aad_len);
    }
    
    /* Copy ciphertext and decrypt in place */
    memcpy(plaintext, ciphertext, ct_len);
    gecko_gcm_decrypt(&ctx, plaintext, ct_len);
    
    /* Verify tag */
    if (!gecko_gcm_verify(&ctx, tag)) {
        gecko_secure_zero(plaintext, ct_len);
        gecko_secure_zero(&ctx, sizeof(ctx));
        return GECKO_ERR_AUTH;
    }
    
    /* Clear sensitive data */
    gecko_secure_zero(&ctx, sizeof(ctx));
    
    return GECKO_OK;
}
