#ifndef GECKO_CRYPTO_H
#define GECKO_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key parameters stored on disk */
struct gecko_key_params {
    uint8_t  salt[GECKO_SALT_SIZE];
    uint32_t iterations;
    uint32_t version;
    uint64_t created_timestamp;
};

/* AES context */
typedef struct {
    uint32_t round_keys[60];
    int      num_rounds;
} gecko_aes_ctx_t;

/* GCM context */
typedef struct {
    gecko_aes_ctx_t aes;
    uint8_t         h[16];      /* Hash subkey */
    uint8_t         j0[16];     /* Pre-counter block */
    uint8_t         ghash[16];  /* GHASH accumulator */
    uint64_t        aad_len;
    uint64_t        ct_len;
} gecko_gcm_ctx_t;

/* SHA-256 context */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} gecko_sha256_ctx_t;

/* Generate cryptographically secure random bytes */
gecko_error_t gecko_random_bytes(uint8_t *buf, size_t len);

/* Initialize AES context with key */
void gecko_aes_init(gecko_aes_ctx_t *ctx, const uint8_t key[32]);

/* Encrypt single block */
void gecko_aes_encrypt_block(const gecko_aes_ctx_t *ctx, 
                              const uint8_t in[16], 
                              uint8_t out[16]);

/* Decrypt single block */
void gecko_aes_decrypt_block(const gecko_aes_ctx_t *ctx,
                              const uint8_t in[16],
                              uint8_t out[16]);

/* Initialize GCM context */
void gecko_gcm_init(gecko_gcm_ctx_t *ctx, const uint8_t key[32]);

/* Set nonce (must be 12 bytes) */
void gecko_gcm_set_nonce(gecko_gcm_ctx_t *ctx, const uint8_t nonce[12]);

/* Add additional authenticated data */
void gecko_gcm_aad(gecko_gcm_ctx_t *ctx, const uint8_t *aad, size_t len);

/* Encrypt data in place */
void gecko_gcm_encrypt(gecko_gcm_ctx_t *ctx, uint8_t *data, size_t len);

/* Decrypt data in place */
void gecko_gcm_decrypt(gecko_gcm_ctx_t *ctx, uint8_t *data, size_t len);

/* Generate authentication tag */
void gecko_gcm_finish(gecko_gcm_ctx_t *ctx, uint8_t tag[16]);

/* Verify authentication tag */
bool gecko_gcm_verify(gecko_gcm_ctx_t *ctx, const uint8_t tag[16]);

/* Simple GCM encrypt with separate IV and tag */
gecko_error_t gecko_gcm_encrypt_simple(const uint8_t key[32],
                                        const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t iv[12],
                                        uint8_t *ciphertext,
                                        uint8_t tag[16]);

/* Simple GCM decrypt with separate IV and tag */
gecko_error_t gecko_gcm_decrypt_simple(const uint8_t key[32],
                                        const uint8_t *ciphertext, size_t ct_len,
                                        const uint8_t *aad, size_t aad_len,
                                        const uint8_t iv[12],
                                        const uint8_t tag[16],
                                        uint8_t *plaintext);

/* High-level encrypt: nonce || ciphertext || tag */
gecko_error_t gecko_encrypt(const uint8_t key[32],
                            const uint8_t *plaintext, size_t pt_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *output, size_t *out_len);

/* High-level decrypt */
gecko_error_t gecko_decrypt(const uint8_t key[32],
                            const uint8_t *ciphertext, size_t ct_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *output, size_t *out_len);

void gecko_sha256_init(gecko_sha256_ctx_t *ctx);
void gecko_sha256_update(gecko_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void gecko_sha256_final(gecko_sha256_ctx_t *ctx, uint8_t hash[32]);

/* One-shot hash */
void gecko_sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

void gecko_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t mac[32]);

/* Derive key from password */
gecko_error_t gecko_pbkdf2(const void *password, size_t password_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iterations,
                           uint8_t *key, size_t key_len);

/* Derive key using stored parameters */
gecko_error_t gecko_derive_key(const char *password,
                               const gecko_key_params_t *params,
                               uint8_t key[32]);

/* Generate new key parameters */
gecko_error_t gecko_key_params_generate(gecko_key_params_t *params);

/* Save parameters to file */
gecko_error_t gecko_key_params_save(const gecko_key_params_t *params,
                                    const char *path);

/* Load parameters from file */
gecko_error_t gecko_key_params_load(gecko_key_params_t *params,
                                    const char *path);

/* Securely zero memory */
void gecko_secure_zero(void *ptr, size_t len);

/* Constant-time comparison - returns 0 if equal, non-zero otherwise */
int gecko_secure_compare(const void *a, const void *b, size_t len);

/* Secure memory allocation */
void *gecko_secure_alloc(size_t size);

/* Secure memory free with zeroing */
void gecko_secure_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif
