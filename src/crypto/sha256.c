/*
 * Based on FIPS 180-4 specification
 */

#include "gecko.h"
#include <string.h>

/* SHA-256 constants */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Rotate right */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* SHA-256 functions */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)       (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* Process single 512-bit block */
static void sha256_transform(gecko_sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t w[64];
    
    /* Prepare message schedule */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4] << 24) |
               ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) |
               ((uint32_t)data[i*4+3]);
    }
    
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }
    
    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    /* 64 rounds */
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    /* Update state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void gecko_sha256_init(gecko_sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void gecko_sha256_update(gecko_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t buffer_idx = ctx->count % 64;
    ctx->count += len;
    
    /* If we have data in buffer, fill it first */
    if (buffer_idx > 0) {
        size_t fill = 64 - buffer_idx;
        if (len < fill) {
            memcpy(ctx->buffer + buffer_idx, data, len);
            return;
        }
        memcpy(ctx->buffer + buffer_idx, data, fill);
        sha256_transform(ctx, ctx->buffer);
        data += fill;
        len -= fill;
    }
    
    /* Process complete blocks */
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }
    
    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void gecko_sha256_final(gecko_sha256_ctx_t *ctx, uint8_t hash[32]) {
    uint8_t pad[64];
    size_t buffer_idx = ctx->count % 64;
    uint64_t bit_count = ctx->count * 8;
    
    /* Padding: 1 bit, then zeros, then 64-bit length */
    pad[0] = 0x80;
    
    if (buffer_idx < 56) {
        memset(pad + 1, 0, 55 - buffer_idx);
        gecko_sha256_update(ctx, pad, 56 - buffer_idx);
    } else {
        memset(pad + 1, 0, 63 - buffer_idx);
        gecko_sha256_update(ctx, pad, 64 - buffer_idx);
        memset(pad, 0, 56);
        gecko_sha256_update(ctx, pad, 56);
    }
    
    /* Append length in bits */
    pad[0] = (bit_count >> 56) & 0xff;
    pad[1] = (bit_count >> 48) & 0xff;
    pad[2] = (bit_count >> 40) & 0xff;
    pad[3] = (bit_count >> 32) & 0xff;
    pad[4] = (bit_count >> 24) & 0xff;
    pad[5] = (bit_count >> 16) & 0xff;
    pad[6] = (bit_count >> 8) & 0xff;
    pad[7] = bit_count & 0xff;
    gecko_sha256_update(ctx, pad, 8);
    
    /* Output hash */
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (ctx->state[i] >> 24) & 0xff;
        hash[i*4+1] = (ctx->state[i] >> 16) & 0xff;
        hash[i*4+2] = (ctx->state[i] >> 8) & 0xff;
        hash[i*4+3] = ctx->state[i] & 0xff;
    }
}

/* One-shot hash */
void gecko_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    gecko_sha256_ctx_t ctx;
    gecko_sha256_init(&ctx);
    gecko_sha256_update(&ctx, data, len);
    gecko_sha256_final(&ctx, hash);
}

/* HMAC-SHA256 */
void gecko_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t mac[32]) {
    gecko_sha256_ctx_t ctx;
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];
    
    /* If key is longer than block size, hash it */
    if (key_len > 64) {
        gecko_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }
    
    /* Prepare key pads */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    
    /* Inner hash */
    gecko_sha256_init(&ctx);
    gecko_sha256_update(&ctx, k_ipad, 64);
    gecko_sha256_update(&ctx, data, data_len);
    gecko_sha256_final(&ctx, mac);
    
    /* Outer hash */
    gecko_sha256_init(&ctx);
    gecko_sha256_update(&ctx, k_opad, 64);
    gecko_sha256_update(&ctx, mac, 32);
    gecko_sha256_final(&ctx, mac);
    
    /* Clear sensitive data */
    gecko_secure_zero(k_ipad, 64);
    gecko_secure_zero(k_opad, 64);
    gecko_secure_zero(&ctx, sizeof(ctx));
}
