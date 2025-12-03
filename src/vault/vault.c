/*
 * Gecko Vault - Hardened encrypted file container
 * 
 * Security features:
 *   - AES-256-GCM authenticated encryption
 *   - PBKDF2-HMAC-SHA256 key derivation (600k iterations)
 *   - Fresh random IV for every encryption
 *   - Authenticated metadata prevents tampering
 *   - Secure memory wiping of sensitive data
 *   - Atomic file operations via tmp+rename
 */

#include "gecko.h"
#include "gecko/vault.h"
#include "gecko/crypto.h"
#include "gecko/util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef GECKO_WINDOWS
#include <windows.h>
#else
#include <unistd.h>
#endif

static const uint8_t MAGIC[8] = {'G','E','C','K','O','1',0,0};
#define MAX_ENTRY_COUNT 100000  /* Prevent DoS via huge entry count */
#define MAX_DATA_SIZE   (16ULL * 1024 * 1024 * 1024) /* 16GB max vault size */
#define MIN_ENC_SIZE    28  /* IV(12) + tag(16) minimum */

typedef struct {
    uint8_t magic[8];
    uint32_t version;
    uint32_t flags;
    uint32_t kdf_iter;
    uint32_t entry_count;
    uint64_t data_offset;
    uint64_t data_size;
    uint8_t reserved[24];
} header_t;

typedef struct file_data {
    uint8_t *enc_data;
    size_t enc_len;
    struct file_data *next;
} file_data_t;

struct gecko_vault {
    char path[GECKO_MAX_PATH];
    uint8_t key[32];
    uint8_t salt[32];
    header_t hdr;
    gecko_vault_entry_t *entries;
    file_data_t *file_data;
    uint32_t count;
    uint32_t capacity;
    bool open;
    bool dirty;
};

/* Endian-safe read/write */
static void w32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t r32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static void w64(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (v >> (i * 8)) & 0xff;
}
static uint64_t r64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
    return v;
}

static file_data_t *get_file_data(gecko_vault_t *v, uint32_t idx) {
    if (!v || idx >= v->count) return NULL;
    file_data_t *fd = v->file_data;
    for (uint32_t i = 0; i < idx && fd; i++) fd = fd->next;
    return fd;
}

static void free_file_data(file_data_t *fd) {
    while (fd) {
        file_data_t *next = fd->next;
        if (fd->enc_data) {
            gecko_secure_zero(fd->enc_data, fd->enc_len);
            free(fd->enc_data);
        }
        free(fd);
        fd = next;
    }
}

static void vault_cleanup(gecko_vault_t *v) {
    if (!v) return;
    gecko_secure_zero(v->key, 32);
    gecko_secure_zero(v->salt, 32);
    free_file_data(v->file_data);
    if (v->entries) {
        gecko_secure_zero(v->entries, v->capacity * sizeof(gecko_vault_entry_t));
        free(v->entries);
    }
    gecko_secure_zero(v, sizeof(*v));
    free(v);
}

gecko_error_t gecko_vault_create(const char *path, const char *password, gecko_vault_t **vault) {
    if (!path || !password || !vault) return GECKO_ERR_INVALID_PARAM;
    if (strlen(path) >= GECKO_MAX_PATH) return GECKO_ERR_INVALID_PARAM;
    if (strlen(password) < 8) return GECKO_ERR_INVALID_PARAM;  /* Enforce minimum */
    if (gecko_file_exists(path)) return GECKO_ERR_EXISTS;
    
    *vault = NULL;
    
    gecko_vault_t *v = calloc(1, sizeof(gecko_vault_t));
    if (!v) return GECKO_ERR_NO_MEMORY;
    
    strncpy(v->path, path, sizeof(v->path) - 1);
    v->path[sizeof(v->path) - 1] = '\0';
    
    gecko_error_t e = gecko_random_bytes(v->salt, 32);
    if (e != GECKO_OK) { vault_cleanup(v); return e; }
    
    e = gecko_pbkdf2(password, strlen(password), v->salt, 32, GECKO_KDF_ITERATIONS, v->key, 32);
    if (e != GECKO_OK) { vault_cleanup(v); return e; }
    
    memcpy(v->hdr.magic, MAGIC, 8);
    v->hdr.version = GECKO_VAULT_VERSION;
    v->hdr.kdf_iter = GECKO_KDF_ITERATIONS;
    
    v->capacity = 16;
    v->entries = calloc(v->capacity, sizeof(gecko_vault_entry_t));
    if (!v->entries) { vault_cleanup(v); return GECKO_ERR_NO_MEMORY; }
    
    v->open = true;
    v->dirty = true;
    *vault = v;
    return GECKO_OK;
}

gecko_error_t gecko_vault_open(const char *path, const char *password, gecko_vault_t **vault) {
    if (!path || !password || !vault) return GECKO_ERR_INVALID_PARAM;
    if (strlen(path) >= GECKO_MAX_PATH) return GECKO_ERR_INVALID_PARAM;
    
    *vault = NULL;
    
    FILE *f = fopen(path, "rb");
    if (!f) return GECKO_ERR_FILE_NOT_FOUND;
    
    gecko_vault_t *v = calloc(1, sizeof(gecko_vault_t));
    if (!v) { fclose(f); return GECKO_ERR_NO_MEMORY; }
    
    strncpy(v->path, path, sizeof(v->path) - 1);
    
    gecko_error_t e = GECKO_OK;
    uint8_t buf[64];
    
    /* Read and validate header */
    if (fread(buf, 1, 64, f) != 64) { e = GECKO_ERR_FORMAT; goto fail; }
    if (memcmp(buf, MAGIC, 8) != 0) { e = GECKO_ERR_FORMAT; goto fail; }
    
    v->hdr.version = r32(buf + 8);
    if (v->hdr.version > GECKO_VAULT_VERSION) { e = GECKO_ERR_FORMAT; goto fail; }
    
    v->hdr.flags = r32(buf + 12);
    v->hdr.kdf_iter = r32(buf + 16);
    v->hdr.entry_count = r32(buf + 20);
    v->hdr.data_offset = r64(buf + 24);
    v->hdr.data_size = r64(buf + 32);
    
    /* Sanity checks */
    if (v->hdr.kdf_iter < 100000) { e = GECKO_ERR_FORMAT; goto fail; }  /* Reject weak KDF */
    if (v->hdr.entry_count > MAX_ENTRY_COUNT) { e = GECKO_ERR_FORMAT; goto fail; }
    if (v->hdr.data_size > MAX_DATA_SIZE) { e = GECKO_ERR_FORMAT; goto fail; }
    
    /* Read salt */
    if (fread(v->salt, 1, 32, f) != 32) { e = GECKO_ERR_FORMAT; goto fail; }
    
    /* Derive key */
    e = gecko_pbkdf2(password, strlen(password), v->salt, 32, v->hdr.kdf_iter, v->key, 32);
    if (e != GECKO_OK) goto fail;
    
    /* Read and verify key check block */
    uint8_t iv[12], enc[48], dec[32];
    if (fread(iv, 1, 12, f) != 12) { e = GECKO_ERR_FORMAT; goto fail; }
    if (fread(enc, 1, 48, f) != 48) { e = GECKO_ERR_FORMAT; goto fail; }
    
    e = gecko_gcm_decrypt_simple(v->key, enc, 32, NULL, 0, iv, enc + 32, dec);
    if (e != GECKO_OK) { e = GECKO_ERR_AUTH; goto fail; }
    if (gecko_secure_compare(dec, v->key, 32) != 0) { e = GECKO_ERR_AUTH; goto fail; }
    gecko_secure_zero(dec, 32);
    
    /* Allocate entries */
    v->capacity = v->hdr.entry_count > 0 ? v->hdr.entry_count : 16;
    v->entries = calloc(v->capacity, sizeof(gecko_vault_entry_t));
    if (!v->entries) { e = GECKO_ERR_NO_MEMORY; goto fail; }
    
    /* Read entries */
    file_data_t *last_fd = NULL;
    for (uint32_t i = 0; i < v->hdr.entry_count; i++) {
        uint8_t eiv[12], etag[16], emeta[28], meta[28];
        
        if (fread(eiv, 1, 12, f) != 12) { e = GECKO_ERR_FORMAT; goto fail; }
        if (fread(etag, 1, 16, f) != 16) { e = GECKO_ERR_FORMAT; goto fail; }
        if (fread(emeta, 1, 28, f) != 28) { e = GECKO_ERR_FORMAT; goto fail; }
        
        e = gecko_gcm_decrypt_simple(v->key, emeta, 28, NULL, 0, eiv, etag, meta);
        if (e != GECKO_OK) { e = GECKO_ERR_CORRUPTED; goto fail; }
        
        uint32_t nlen = r32(meta);
        v->entries[i].size = r64(meta + 4);
        v->entries[i].encrypted_size = r64(meta + 12);
        v->entries[i].offset = r64(meta + 20);
        
        /* Validate name length */
        if (nlen == 0 || nlen >= GECKO_MAX_FILENAME) { e = GECKO_ERR_FORMAT; goto fail; }
        
        /* Validate encrypted_size */
        if (v->entries[i].encrypted_size < MIN_ENC_SIZE) { e = GECKO_ERR_FORMAT; goto fail; }
        if (v->entries[i].encrypted_size > MAX_DATA_SIZE) { e = GECKO_ERR_FORMAT; goto fail; }
        
        /* Read encrypted name */
        uint8_t niv[12], ntag[16];
        if (fread(niv, 1, 12, f) != 12) { e = GECKO_ERR_FORMAT; goto fail; }
        if (fread(ntag, 1, 16, f) != 16) { e = GECKO_ERR_FORMAT; goto fail; }
        
        uint8_t *ename = malloc(nlen);
        if (!ename) { e = GECKO_ERR_NO_MEMORY; goto fail; }
        
        if (fread(ename, 1, nlen, f) != nlen) {
            gecko_secure_zero(ename, nlen);
            free(ename);
            e = GECKO_ERR_FORMAT;
            goto fail;
        }
        
        e = gecko_gcm_decrypt_simple(v->key, ename, nlen, NULL, 0, niv, ntag,
                                      (uint8_t *)v->entries[i].name);
        gecko_secure_zero(ename, nlen);
        free(ename);
        
        if (e != GECKO_OK) { e = GECKO_ERR_CORRUPTED; goto fail; }
        v->entries[i].name[nlen] = '\0';
        v->count++;
    }
    
    /* Read file data */
    if (v->hdr.data_size > 0 && v->hdr.data_offset > 0) {
        if (fseek(f, (long)v->hdr.data_offset, SEEK_SET) != 0) { e = GECKO_ERR_IO; goto fail; }
        
        for (uint32_t i = 0; i < v->count; i++) {
            size_t enc_len = (size_t)v->entries[i].encrypted_size;
            if (enc_len < MIN_ENC_SIZE || enc_len > SIZE_MAX - 1) { e = GECKO_ERR_FORMAT; goto fail; }
            
            file_data_t *fd = calloc(1, sizeof(file_data_t));
            if (!fd) { e = GECKO_ERR_NO_MEMORY; goto fail; }
            
            fd->enc_len = enc_len;
            fd->enc_data = malloc(enc_len);
            if (!fd->enc_data) { free(fd); e = GECKO_ERR_NO_MEMORY; goto fail; }
            
            if (fread(fd->enc_data, 1, enc_len, f) != enc_len) {
                gecko_secure_zero(fd->enc_data, enc_len);
                free(fd->enc_data);
                free(fd);
                e = GECKO_ERR_FORMAT;
                goto fail;
            }
            
            if (!v->file_data) v->file_data = fd;
            else last_fd->next = fd;
            last_fd = fd;
        }
    }
    
    fclose(f);
    v->open = true;
    *vault = v;
    return GECKO_OK;

fail:
    fclose(f);
    vault_cleanup(v);
    return e;
}

gecko_error_t gecko_vault_save(gecko_vault_t *v) {
    if (!v || !v->open) return GECKO_ERR_INVALID_PARAM;
    
    char tmp[GECKO_MAX_PATH + 8];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", v->path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return GECKO_ERR_INVALID_PARAM;
    
    FILE *f = fopen(tmp, "wb");
    if (!f) return GECKO_ERR_IO;
    
    gecko_error_t e = GECKO_OK;
    
    /* Write header */
    uint8_t hdr[64] = {0};
    memcpy(hdr, MAGIC, 8);
    w32(hdr + 8, v->hdr.version);
    w32(hdr + 12, v->hdr.flags);
    w32(hdr + 16, v->hdr.kdf_iter);
    w32(hdr + 20, v->count);
    
    if (fwrite(hdr, 1, 64, f) != 64) { e = GECKO_ERR_IO; goto fail; }
    if (fwrite(v->salt, 1, 32, f) != 32) { e = GECKO_ERR_IO; goto fail; }
    
    /* Write encrypted key check */
    uint8_t kiv[12], kenc[32], ktag[16];
    e = gecko_random_bytes(kiv, 12);
    if (e != GECKO_OK) goto fail;
    e = gecko_gcm_encrypt_simple(v->key, v->key, 32, NULL, 0, kiv, kenc, ktag);
    if (e != GECKO_OK) goto fail;
    
    if (fwrite(kiv, 1, 12, f) != 12) { e = GECKO_ERR_IO; goto fail; }
    if (fwrite(kenc, 1, 32, f) != 32) { e = GECKO_ERR_IO; goto fail; }
    if (fwrite(ktag, 1, 16, f) != 16) { e = GECKO_ERR_IO; goto fail; }
    
    /* Write entries */
    for (uint32_t i = 0; i < v->count; i++) {
        gecko_vault_entry_t *ent = &v->entries[i];
        size_t nlen = strlen(ent->name);
        if (nlen == 0 || nlen >= GECKO_MAX_FILENAME) { e = GECKO_ERR_INVALID_PARAM; goto fail; }
        
        /* Encrypt metadata */
        uint8_t meta[28], emeta[28], eiv[12], etag[16];
        w32(meta, (uint32_t)nlen);
        w64(meta + 4, ent->size);
        w64(meta + 12, ent->encrypted_size);
        w64(meta + 20, ent->offset);
        
        e = gecko_random_bytes(eiv, 12);
        if (e != GECKO_OK) goto fail;
        e = gecko_gcm_encrypt_simple(v->key, meta, 28, NULL, 0, eiv, emeta, etag);
        if (e != GECKO_OK) goto fail;
        
        if (fwrite(eiv, 1, 12, f) != 12) { e = GECKO_ERR_IO; goto fail; }
        if (fwrite(etag, 1, 16, f) != 16) { e = GECKO_ERR_IO; goto fail; }
        if (fwrite(emeta, 1, 28, f) != 28) { e = GECKO_ERR_IO; goto fail; }
        
        /* Encrypt and write name */
        uint8_t niv[12], ntag[16];
        uint8_t *ename = malloc(nlen);
        if (!ename) { e = GECKO_ERR_NO_MEMORY; goto fail; }
        
        e = gecko_random_bytes(niv, 12);
        if (e != GECKO_OK) { free(ename); goto fail; }
        e = gecko_gcm_encrypt_simple(v->key, (uint8_t *)ent->name, nlen, NULL, 0, niv, ename, ntag);
        if (e != GECKO_OK) { free(ename); goto fail; }
        
        if (fwrite(niv, 1, 12, f) != 12) { free(ename); e = GECKO_ERR_IO; goto fail; }
        if (fwrite(ntag, 1, 16, f) != 16) { free(ename); e = GECKO_ERR_IO; goto fail; }
        if (fwrite(ename, 1, nlen, f) != nlen) { free(ename); e = GECKO_ERR_IO; goto fail; }
        
        gecko_secure_zero(ename, nlen);
        free(ename);
    }
    
    /* Record data offset and write file data */
    long pos = ftell(f);
    if (pos < 0) { e = GECKO_ERR_IO; goto fail; }
    uint64_t data_off = (uint64_t)pos;
    uint64_t data_sz = 0;
    
    file_data_t *fd = v->file_data;
    for (uint32_t i = 0; i < v->count && fd; i++) {
        v->entries[i].offset = data_sz;
        if (fwrite(fd->enc_data, 1, fd->enc_len, f) != fd->enc_len) { e = GECKO_ERR_IO; goto fail; }
        data_sz += fd->enc_len;
        fd = fd->next;
    }
    
    /* Update header with data offset/size */
    if (fseek(f, 24, SEEK_SET) != 0) { e = GECKO_ERR_IO; goto fail; }
    uint8_t off[16];
    w64(off, data_off);
    w64(off + 8, data_sz);
    if (fwrite(off, 1, 16, f) != 16) { e = GECKO_ERR_IO; goto fail; }
    
    /* Ensure data is flushed to disk */
    if (fflush(f) != 0) { e = GECKO_ERR_IO; goto fail; }
    fclose(f);
    f = NULL;
    
    /* Atomic replace */
#ifdef GECKO_WINDOWS
    DeleteFileA(v->path);
    if (!MoveFileA(tmp, v->path)) {
        DeleteFileA(tmp);
        return GECKO_ERR_IO;
    }
#else
    if (rename(tmp, v->path) != 0) {
        unlink(tmp);
        return GECKO_ERR_IO;
    }
#endif
    
    v->dirty = false;
    return GECKO_OK;

fail:
    if (f) fclose(f);
#ifdef GECKO_WINDOWS
    DeleteFileA(tmp);
#else
    unlink(tmp);
#endif
    return e;
}

gecko_error_t gecko_vault_close(gecko_vault_t *v) {
    if (!v) return GECKO_ERR_INVALID_PARAM;
    
    gecko_error_t e = GECKO_OK;
    if (v->dirty) e = gecko_vault_save(v);
    
    vault_cleanup(v);
    return e;
}

gecko_error_t gecko_vault_add(gecko_vault_t *v, const char *filepath, const char *name) {
    if (!v || !v->open || !filepath) return GECKO_ERR_INVALID_PARAM;
    
    const char *fname = name ? name : gecko_basename(filepath);
    if (!fname) return GECKO_ERR_INVALID_PARAM;
    
    size_t name_len = strlen(fname);
    if (name_len == 0 || name_len >= GECKO_MAX_FILENAME) return GECKO_ERR_INVALID_PARAM;
    
    /* Validate filename - no path traversal */
    for (size_t i = 0; i < name_len; i++) {
        char c = fname[i];
        if (c == '/' || c == '\\' || c == ':' || c == '\0') return GECKO_ERR_INVALID_PARAM;
    }
    if (strcmp(fname, ".") == 0 || strcmp(fname, "..") == 0) return GECKO_ERR_INVALID_PARAM;
    
    /* Check duplicate */
    for (uint32_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, fname) == 0) return GECKO_ERR_EXISTS;
    }
    
    /* Check max entries */
    if (v->count >= MAX_ENTRY_COUNT) return GECKO_ERR_NO_SPACE;
    
    /* Read file */
    uint8_t *data = NULL;
    size_t sz = 0;
    gecko_error_t e = gecko_read_file(filepath, &data, &sz);
    if (e != GECKO_OK) return e;
    
    /* Grow entries if needed */
    if (v->count >= v->capacity) {
        if (v->capacity > UINT32_MAX / 2) {
            gecko_secure_zero(data, sz);
            free(data);
            return GECKO_ERR_NO_MEMORY;
        }
        uint32_t nc = v->capacity * 2;
        gecko_vault_entry_t *ne = realloc(v->entries, nc * sizeof(gecko_vault_entry_t));
        if (!ne) {
            gecko_secure_zero(data, sz);
            free(data);
            return GECKO_ERR_NO_MEMORY;
        }
        memset(ne + v->capacity, 0, (nc - v->capacity) * sizeof(gecko_vault_entry_t));
        v->entries = ne;
        v->capacity = nc;
    }
    
    /* Encrypt: IV(12) + ciphertext + tag(16) */
    uint8_t iv[12];
    e = gecko_random_bytes(iv, 12);
    if (e != GECKO_OK) {
        gecko_secure_zero(data, sz);
        free(data);
        return e;
    }
    
    /* Check for overflow */
    if (sz > SIZE_MAX - 28) {
        gecko_secure_zero(data, sz);
        free(data);
        return GECKO_ERR_INVALID_PARAM;
    }
    
    size_t enc_len = 12 + sz + 16;
    uint8_t *enc = malloc(enc_len);
    if (!enc) {
        gecko_secure_zero(data, sz);
        free(data);
        return GECKO_ERR_NO_MEMORY;
    }
    
    memcpy(enc, iv, 12);
    e = gecko_gcm_encrypt_simple(v->key, data, sz, NULL, 0, iv, enc + 12, enc + 12 + sz);
    
    gecko_secure_zero(data, sz);
    free(data);
    
    if (e != GECKO_OK) {
        gecko_secure_zero(enc, enc_len);
        free(enc);
        return e;
    }
    
    /* Store encrypted data */
    file_data_t *fd = calloc(1, sizeof(file_data_t));
    if (!fd) {
        gecko_secure_zero(enc, enc_len);
        free(enc);
        return GECKO_ERR_NO_MEMORY;
    }
    fd->enc_data = enc;
    fd->enc_len = enc_len;
    
    /* Append to list */
    if (!v->file_data) {
        v->file_data = fd;
    } else {
        file_data_t *tail = v->file_data;
        while (tail->next) tail = tail->next;
        tail->next = fd;
    }
    
    /* Add entry */
    gecko_vault_entry_t *ent = &v->entries[v->count];
    memset(ent, 0, sizeof(*ent));
    strncpy(ent->name, fname, sizeof(ent->name) - 1);
    ent->name[sizeof(ent->name) - 1] = '\0';
    ent->size = sz;
    ent->encrypted_size = enc_len;
    
    v->count++;
    v->dirty = true;
    return GECKO_OK;
}

gecko_error_t gecko_vault_extract(gecko_vault_t *v, const char *name, const char *dest) {
    if (!v || !v->open || !name || !dest) return GECKO_ERR_INVALID_PARAM;
    if (strlen(name) == 0 || strlen(dest) == 0) return GECKO_ERR_INVALID_PARAM;
    
    /* Find entry */
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, name) == 0) { idx = i; break; }
    }
    if (idx == UINT32_MAX) return GECKO_ERR_NOT_FOUND;
    
    file_data_t *fd = get_file_data(v, idx);
    if (!fd || !fd->enc_data) return GECKO_ERR_NOT_FOUND;
    if (fd->enc_len < MIN_ENC_SIZE) return GECKO_ERR_FORMAT;
    
    size_t ct_len = fd->enc_len - 12 - 16;
    uint8_t *plain = malloc(ct_len);
    if (!plain) return GECKO_ERR_NO_MEMORY;
    
    gecko_error_t e = gecko_gcm_decrypt_simple(v->key, fd->enc_data + 12, ct_len,
                                                NULL, 0, fd->enc_data,
                                                fd->enc_data + 12 + ct_len, plain);
    if (e != GECKO_OK) {
        gecko_secure_zero(plain, ct_len);
        free(plain);
        return e;
    }
    
    e = gecko_write_file(dest, plain, ct_len);
    gecko_secure_zero(plain, ct_len);
    free(plain);
    return e;
}

gecko_error_t gecko_vault_remove(gecko_vault_t *v, const char *name) {
    if (!v || !v->open || !name) return GECKO_ERR_INVALID_PARAM;
    
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, name) == 0) { idx = i; break; }
    }
    if (idx == UINT32_MAX) return GECKO_ERR_NOT_FOUND;
    
    /* Remove file data from linked list */
    file_data_t *prev = NULL, *fd = v->file_data;
    for (uint32_t i = 0; i < idx && fd; i++) { prev = fd; fd = fd->next; }
    
    if (fd) {
        if (prev) prev->next = fd->next;
        else v->file_data = fd->next;
        
        if (fd->enc_data) {
            gecko_secure_zero(fd->enc_data, fd->enc_len);
            free(fd->enc_data);
        }
        free(fd);
    }
    
    /* Shift entries */
    if (idx < v->count - 1) {
        memmove(&v->entries[idx], &v->entries[idx + 1],
                (v->count - idx - 1) * sizeof(gecko_vault_entry_t));
    }
    memset(&v->entries[v->count - 1], 0, sizeof(gecko_vault_entry_t));
    
    v->count--;
    v->dirty = true;
    return GECKO_OK;
}

gecko_error_t gecko_vault_list(gecko_vault_t *v, gecko_vault_entry_t **entries, uint32_t *count) {
    if (!v || !v->open || !entries || !count) return GECKO_ERR_INVALID_PARAM;
    *entries = v->entries;
    *count = v->count;
    return GECKO_OK;
}

gecko_error_t gecko_vault_stats(gecko_vault_t *v, uint32_t *fc, uint64_t *ts, uint64_t *es) {
    if (!v || !v->open) return GECKO_ERR_INVALID_PARAM;
    
    if (fc) *fc = v->count;
    if (ts) {
        *ts = 0;
        for (uint32_t i = 0; i < v->count; i++) *ts += v->entries[i].size;
    }
    if (es) {
        *es = 0;
        for (uint32_t i = 0; i < v->count; i++) *es += v->entries[i].encrypted_size;
    }
    return GECKO_OK;
}

gecko_error_t gecko_vault_change_password(gecko_vault_t *v, const char *newpw) {
    if (!v || !v->open || !newpw) return GECKO_ERR_INVALID_PARAM;
    if (strlen(newpw) < 8) return GECKO_ERR_INVALID_PARAM;
    
    /* Generate new salt and derive new key */
    uint8_t newsalt[32], newkey[32];
    gecko_error_t e = gecko_random_bytes(newsalt, 32);
    if (e != GECKO_OK) return e;
    
    e = gecko_pbkdf2(newpw, strlen(newpw), newsalt, 32, GECKO_KDF_ITERATIONS, newkey, 32);
    if (e != GECKO_OK) return e;
    
    /* Re-encrypt all file data with new key */
    file_data_t *fd = v->file_data;
    for (uint32_t i = 0; i < v->count && fd; i++) {
        if (fd->enc_len < MIN_ENC_SIZE) {
            gecko_secure_zero(newkey, 32);
            return GECKO_ERR_FORMAT;
        }
        
        size_t ct_len = fd->enc_len - 12 - 16;
        uint8_t *plain = malloc(ct_len);
        if (!plain) {
            gecko_secure_zero(newkey, 32);
            return GECKO_ERR_NO_MEMORY;
        }
        
        /* Decrypt with old key */
        e = gecko_gcm_decrypt_simple(v->key, fd->enc_data + 12, ct_len,
                                      NULL, 0, fd->enc_data,
                                      fd->enc_data + 12 + ct_len, plain);
        if (e != GECKO_OK) {
            gecko_secure_zero(plain, ct_len);
            free(plain);
            gecko_secure_zero(newkey, 32);
            return e;
        }
        
        /* Re-encrypt with new key and fresh IV */
        uint8_t newiv[12];
        e = gecko_random_bytes(newiv, 12);
        if (e != GECKO_OK) {
            gecko_secure_zero(plain, ct_len);
            free(plain);
            gecko_secure_zero(newkey, 32);
            return e;
        }
        
        memcpy(fd->enc_data, newiv, 12);
        e = gecko_gcm_encrypt_simple(newkey, plain, ct_len, NULL, 0, newiv,
                                      fd->enc_data + 12, fd->enc_data + 12 + ct_len);
        
        gecko_secure_zero(plain, ct_len);
        free(plain);
        
        if (e != GECKO_OK) {
            gecko_secure_zero(newkey, 32);
            return e;
        }
        
        fd = fd->next;
    }
    
    /* Update vault key and salt */
    memcpy(v->salt, newsalt, 32);
    gecko_secure_zero(v->key, 32);
    memcpy(v->key, newkey, 32);
    gecko_secure_zero(newkey, 32);
    
    v->dirty = true;
    return GECKO_OK;
}

gecko_error_t gecko_vault_verify(gecko_vault_t *v) {
    if (!v || !v->open) return GECKO_ERR_INVALID_PARAM;
    
    /* Verify all encrypted data can be decrypted */
    file_data_t *fd = v->file_data;
    for (uint32_t i = 0; i < v->count && fd; i++) {
        if (fd->enc_len < MIN_ENC_SIZE) return GECKO_ERR_CORRUPTED;
        
        size_t ct_len = fd->enc_len - 12 - 16;
        uint8_t *test = malloc(ct_len);
        if (!test) return GECKO_ERR_NO_MEMORY;
        
        gecko_error_t e = gecko_gcm_decrypt_simple(v->key, fd->enc_data + 12, ct_len,
                                                    NULL, 0, fd->enc_data,
                                                    fd->enc_data + 12 + ct_len, test);
        gecko_secure_zero(test, ct_len);
        free(test);
        
        if (e != GECKO_OK) return GECKO_ERR_CORRUPTED;
        fd = fd->next;
    }
    
    return GECKO_OK;
}

bool gecko_vault_exists(const char *path) {
    return gecko_file_exists(path);
}

/* ============== Secure Notes ============== */

gecko_error_t gecko_vault_add_note(gecko_vault_t *v, const char *name, const char *content) {
    if (!v || !v->open || !name || !content) return GECKO_ERR_INVALID_PARAM;
    
    size_t len = strlen(content);
    return gecko_vault_add_data(v, name, (const uint8_t *)content, len);
}

gecko_error_t gecko_vault_read_note(gecko_vault_t *v, const char *name, char **content) {
    if (!v || !v->open || !name || !content) return GECKO_ERR_INVALID_PARAM;
    
    uint8_t *data = NULL;
    size_t len = 0;
    
    gecko_error_t e = gecko_vault_read_data(v, name, &data, &len);
    if (e != GECKO_OK) return e;
    
    /* Null-terminate for string use */
    char *str = malloc(len + 1);
    if (!str) {
        gecko_secure_zero(data, len);
        free(data);
        return GECKO_ERR_NO_MEMORY;
    }
    
    memcpy(str, data, len);
    str[len] = '\0';
    
    gecko_secure_zero(data, len);
    free(data);
    
    *content = str;
    return GECKO_OK;
}

/* ============== Data Operations (for clipboard, notes, etc.) ============== */

gecko_error_t gecko_vault_add_data(gecko_vault_t *v, const char *name, const uint8_t *data, size_t len) {
    if (!v || !v->open || !name || !data) return GECKO_ERR_INVALID_PARAM;
    
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= GECKO_MAX_FILENAME) return GECKO_ERR_INVALID_PARAM;
    
    /* Validate name - no path traversal */
    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || c == ':' || c == '\0') return GECKO_ERR_INVALID_PARAM;
    }
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return GECKO_ERR_INVALID_PARAM;
    
    /* Check duplicate */
    for (uint32_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, name) == 0) return GECKO_ERR_EXISTS;
    }
    
    if (v->count >= MAX_ENTRY_COUNT) return GECKO_ERR_NO_SPACE;
    
    /* Grow entries if needed */
    if (v->count >= v->capacity) {
        if (v->capacity > UINT32_MAX / 2) return GECKO_ERR_NO_MEMORY;
        uint32_t nc = v->capacity * 2;
        gecko_vault_entry_t *ne = realloc(v->entries, nc * sizeof(gecko_vault_entry_t));
        if (!ne) return GECKO_ERR_NO_MEMORY;
        memset(ne + v->capacity, 0, (nc - v->capacity) * sizeof(gecko_vault_entry_t));
        v->entries = ne;
        v->capacity = nc;
    }
    
    /* Encrypt: IV(12) + ciphertext + tag(16) */
    uint8_t iv[12];
    gecko_error_t e = gecko_random_bytes(iv, 12);
    if (e != GECKO_OK) return e;
    
    if (len > SIZE_MAX - 28) return GECKO_ERR_INVALID_PARAM;
    
    size_t enc_len = 12 + len + 16;
    uint8_t *enc = malloc(enc_len);
    if (!enc) return GECKO_ERR_NO_MEMORY;
    
    memcpy(enc, iv, 12);
    e = gecko_gcm_encrypt_simple(v->key, data, len, NULL, 0, iv, enc + 12, enc + 12 + len);
    if (e != GECKO_OK) {
        gecko_secure_zero(enc, enc_len);
        free(enc);
        return e;
    }
    
    /* Store encrypted data */
    file_data_t *fd = calloc(1, sizeof(file_data_t));
    if (!fd) {
        gecko_secure_zero(enc, enc_len);
        free(enc);
        return GECKO_ERR_NO_MEMORY;
    }
    fd->enc_data = enc;
    fd->enc_len = enc_len;
    
    /* Append to list */
    if (!v->file_data) {
        v->file_data = fd;
    } else {
        file_data_t *tail = v->file_data;
        while (tail->next) tail = tail->next;
        tail->next = fd;
    }
    
    /* Add entry */
    gecko_vault_entry_t *ent = &v->entries[v->count];
    memset(ent, 0, sizeof(*ent));
    strncpy(ent->name, name, sizeof(ent->name) - 1);
    ent->name[sizeof(ent->name) - 1] = '\0';
    ent->size = len;
    ent->encrypted_size = enc_len;
    
    v->count++;
    v->dirty = true;
    return GECKO_OK;
}

gecko_error_t gecko_vault_read_data(gecko_vault_t *v, const char *name, uint8_t **data, size_t *len) {
    if (!v || !v->open || !name || !data || !len) return GECKO_ERR_INVALID_PARAM;
    
    /* Find entry */
    uint32_t idx = UINT32_MAX;
    for (uint32_t i = 0; i < v->count; i++) {
        if (strcmp(v->entries[i].name, name) == 0) { idx = i; break; }
    }
    if (idx == UINT32_MAX) return GECKO_ERR_NOT_FOUND;
    
    file_data_t *fd = v->file_data;
    for (uint32_t i = 0; i < idx && fd; i++) fd = fd->next;
    if (!fd || !fd->enc_data) return GECKO_ERR_NOT_FOUND;
    if (fd->enc_len < MIN_ENC_SIZE) return GECKO_ERR_FORMAT;
    
    size_t ct_len = fd->enc_len - 12 - 16;
    uint8_t *plain = malloc(ct_len);
    if (!plain) return GECKO_ERR_NO_MEMORY;
    
    gecko_error_t e = gecko_gcm_decrypt_simple(v->key, fd->enc_data + 12, ct_len,
                                                NULL, 0, fd->enc_data,
                                                fd->enc_data + 12 + ct_len, plain);
    if (e != GECKO_OK) {
        gecko_secure_zero(plain, ct_len);
        free(plain);
        return e;
    }
    
    *data = plain;
    *len = ct_len;
    return GECKO_OK;
}

/* ============== Emergency Wipe ============== */

gecko_error_t gecko_vault_emergency_wipe(gecko_vault_t *v) {
    if (!v) return GECKO_ERR_INVALID_PARAM;
    
    /* Overwrite vault file with random data multiple times */
    FILE *f = fopen(v->path, "r+b");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (size > 0) {
            uint8_t *junk = malloc(4096);
            if (junk) {
                /* 3 passes: random, zeros, random */
                for (int pass = 0; pass < 3; pass++) {
                    fseek(f, 0, SEEK_SET);
                    long remaining = size;
                    while (remaining > 0) {
                        size_t chunk = remaining > 4096 ? 4096 : (size_t)remaining;
                        if (pass == 1) {
                            memset(junk, 0, chunk);
                        } else {
                            gecko_random_bytes(junk, chunk);
                        }
                        fwrite(junk, 1, chunk, f);
                        remaining -= chunk;
                    }
                    fflush(f);
                }
                gecko_secure_zero(junk, 4096);
                free(junk);
            }
        }
        fclose(f);
    }
    
    /* Delete the file */
#ifdef GECKO_WINDOWS
    DeleteFileA(v->path);
#else
    unlink(v->path);
#endif
    
    /* Wipe in-memory data */
    gecko_secure_zero(v->key, 32);
    gecko_secure_zero(v->salt, 32);
    
    file_data_t *fd = v->file_data;
    while (fd) {
        file_data_t *next = fd->next;
        if (fd->enc_data) {
            gecko_secure_zero(fd->enc_data, fd->enc_len);
            free(fd->enc_data);
        }
        free(fd);
        fd = next;
    }
    v->file_data = NULL;
    
    if (v->entries) {
        gecko_secure_zero(v->entries, v->capacity * sizeof(gecko_vault_entry_t));
        free(v->entries);
        v->entries = NULL;
    }
    
    v->count = 0;
    v->open = false;
    v->dirty = false;
    
    return GECKO_OK;
}

