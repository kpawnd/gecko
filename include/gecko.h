#ifndef GECKO_H
#define GECKO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version */
#define GECKO_VERSION_MAJOR 1
#define GECKO_VERSION_MINOR 1
#define GECKO_VERSION_PATCH 0
#define GECKO_VERSION_STRING "1.1.0"

/* Platform detection */
#if defined(_WIN32) || defined(_WIN64)
    #define GECKO_WINDOWS 1
    #define GECKO_PATH_SEP '\\'
    #define GECKO_PATH_SEP_STR "\\"
#else
    #define GECKO_LINUX 1
    #define GECKO_PATH_SEP '/'
    #define GECKO_PATH_SEP_STR "/"
#endif

/* Error codes */
typedef enum {
    GECKO_OK = 0,
    GECKO_ERR_INVALID_PARAM = -1,
    GECKO_ERR_NO_MEMORY = -2,
    GECKO_ERR_FILE_NOT_FOUND = -3,
    GECKO_ERR_EXISTS = -4,
    GECKO_ERR_IO = -5,
    GECKO_ERR_CRYPTO = -6,
    GECKO_ERR_AUTH = -7,
    GECKO_ERR_NOT_FOUND = -8,
    GECKO_ERR_FORMAT = -9,
    GECKO_ERR_CORRUPTED = -10,
    GECKO_ERR_NO_SPACE = -11,
    GECKO_ERR_DEVICE = -12,
    GECKO_ERR_PERMISSION = -13,
    GECKO_ERR_NOT_INITIALIZED = -14,
    GECKO_ERR_OVERFLOW = -15,
    GECKO_ERR_NOT_IMPLEMENTED = -16,
} gecko_error_t;

/* Constants */
#define GECKO_AES_KEY_SIZE      32      /* 256 bits */
#define GECKO_AES_BLOCK_SIZE    16      /* 128 bits */
#define GECKO_GCM_NONCE_SIZE    12      /* 96 bits */
#define GECKO_GCM_TAG_SIZE      16      /* 128 bits */
#define GECKO_SALT_SIZE         32      /* 256 bits */
#define GECKO_HASH_SIZE         32      /* SHA-256 */
#define GECKO_KDF_ITERATIONS    600000  /* PBKDF2 iterations */
#define GECKO_VAULT_VERSION     1       /* Vault format version */
#define GECKO_CHUNK_SIZE        (64 * 1024 * 1024)  /* 64 MB */
#define GECKO_MAX_PATH          4096
#define GECKO_MAX_FILENAME      256

/* Directory names */
#define GECKO_DIR_NAME          "GECKO"
#define GECKO_BOOT_DIR          "boot"
#define GECKO_VAULT_DIR         "vault"
#define GECKO_KEYS_DIR          "keys"
#define GECKO_MANIFEST_FILE     "manifest.enc"
#define GECKO_PARAMS_FILE       "params.dat"
#define GECKO_VERIFIER_FILE     "verify.enc"

/* Forward declarations */
typedef struct gecko_vault gecko_vault_t;
typedef struct gecko_file_info gecko_file_info_t;
typedef struct gecko_usb_drive gecko_usb_drive_t;
typedef struct gecko_key_params gecko_key_params_t;

/* Progress callback */
typedef void (*gecko_progress_fn)(uint64_t current, uint64_t total, void *user_data);

/* Include sub-headers */
#include "gecko/crypto.h"
#include "gecko/vault.h"
#include "gecko/usb.h"
#include "gecko/util.h"

/* Error handling */
const char *gecko_error_string(gecko_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* GECKO_H */
