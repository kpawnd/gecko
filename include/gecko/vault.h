#ifndef GECKO_VAULT_H
#define GECKO_VAULT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gecko_vault_entry {
    char     name[GECKO_MAX_FILENAME];   /* Filename in vault */
    uint64_t size;                       /* Original file size */
    uint64_t encrypted_size;             /* Encrypted size */
    uint64_t offset;                     /* Offset in vault data section */
    uint8_t  hash[GECKO_HASH_SIZE];      /* SHA-256 hash for lookup */
} gecko_vault_entry_t;

/* Forward declaration - vault is opaque */
typedef struct gecko_vault gecko_vault_t;

/* Create a new encrypted vault */
gecko_error_t gecko_vault_create(const char *path,
                                  const char *password,
                                  gecko_vault_t **vault);

/* Open an existing vault */
gecko_error_t gecko_vault_open(const char *path,
                                const char *password,
                                gecko_vault_t **vault);

/* Save vault to disk */
gecko_error_t gecko_vault_save(gecko_vault_t *vault);

/* Close vault and free resources */
gecko_error_t gecko_vault_close(gecko_vault_t *vault);

/* Check if vault exists */
bool gecko_vault_exists(const char *path);

/* Add file to vault */
gecko_error_t gecko_vault_add(gecko_vault_t *vault,
                               const char *filepath,
                               const char *vault_name);

/* Extract file from vault */
gecko_error_t gecko_vault_extract(gecko_vault_t *vault,
                                   const char *name,
                                   const char *dest_path);

/* Remove file from vault */
gecko_error_t gecko_vault_remove(gecko_vault_t *vault,
                                  const char *name);

/* List vault contents */
gecko_error_t gecko_vault_list(gecko_vault_t *vault,
                                gecko_vault_entry_t **entries,
                                uint32_t *count);

/* Get vault statistics */
gecko_error_t gecko_vault_stats(gecko_vault_t *vault,
                                 uint32_t *file_count,
                                 uint64_t *total_size,
                                 uint64_t *encrypted_size);

/* Change vault password */
gecko_error_t gecko_vault_change_password(gecko_vault_t *vault,
                                           const char *new_password);

/* Verify vault integrity */
gecko_error_t gecko_vault_verify(gecko_vault_t *vault);

/* Add encrypted text note */
gecko_error_t gecko_vault_add_note(gecko_vault_t *vault,
                                    const char *name,
                                    const char *content);

/* Read decrypted note */
gecko_error_t gecko_vault_read_note(gecko_vault_t *vault,
                                     const char *name,
                                     char **content);

/* Add data directly from memory (for clipboard) */
gecko_error_t gecko_vault_add_data(gecko_vault_t *vault,
                                    const char *name,
                                    const uint8_t *data,
                                    size_t len);

/* Read data to memory */
gecko_error_t gecko_vault_read_data(gecko_vault_t *vault,
                                     const char *name,
                                     uint8_t **data,
                                     size_t *len);

/* Emergency wipe - destroy all vault data */
gecko_error_t gecko_vault_emergency_wipe(gecko_vault_t *vault);

#ifdef __cplusplus
}
#endif

#endif
