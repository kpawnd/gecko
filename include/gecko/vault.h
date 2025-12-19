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
    uint64_t created_time;               /* Creation timestamp (Unix epoch) */
    uint64_t expire_time;                /* Expiration timestamp (0 = never) */
    uint32_t flags;                      /* Entry flags (bitfield) */
} gecko_vault_entry_t;

/* Versioning structures */
typedef struct gecko_file_version {
    uint32_t version_id;                 /* Version number (1, 2, 3...) */
    uint64_t timestamp;                  /* When this version was created */
    uint64_t size;                       /* Original file size */
    uint64_t encrypted_size;             /* Encrypted size */
    uint64_t offset;                     /* Offset in vault data section */
    uint8_t  hash[GECKO_HASH_SIZE];      /* SHA-256 hash */
    char     comment[128];               /* Optional version comment */
} gecko_file_version_t;

typedef struct gecko_versioned_entry {
    char name[GECKO_MAX_FILENAME];       /* Base filename */
    uint32_t current_version;            /* Latest version number */
    uint32_t version_count;              /* Total versions stored */
    gecko_file_version_t *versions;      /* Array of versions (max 10) */
    uint64_t expire_time;                /* Expiration timestamp */
    uint32_t flags;                      /* Entry flags */
} gecko_versioned_entry_t;

/* Progress callback for long operations */
typedef void (*gecko_progress_fn)(uint64_t current, uint64_t total, void *user_data);

/* Entry flags */
#define GECKO_ENTRY_FLAG_EXPIRED     (1 << 0)  /* Entry has expired */
#define GECKO_ENTRY_FLAG_AUTO_DELETE (1 << 1)  /* Auto-delete when expired */

/* Versioned entry flags */
#define GECKO_VERSIONED_FLAG_EXPIRED     (1 << 0)
#define GECKO_VERSIONED_FLAG_AUTO_DELETE (1 << 1)

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

/* Search for files by pattern (supports * and ? wildcards) */
gecko_error_t gecko_vault_search(gecko_vault_t *vault,
                                  const char *pattern,
                                  gecko_vault_entry_t **entries,
                                  uint32_t *count);

/* Export all files to a directory */
gecko_error_t gecko_vault_export(gecko_vault_t *vault,
                                  const char *dest_dir);

/* Import entire directory recursively */
gecko_error_t gecko_vault_import(gecko_vault_t *vault,
                                  const char *src_dir,
                                  const char *prefix);

/* Compact vault (remove deleted space) */
gecko_error_t gecko_vault_compact(gecko_vault_t *vault);

/* Create timestamped backup copy */
gecko_error_t gecko_vault_backup(gecko_vault_t *vault,
                                  const char *backup_dir,
                                  char *backup_path,
                                  size_t path_len);

/* Merge another vault into this one */
gecko_error_t gecko_vault_merge(gecko_vault_t *vault,
                                 const char *other_path,
                                 const char *other_password);

/* Merge another vault (with keyfile) into this one */
gecko_error_t gecko_vault_merge_with_keyfile(gecko_vault_t *vault,
                                              const char *other_path,
                                              const char *other_password,
                                              const char *other_keyfile);

/* Print file contents to stdout (cat) */
gecko_error_t gecko_vault_cat(gecko_vault_t *vault,
                               const char *name);

/* Get vault path */
const char *gecko_vault_get_path(gecko_vault_t *vault);

/* Create vault with keyfile (2FA) */
gecko_error_t gecko_vault_create_with_keyfile(const char *path,
                                               const char *password,
                                               const char *keyfile,
                                               gecko_vault_t **vault);

/* Open vault with keyfile */
gecko_error_t gecko_vault_open_with_keyfile(const char *path,
                                             const char *password,
                                             const char *keyfile,
                                             gecko_vault_t **vault);

/* Generate a keyfile */
gecko_error_t gecko_vault_generate_keyfile(const char *path);

/* Check if vault uses keyfile */
bool gecko_vault_uses_keyfile(gecko_vault_t *vault);

/* Enable audit logging */
gecko_error_t gecko_vault_enable_audit(gecko_vault_t *vault,
                                        const char *log_path);

/* Log an audit event */
gecko_error_t gecko_vault_audit_log(gecko_vault_t *vault,
                                     const char *action,
                                     const char *details);

/* Time-based access control functions */
gecko_error_t gecko_vault_add_with_expiry(gecko_vault_t *vault,
                                           const char *filepath,
                                           const char *vault_name,
                                           uint64_t expire_time,
                                           bool auto_delete);

gecko_error_t gecko_vault_set_expiry(gecko_vault_t *vault,
                                      const char *name,
                                      uint64_t expire_time,
                                      bool auto_delete);

gecko_error_t gecko_vault_get_expiry(gecko_vault_t *vault,
                                      const char *name,
                                      uint64_t *expire_time,
                                      bool *auto_delete);

gecko_error_t gecko_vault_cleanup_expired(gecko_vault_t *vault);

/* File versioning functions */
gecko_error_t gecko_vault_add_versioned(gecko_vault_t *vault,
                                         const char *filepath,
                                         const char *vault_name,
                                         const char *comment);

gecko_error_t gecko_vault_list_versions(gecko_vault_t *vault,
                                         const char *name,
                                         gecko_file_version_t **versions,
                                         uint32_t *count);

gecko_error_t gecko_vault_restore_version(gecko_vault_t *vault,
                                           const char *name,
                                           uint32_t version_id,
                                           const char *dest_path);

gecko_error_t gecko_vault_delete_version(gecko_vault_t *vault,
                                          const char *name,
                                          uint32_t version_id);

/* Progress-aware operations */
gecko_error_t gecko_vault_add_with_progress(gecko_vault_t *vault,
                                             const char *filepath,
                                             const char *vault_name,
                                             gecko_progress_fn progress_callback,
                                             void *user_data);

gecko_error_t gecko_vault_extract_with_progress(gecko_vault_t *vault,
                                                 const char *name,
                                                 const char *dest_path,
                                                 gecko_progress_fn progress_callback,
                                                 void *user_data);

gecko_error_t gecko_vault_export_with_progress(gecko_vault_t *vault,
                                                const char *dest_dir,
                                                gecko_progress_fn progress_callback,
                                                void *user_data);

gecko_error_t gecko_vault_import_with_progress(gecko_vault_t *vault,
                                                const char *src_dir,
                                                const char *prefix,
                                                gecko_progress_fn progress_callback,
                                                void *user_data);

#ifdef __cplusplus
}
#endif

#endif
