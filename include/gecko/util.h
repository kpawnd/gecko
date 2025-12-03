#ifndef GECKO_UTIL_H
#define GECKO_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Convert bytes to hex string */
gecko_error_t gecko_bytes_to_hex(const uint8_t *bytes, size_t len,
                                  char *hex, size_t hex_len);

/* Convert hex string to bytes */
gecko_error_t gecko_hex_to_bytes(const char *hex, 
                                  uint8_t *bytes, size_t *len);

/* Get file size */
gecko_error_t gecko_file_size(const char *path, uint64_t *size);

/* Check if file exists */
bool gecko_file_exists(const char *path);

/* Check if directory exists */
bool gecko_dir_exists(const char *path);

/* Create directory (and parents) */
gecko_error_t gecko_mkdir_p(const char *path);

/* Read entire file into memory */
gecko_error_t gecko_read_file(const char *path, uint8_t **data, size_t *size);

/* Write data to file */
gecko_error_t gecko_write_file(const char *path, const uint8_t *data, size_t size);

/* Get filename from path */
const char *gecko_basename(const char *path);

/* Get directory from path */
gecko_error_t gecko_dirname(const char *path, char *dir, size_t dir_len);

/* Securely delete file (overwrite then delete) */
gecko_error_t gecko_shred_file(const char *path, int passes);

/* Get text from clipboard */
gecko_error_t gecko_clipboard_get(char **text, size_t *len);

/* Set text to clipboard */
gecko_error_t gecko_clipboard_set(const char *text, size_t len);

/* Hide data inside an image */
gecko_error_t gecko_steg_hide(const char *image_path,
                               const uint8_t *data, size_t len,
                               const char *output_path);

/* Extract hidden data from image */
gecko_error_t gecko_steg_extract(const char *image_path,
                                  uint8_t **data, size_t *len);

/* Get error message string */
const char *gecko_error_string(gecko_error_t err);

#ifdef __cplusplus
}
#endif

#endif
