/*
 * Gecko Utility Functions
 * 
 * Memory, string, and file utilities
 */

#include "gecko.h"
#include "gecko/util.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef GECKO_WINDOWS
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#endif

/*
 * Secure memory wiping - resistant to compiler optimization
 */
void gecko_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
    
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
    
    /* Memory barrier to prevent reordering */
#ifdef _MSC_VER
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/*
 * Constant-time memory comparison (prevents timing attacks)
 */
int gecko_secure_compare(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result == 0 ? 0 : 1;
}

/*
 * Secure memory allocation with automatic zeroing
 */
void *gecko_secure_alloc(size_t size) {
    if (size == 0 || size > SIZE_MAX - sizeof(size_t)) return NULL;
    
    /* Allocate with extra space for size storage */
    size_t total = size + sizeof(size_t);
    uint8_t *ptr = (uint8_t *)malloc(total);
    if (!ptr) return NULL;
    
    /* Store size at beginning */
    memcpy(ptr, &size, sizeof(size_t));
    
    /* Zero the user portion */
    memset(ptr + sizeof(size_t), 0, size);
    
    return ptr + sizeof(size_t);
}

/*
 * Secure memory free with zeroing
 */
void gecko_secure_free(void *ptr) {
    if (!ptr) return;
    
    /* Retrieve size from before pointer */
    uint8_t *real_ptr = (uint8_t *)ptr - sizeof(size_t);
    size_t size;
    memcpy(&size, real_ptr, sizeof(size_t));
    
    /* Zero entire allocation including size */
    gecko_secure_zero(real_ptr, size + sizeof(size_t));
    
    free(real_ptr);
}

/*
 * Convert bytes to hexadecimal string
 */
gecko_error_t gecko_bytes_to_hex(const uint8_t *bytes, size_t len,
                                  char *hex, size_t hex_len) {
    if (!bytes || !hex) return GECKO_ERR_INVALID_PARAM;
    if (len > SIZE_MAX / 2 - 1) return GECKO_ERR_INVALID_PARAM;  /* Overflow check */
    if (hex_len < len * 2 + 1) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    static const char hex_chars[] = "0123456789abcdef";
    
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
    
    return GECKO_OK;
}

/*
 * Convert hexadecimal string to bytes
 */
gecko_error_t gecko_hex_to_bytes(const char *hex, uint8_t *bytes, size_t *len) {
    if (!hex || !bytes || !len) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || *len < hex_len / 2) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    for (size_t i = 0; i < hex_len / 2; i++) {
        uint8_t high, low;
        char c;
        
        c = hex[i * 2];
        if (c >= '0' && c <= '9') high = c - '0';
        else if (c >= 'a' && c <= 'f') high = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') high = c - 'A' + 10;
        else return GECKO_ERR_INVALID_PARAM;
        
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') low = c - '0';
        else if (c >= 'a' && c <= 'f') low = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') low = c - 'A' + 10;
        else return GECKO_ERR_INVALID_PARAM;
        
        bytes[i] = (high << 4) | low;
    }
    
    *len = hex_len / 2;
    return GECKO_OK;
}

/*
 * Get file size
 */
gecko_error_t gecko_file_size(const char *path, uint64_t *size) {
    if (!path || !size) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
#ifdef GECKO_WINDOWS
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &attr)) {
        return GECKO_ERR_FILE_NOT_FOUND;
    }
    *size = ((uint64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return GECKO_ERR_FILE_NOT_FOUND;
    }
    *size = st.st_size;
#endif
    
    return GECKO_OK;
}

/*
 * Check if file exists
 */
bool gecko_file_exists(const char *path) {
    if (!path) return false;
    
#ifdef GECKO_WINDOWS
    DWORD attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

/*
 * Check if directory exists
 */
bool gecko_dir_exists(const char *path) {
    if (!path) return false;
    
#ifdef GECKO_WINDOWS
    DWORD attr = GetFileAttributesA(path);
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

/*
 * Create directory (including parents)
 */
gecko_error_t gecko_mkdir_p(const char *path) {
    if (!path) return GECKO_ERR_INVALID_PARAM;
    
    char tmp[GECKO_MAX_PATH];
    size_t len = strlen(path);
    
    if (len >= sizeof(tmp)) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    strcpy(tmp, path);
    
    /* Remove trailing slash */
    if (len > 0 && (tmp[len - 1] == '/' || tmp[len - 1] == '\\')) {
        tmp[len - 1] = '\0';
    }
    
    /* Create each directory in path */
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            
            if (!gecko_dir_exists(tmp)) {
#ifdef GECKO_WINDOWS
                if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    return GECKO_ERR_IO;
                }
#else
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                    return GECKO_ERR_IO;
                }
#endif
            }
            
            *p = '/';
        }
    }
    
    /* Create final directory */
    if (!gecko_dir_exists(tmp)) {
#ifdef GECKO_WINDOWS
        if (!CreateDirectoryA(tmp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return GECKO_ERR_IO;
        }
#else
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return GECKO_ERR_IO;
        }
#endif
    }
    
    return GECKO_OK;
}

/*
 * Read entire file into memory
 */
gecko_error_t gecko_read_file(const char *path, uint8_t **data, size_t *size) {
    if (!path || !data || !size) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    uint64_t file_size;
    gecko_error_t err = gecko_file_size(path, &file_size);
    if (err != GECKO_OK) return err;
    
    /* Check for reasonable size */
    if (file_size > SIZE_MAX || file_size > 1024 * 1024 * 1024) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    FILE *f = fopen(path, "rb");
    if (!f) return GECKO_ERR_FILE_NOT_FOUND;
    
    *data = (uint8_t *)malloc((size_t)file_size);
    if (!*data) {
        fclose(f);
        return GECKO_ERR_NO_MEMORY;
    }
    
    size_t read = fread(*data, 1, (size_t)file_size, f);
    fclose(f);
    
    if (read != (size_t)file_size) {
        free(*data);
        *data = NULL;
        return GECKO_ERR_IO;
    }
    
    *size = (size_t)file_size;
    return GECKO_OK;
}

/*
 * Write data to file
 */
gecko_error_t gecko_write_file(const char *path, const uint8_t *data, size_t size) {
    if (!path || (!data && size > 0)) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    FILE *f = fopen(path, "wb");
    if (!f) return GECKO_ERR_IO;
    
    if (size > 0) {
        size_t written = fwrite(data, 1, size, f);
        if (written != size) {
            fclose(f);
            return GECKO_ERR_IO;
        }
    }
    
    fclose(f);
    return GECKO_OK;
}

/*
 * Get filename from path
 */
const char *gecko_basename(const char *path) {
    if (!path) return NULL;
    
    const char *last_sep = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            last_sep = p;
        }
    }
    
    return last_sep ? last_sep + 1 : path;
}

/*
 * Get directory from path
 */
gecko_error_t gecko_dirname(const char *path, char *dir, size_t dir_len) {
    if (!path || !dir || dir_len == 0) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    const char *last_sep = NULL;
    
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            last_sep = p;
        }
    }
    
    if (!last_sep) {
        if (dir_len < 2) return GECKO_ERR_INVALID_PARAM;
        strcpy(dir, ".");
        return GECKO_OK;
    }
    
    size_t dir_size = last_sep - path;
    if (dir_size == 0) dir_size = 1; /* Root directory */
    
    if (dir_len <= dir_size) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    memcpy(dir, path, dir_size);
    dir[dir_size] = '\0';
    
    return GECKO_OK;
}

/*
 * Format error message
 */
const char *gecko_error_string(gecko_error_t err) {
    switch (err) {
        case GECKO_OK:                return "Success";
        case GECKO_ERR_INVALID_PARAM: return "Invalid parameter";
        case GECKO_ERR_NO_MEMORY:     return "Out of memory";
        case GECKO_ERR_IO:            return "I/O error";
        case GECKO_ERR_CRYPTO:        return "Cryptographic error";
        case GECKO_ERR_AUTH:          return "Authentication failed";
        case GECKO_ERR_NOT_FOUND:     return "Not found";
        case GECKO_ERR_EXISTS:        return "Already exists";
        case GECKO_ERR_FORMAT:        return "Invalid format";
        case GECKO_ERR_PERMISSION:    return "Permission denied";
        case GECKO_ERR_DEVICE:        return "Device error";
        case GECKO_ERR_FILE_NOT_FOUND: return "File not found";
        case GECKO_ERR_NO_SPACE:      return "No space";
        case GECKO_ERR_CORRUPTED:     return "Data corrupted";
        default:                      return "Unknown error";
    }
}

/* ============== Secure File Shredding ============== */

gecko_error_t gecko_shred_file(const char *path, int passes) {
    if (!path || passes < 1) return GECKO_ERR_INVALID_PARAM;
    if (passes > 10) passes = 10;  /* Cap at 10 passes */
    
    uint64_t size;
    gecko_error_t e = gecko_file_size(path, &size);
    if (e != GECKO_OK) return e;
    
    FILE *f = fopen(path, "r+b");
    if (!f) return GECKO_ERR_IO;
    
    uint8_t *buf = malloc(4096);
    if (!buf) { fclose(f); return GECKO_ERR_NO_MEMORY; }
    
    /* Multiple overwrite passes */
    for (int pass = 0; pass < passes; pass++) {
        fseek(f, 0, SEEK_SET);
        uint64_t remaining = size;
        
        while (remaining > 0) {
            size_t chunk = remaining > 4096 ? 4096 : (size_t)remaining;
            
            /* Alternate: random, 0x00, 0xFF, random */
            switch (pass % 4) {
                case 0: case 3:
                    gecko_random_bytes(buf, chunk);
                    break;
                case 1:
                    memset(buf, 0x00, chunk);
                    break;
                case 2:
                    memset(buf, 0xFF, chunk);
                    break;
            }
            
            if (fwrite(buf, 1, chunk, f) != chunk) {
                gecko_secure_zero(buf, 4096);
                free(buf);
                fclose(f);
                return GECKO_ERR_IO;
            }
            remaining -= chunk;
        }
        fflush(f);
    }
    
    gecko_secure_zero(buf, 4096);
    free(buf);
    fclose(f);
    
    /* Delete the file */
#ifdef GECKO_WINDOWS
    return DeleteFileA(path) ? GECKO_OK : GECKO_ERR_IO;
#else
    return unlink(path) == 0 ? GECKO_OK : GECKO_ERR_IO;
#endif
}

/* ============== Clipboard Operations ============== */

#ifdef GECKO_WINDOWS

gecko_error_t gecko_clipboard_get(char **text, size_t *len) {
    if (!text || !len) return GECKO_ERR_INVALID_PARAM;
    
    *text = NULL;
    *len = 0;
    
    if (!OpenClipboard(NULL)) return GECKO_ERR_IO;
    
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) {
        CloseClipboard();
        return GECKO_ERR_NOT_FOUND;
    }
    
    char *data = (char *)GlobalLock(h);
    if (!data) {
        CloseClipboard();
        return GECKO_ERR_IO;
    }
    
    size_t data_len = strlen(data);
    char *copy = malloc(data_len + 1);
    if (!copy) {
        GlobalUnlock(h);
        CloseClipboard();
        return GECKO_ERR_NO_MEMORY;
    }
    
    memcpy(copy, data, data_len + 1);
    GlobalUnlock(h);
    CloseClipboard();
    
    *text = copy;
    *len = data_len;
    return GECKO_OK;
}

gecko_error_t gecko_clipboard_set(const char *text, size_t len) {
    if (!text) return GECKO_ERR_INVALID_PARAM;
    if (len == 0) len = strlen(text);
    
    if (!OpenClipboard(NULL)) return GECKO_ERR_IO;
    EmptyClipboard();
    
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (!h) {
        CloseClipboard();
        return GECKO_ERR_NO_MEMORY;
    }
    
    char *data = (char *)GlobalLock(h);
    if (!data) {
        GlobalFree(h);
        CloseClipboard();
        return GECKO_ERR_IO;
    }
    
    memcpy(data, text, len);
    data[len] = '\0';
    GlobalUnlock(h);
    
    if (!SetClipboardData(CF_TEXT, h)) {
        GlobalFree(h);
        CloseClipboard();
        return GECKO_ERR_IO;
    }
    
    CloseClipboard();
    return GECKO_OK;
}

#else /* Linux */

gecko_error_t gecko_clipboard_get(char **text, size_t *len) {
    if (!text || !len) return GECKO_ERR_INVALID_PARAM;
    
    *text = NULL;
    *len = 0;
    
    /* Try xclip first, then xsel */
    FILE *p = popen("xclip -selection clipboard -o 2>/dev/null || xsel -b -o 2>/dev/null", "r");
    if (!p) return GECKO_ERR_IO;
    
    size_t capacity = 4096;
    size_t size = 0;
    char *buf = malloc(capacity);
    if (!buf) { pclose(p); return GECKO_ERR_NO_MEMORY; }
    
    while (!feof(p)) {
        if (size + 1024 > capacity) {
            capacity *= 2;
            char *newbuf = realloc(buf, capacity);
            if (!newbuf) { free(buf); pclose(p); return GECKO_ERR_NO_MEMORY; }
            buf = newbuf;
        }
        size_t n = fread(buf + size, 1, 1024, p);
        size += n;
        if (n < 1024) break;
    }
    
    pclose(p);
    
    if (size == 0) {
        free(buf);
        return GECKO_ERR_NOT_FOUND;
    }
    
    buf[size] = '\0';
    *text = buf;
    *len = size;
    return GECKO_OK;
}

gecko_error_t gecko_clipboard_set(const char *text, size_t len) {
    if (!text) return GECKO_ERR_INVALID_PARAM;
    if (len == 0) len = strlen(text);
    
    /* Try xclip first, then xsel */
    FILE *p = popen("xclip -selection clipboard 2>/dev/null || xsel -b -i 2>/dev/null", "w");
    if (!p) return GECKO_ERR_IO;
    
    size_t written = fwrite(text, 1, len, p);
    int ret = pclose(p);
    
    return (written == len && ret == 0) ? GECKO_OK : GECKO_ERR_IO;
}

#endif

/* ============== Steganography (LSB in PNG/BMP) ============== */

/* Simple LSB steganography - hides data in least significant bits of image pixels */

gecko_error_t gecko_steg_hide(const char *image_path, const uint8_t *data, size_t len,
                              const char *output_path) {
    if (!image_path || !data || !output_path || len == 0) return GECKO_ERR_INVALID_PARAM;
    
    /* Read image file */
    uint8_t *img = NULL;
    size_t img_size = 0;
    gecko_error_t e = gecko_read_file(image_path, &img, &img_size);
    if (e != GECKO_OK) return e;
    
    /* Check if BMP (simple case - uncompressed) */
    if (img_size < 54 || img[0] != 'B' || img[1] != 'M') {
        free(img);
        return GECKO_ERR_FORMAT;  /* Only BMP supported for now */
    }
    
    /* Parse BMP header */
    uint32_t data_offset = img[10] | (img[11] << 8) | (img[12] << 16) | (img[13] << 24);
    uint32_t pixel_size = img_size - data_offset;
    
    /* Need 8 pixels per byte (1 bit per pixel) + 32 bits for length header */
    size_t needed_pixels = (len + 4) * 8;
    if (needed_pixels > pixel_size) {
        free(img);
        return GECKO_ERR_NO_SPACE;  /* Image too small */
    }
    
    /* Write length header (4 bytes, little-endian) */
    uint8_t *pixels = img + data_offset;
    uint32_t data_len = (uint32_t)len;
    
    for (int i = 0; i < 32; i++) {
        uint8_t bit = (data_len >> i) & 1;
        pixels[i] = (pixels[i] & 0xFE) | bit;
    }
    
    /* Write data bits */
    for (size_t i = 0; i < len; i++) {
        for (int b = 0; b < 8; b++) {
            uint8_t bit = (data[i] >> b) & 1;
            pixels[32 + i * 8 + b] = (pixels[32 + i * 8 + b] & 0xFE) | bit;
        }
    }
    
    /* Write output */
    e = gecko_write_file(output_path, img, img_size);
    free(img);
    return e;
}

gecko_error_t gecko_steg_extract(const char *image_path, uint8_t **data, size_t *len) {
    if (!image_path || !data || !len) return GECKO_ERR_INVALID_PARAM;
    
    *data = NULL;
    *len = 0;
    
    /* Read image file */
    uint8_t *img = NULL;
    size_t img_size = 0;
    gecko_error_t e = gecko_read_file(image_path, &img, &img_size);
    if (e != GECKO_OK) return e;
    
    /* Check BMP */
    if (img_size < 54 || img[0] != 'B' || img[1] != 'M') {
        free(img);
        return GECKO_ERR_FORMAT;
    }
    
    uint32_t data_offset = img[10] | (img[11] << 8) | (img[12] << 16) | (img[13] << 24);
    uint32_t pixel_size = img_size - data_offset;
    
    if (pixel_size < 32) {
        free(img);
        return GECKO_ERR_FORMAT;
    }
    
    uint8_t *pixels = img + data_offset;
    
    /* Read length header */
    uint32_t data_len = 0;
    for (int i = 0; i < 32; i++) {
        data_len |= ((uint32_t)(pixels[i] & 1)) << i;
    }
    
    /* Sanity check */
    if (data_len == 0 || data_len > 100 * 1024 * 1024 || (data_len + 4) * 8 > pixel_size) {
        free(img);
        return GECKO_ERR_FORMAT;
    }
    
    /* Allocate and read data */
    uint8_t *result = malloc(data_len);
    if (!result) {
        free(img);
        return GECKO_ERR_NO_MEMORY;
    }
    
    for (size_t i = 0; i < data_len; i++) {
        result[i] = 0;
        for (int b = 0; b < 8; b++) {
            result[i] |= ((pixels[32 + i * 8 + b] & 1)) << b;
        }
    }
    
    free(img);
    *data = result;
    *len = data_len;
    return GECKO_OK;
}

