/*
 * Gecko Utility Functions
 * 
 * Memory, string, and file utilities
 */

#include "gecko.h"
#include "gecko/util.h"
#include "gecko/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#ifdef GECKO_WINDOWS
#include <windows.h>
#define gecko_strdup _strdup
#else
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <limits.h>
#include <fcntl.h>
#define gecko_strdup strdup
#endif

/*
 * Get current Unix timestamp
 */
uint64_t get_current_time(void) {
    return (uint64_t)time(NULL);
}

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
 * Read file with progress callback
 */
gecko_error_t gecko_read_file_progress(const char *path, uint8_t **data, size_t *size,
                                        void (*progress)(uint64_t current, uint64_t total, void *user_data),
                                        void *user_data) {
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
    
    size_t total_read = 0;
    size_t chunk_size = 64 * 1024;  // 64KB chunks
    
    while (total_read < (size_t)file_size) {
        size_t to_read = chunk_size;
        if (total_read + to_read > (size_t)file_size) {
            to_read = (size_t)file_size - total_read;
        }
        
        size_t read = fread(*data + total_read, 1, to_read, f);
        if (read != to_read) {
            free(*data);
            *data = NULL;
            fclose(f);
            return GECKO_ERR_IO;
        }
        
        total_read += read;
        
        if (progress) {
            progress((uint64_t)total_read, file_size, user_data);
        }
    }
    
    fclose(f);
    *size = (size_t)file_size;
    return GECKO_OK;
}

/*
 * Write file with progress callback
 */
gecko_error_t gecko_write_file_progress(const char *path, const uint8_t *data, size_t size,
                                         void (*progress)(uint64_t current, uint64_t total, void *user_data),
                                         void *user_data) {
    if (!path || (!data && size > 0)) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    FILE *f = fopen(path, "wb");
    if (!f) return GECKO_ERR_IO;
    
    size_t total_written = 0;
    size_t chunk_size = 64 * 1024;  // 64KB chunks
    
    while (total_written < size) {
        size_t to_write = chunk_size;
        if (total_written + to_write > size) {
            to_write = size - total_written;
        }
        
        size_t written = fwrite(data + total_written, 1, to_write, f);
        if (written != to_write) {
            fclose(f);
            return GECKO_ERR_IO;
        }
        
        total_written += written;
        
        if (progress) {
            progress((uint64_t)total_written, (uint64_t)size, user_data);
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
    
    /* Get clipboard data size from global handle */
    size_t data_len = GlobalSize(h);
    if (data_len > 0 && data[data_len - 1] == '\0') {
        data_len--; /* Remove null terminator if present */
    }
    
    char *copy = malloc(data_len + 1);
    if (!copy) {
        GlobalUnlock(h);
        CloseClipboard();
        return GECKO_ERR_NO_MEMORY;
    }
    
    memcpy(copy, data, data_len);
    copy[data_len] = '\0';  /* Ensure null termination */
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

static int command_exists(const char *cmd) {
    char path[PATH_MAX];
    if (strchr(cmd, '/')) {
        return access(cmd, X_OK) == 0;
    }
    char *path_env = getenv("PATH");
    if (!path_env) return 0;
    
    char *path_copy = strdup(path_env);
    if (!path_copy) return 0;
    
    int found = 0;
    char *dir = strtok(path_copy, ":");
    while (dir) {
        snprintf(path, sizeof(path), "%s/%s", dir, cmd);
        if (access(path, X_OK) == 0) {
            found = 1;
            break;
        }
        dir = strtok(NULL, ":");
    }
    free(path_copy);
    return found;
}

static FILE *safe_popen(const char *cmd, const char *mode) {
    if (!cmd || !mode) return NULL;
    
    // Split command into arguments safely
    char *cmd_copy = strdup(cmd);
    if (!cmd_copy) return NULL;
    
    char *args[4] = {NULL}; // Max 3 args + NULL
    int arg_count = 0;
    
    char *token = strtok(cmd_copy, " ");
    while (token && arg_count < 3) {
        args[arg_count++] = token;
        token = strtok(NULL, " ");
    }
    
    if (arg_count == 0) {
        free(cmd_copy);
        return NULL;
    }
    
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        free(cmd_copy);
        return NULL;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(cmd_copy);
        return NULL;
    }
    
    if (pid == 0) { // Child
        close(pipefd[strcmp(mode, "r") == 0 ? 0 : 1]);
        dup2(pipefd[strcmp(mode, "r") == 0 ? 1 : 0], strcmp(mode, "r") == 0 ? 1 : 0);
        close(pipefd[strcmp(mode, "r") == 0 ? 1 : 0]);
        
        execvp(args[0], args);
        _exit(127); // Command not found
    } else { // Parent
        close(pipefd[strcmp(mode, "r") == 0 ? 1 : 0]);
        free(cmd_copy);
        return fdopen(pipefd[strcmp(mode, "r") == 0 ? 0 : 1], mode);
    }
}

gecko_error_t gecko_clipboard_get(char **text, size_t *len) {
    if (!text || !len) return GECKO_ERR_INVALID_PARAM;
    
    *text = NULL;
    *len = 0;
    
    FILE *p = NULL;
    
    /* Try xclip first, then xsel - check availability first */
    if (command_exists("xclip")) {
        p = safe_popen("xclip -selection clipboard -o", "r");
    } else if (command_exists("xsel")) {
        p = safe_popen("xsel -b -o", "r");
    }
    
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
    
    FILE *p = NULL;
    
    /* Try xclip first, then xsel - check availability first */
    if (command_exists("xclip")) {
        p = safe_popen("xclip -selection clipboard", "w");
    } else if (command_exists("xsel")) {
        p = safe_popen("xsel -b -i", "w");
    }
    
    if (!p) return GECKO_ERR_IO;
    
    size_t written = fwrite(text, 1, len, p);
    int ret = pclose(p);
    
    return (written == len && ret == 0) ? GECKO_OK : GECKO_ERR_IO;
}

#endif

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
    uint32_t pixel_size = (uint32_t)(img_size - data_offset);
    
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
    uint32_t pixel_size = (uint32_t)(img_size - data_offset);
    
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

#ifdef GECKO_WINDOWS

gecko_error_t gecko_list_dir(const char *path, char ***files, uint32_t *count) {
    if (!path || !files || !count) return GECKO_ERR_INVALID_PARAM;
    
    *files = NULL;
    *count = 0;
    
    char search_path[GECKO_MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search_path, &fd);
    if (h == INVALID_HANDLE_VALUE) return GECKO_ERR_FILE_NOT_FOUND;
    
    /* Count files first */
    uint32_t n = 0;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || 
            (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0'))) continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) n++;
    } while (FindNextFileA(h, &fd));
    
    if (n == 0) { FindClose(h); return GECKO_OK; }
    
    /* Allocate array */
    char **result = calloc(n, sizeof(char *));
    if (!result) { FindClose(h); return GECKO_ERR_NO_MEMORY; }
    
    /* Restart and fill */
    h = FindFirstFileA(search_path, &fd);
    uint32_t i = 0;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || 
            (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0'))) continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char full[GECKO_MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", path, fd.cFileName);
            result[i] = gecko_strdup(full);
            if (!result[i]) {
                gecko_free_file_list(result, i);
                FindClose(h);
                return GECKO_ERR_NO_MEMORY;
            }
            i++;
        }
    } while (FindNextFileA(h, &fd) && i < n);
    
    FindClose(h);
    *files = result;
    *count = i;
    return GECKO_OK;
}

static gecko_error_t list_recursive_internal(const char *path, char ***files, 
                                              uint32_t *count, uint32_t *capacity) {
    char search_path[GECKO_MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search_path, &fd);
    if (h == INVALID_HANDLE_VALUE) return GECKO_OK;
    
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' || 
            (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0'))) continue;
        
        char full[GECKO_MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", path, fd.cFileName);
        
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            list_recursive_internal(full, files, count, capacity);
        } else {
            if (*count >= *capacity) {
                uint32_t new_cap = *capacity * 2;
                char **new_files = realloc(*files, new_cap * sizeof(char *));
                if (!new_files) { FindClose(h); return GECKO_ERR_NO_MEMORY; }
                *files = new_files;
                *capacity = new_cap;
            }
            (*files)[*count] = gecko_strdup(full);
            if (!(*files)[*count]) { FindClose(h); return GECKO_ERR_NO_MEMORY; }
            (*count)++;
        }
    } while (FindNextFileA(h, &fd));
    
    FindClose(h);
    return GECKO_OK;
}

#else /* Linux/Unix */

#include <dirent.h>
#include <sys/types.h>

gecko_error_t gecko_list_dir(const char *path, char ***files, uint32_t *count) {
    if (!path || !files || !count) return GECKO_ERR_INVALID_PARAM;
    
    *files = NULL;
    *count = 0;
    
    DIR *d = opendir(path);
    if (!d) return GECKO_ERR_FILE_NOT_FOUND;
    
    /* Count files first */
    uint32_t n = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[GECKO_MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) n++;
    }
    
    if (n == 0) { closedir(d); return GECKO_OK; }
    
    /* Allocate and fill */
    char **result = calloc(n, sizeof(char *));
    if (!result) { closedir(d); return GECKO_ERR_NO_MEMORY; }
    
    rewinddir(d);
    uint32_t i = 0;
    while ((ent = readdir(d)) != NULL && i < n) {
        if (ent->d_name[0] == '.') continue;
        char full[GECKO_MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            result[i] = gecko_strdup(full);
            if (!result[i]) {
                gecko_free_file_list(result, i);
                closedir(d);
                return GECKO_ERR_NO_MEMORY;
            }
            i++;
        }
    }
    
    closedir(d);
    *files = result;
    *count = i;
    return GECKO_OK;
}

static gecko_error_t list_recursive_internal(const char *path, char ***files, 
                                              uint32_t *count, uint32_t *capacity) {
    DIR *d = opendir(path);
    if (!d) return GECKO_OK;
    
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        
        char full[GECKO_MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        
        struct stat st;
        if (stat(full, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            list_recursive_internal(full, files, count, capacity);
        } else if (S_ISREG(st.st_mode)) {
            if (*count >= *capacity) {
                uint32_t new_cap = *capacity * 2;
                char **new_files = realloc(*files, new_cap * sizeof(char *));
                if (!new_files) { closedir(d); return GECKO_ERR_NO_MEMORY; }
                *files = new_files;
                *capacity = new_cap;
            }
            (*files)[*count] = gecko_strdup(full);
            if (!(*files)[*count]) { closedir(d); return GECKO_ERR_NO_MEMORY; }
            (*count)++;
        }
    }
    
    closedir(d);
    return GECKO_OK;
}

#endif

gecko_error_t gecko_list_dir_recursive(const char *path, char ***files, uint32_t *count) {
    if (!path || !files || !count) return GECKO_ERR_INVALID_PARAM;
    
    *files = NULL;
    *count = 0;
    
    uint32_t capacity = 64;
    char **result = calloc(capacity, sizeof(char *));
    if (!result) return GECKO_ERR_NO_MEMORY;
    
    gecko_error_t e = list_recursive_internal(path, &result, count, &capacity);
    if (e != GECKO_OK) {
        gecko_free_file_list(result, *count);
        *files = NULL;
        *count = 0;
        return e;
    }
    
    *files = result;
    return GECKO_OK;
}

void gecko_free_file_list(char **files, uint32_t count) {
    if (!files) return;
    for (uint32_t i = 0; i < count; i++) {
        free(files[i]);
    }
    free(files);
}

/* Pattern matching (supports * and ?) */
bool gecko_pattern_match(const char *pattern, const char *str) {
    if (!pattern || !str) return false;
    
    while (*pattern && *str) {
        if (*pattern == '*') {
            pattern++;
            if (*pattern == '\0') return true;
            while (*str) {
                if (gecko_pattern_match(pattern, str)) return true;
                str++;
            }
            return false;
        } else if (*pattern == '?' || *pattern == *str) {
            pattern++;
            str++;
        } else {
            return false;
        }
    }
    
    while (*pattern == '*') pattern++;
    return *pattern == '\0' && *str == '\0';
}

/* Get current timestamp string */
gecko_error_t gecko_timestamp_string(char *buf, size_t len) {
    if (!buf || len < 16) return GECKO_ERR_INVALID_PARAM;
    
#ifdef GECKO_WINDOWS
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, len, "%04d%02d%02d_%02d%02d%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
#else
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (!tm) return GECKO_ERR_IO;
    snprintf(buf, len, "%04d%02d%02d_%02d%02d%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
#endif
    return GECKO_OK;
}

/* Combine keyfile with password for 2FA */
gecko_error_t gecko_combine_keyfile(const char *password, const char *keyfile_path,
                                     uint8_t *combined_key, size_t key_len) {
    if (!password || !keyfile_path || !combined_key || key_len < 32)
        return GECKO_ERR_INVALID_PARAM;
    
    /* Read keyfile */
    uint8_t *keydata = NULL;
    size_t keydata_len = 0;
    gecko_error_t e = gecko_read_file(keyfile_path, &keydata, &keydata_len);
    if (e != GECKO_OK) return e;
    
    if (keydata_len < 32) {
        free(keydata);
        return GECKO_ERR_FORMAT;
    }
    
    /* Hash password */
    uint8_t pw_hash[32];
    gecko_sha256((const uint8_t *)password, strlen(password), pw_hash);
    
    /* Hash keyfile */
    uint8_t kf_hash[32];
    gecko_sha256(keydata, keydata_len, kf_hash);
    gecko_secure_zero(keydata, keydata_len);
    free(keydata);
    
    /* XOR and hash again for combined key */
    uint8_t xored[32];
    for (int i = 0; i < 32; i++) {
        xored[i] = pw_hash[i] ^ kf_hash[i];
    }
    
    /* Final hash as combined key */
    if (key_len >= 64) {
        /* Output both hashes concatenated for more entropy */
        gecko_sha256(xored, 32, combined_key);
        uint8_t temp[64];
        memcpy(temp, pw_hash, 32);
        memcpy(temp + 32, kf_hash, 32);
        gecko_sha256(temp, 64, combined_key + 32);
        gecko_secure_zero(temp, 64);
    } else {
        gecko_sha256(xored, 32, combined_key);
    }
    
    gecko_secure_zero(pw_hash, 32);
    gecko_secure_zero(kf_hash, 32);
    gecko_secure_zero(xored, 32);
    
    return GECKO_OK;
}