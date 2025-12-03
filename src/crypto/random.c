/*
 * Cryptographically secure random bytes
 */

#include "gecko.h"

#ifdef GECKO_WINDOWS

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

gecko_error_t gecko_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    /* Use BCryptGenRandom (Windows CNG) */
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    
    if (!BCRYPT_SUCCESS(status)) {
        return GECKO_ERR_CRYPTO;
    }
    
    return GECKO_OK;
}

#else /* GECKO_LINUX */

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#ifdef __linux__
#include <sys/random.h>
#endif

gecko_error_t gecko_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return GECKO_ERR_INVALID_PARAM;
    }
    
    /* Try getrandom() first (Linux 3.17+) */
    #ifdef __linux__
    ssize_t result = getrandom(buf, len, 0);
    if (result == (ssize_t)len) {
        return GECKO_OK;
    }
    #endif
    
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return GECKO_ERR_CRYPTO;
    }
    
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return GECKO_ERR_CRYPTO;
        }
        total += n;
    }
    
    close(fd);
    return GECKO_OK;
}

#endif
