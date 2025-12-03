#ifndef GECKO_USB_H
#define GECKO_USB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* USB drive information */
typedef struct gecko_usb_drive {
    char     device[128];           /* Device path (e.g., /dev/sdb) */
    char     path[GECKO_MAX_PATH];  /* Mount point */
    char     label[64];             /* Volume label */
    char     filesystem[32];        /* Filesystem type */
    char     letter;                /* Drive letter (Windows only) */
    
    uint64_t size;                  /* Total capacity */
    uint64_t free_space;            /* Available space */
    
    bool     is_removable;          /* Is removable media */
    bool     is_mounted;            /* Is currently mounted */
} gecko_usb_drive_t;

/* Enumerate all USB drives */
gecko_error_t gecko_usb_enumerate(gecko_usb_drive_t **drives, uint32_t *count);

/* Free enumerated drives list */
void gecko_usb_free(gecko_usb_drive_t *drives);

/* Get USB drive info by path */
gecko_error_t gecko_usb_get_info(const char *path, gecko_usb_drive_t *drive);

/* Check if path is on USB drive */
bool gecko_usb_is_usb_path(const char *path);

/* Safely eject USB drive */
gecko_error_t gecko_usb_eject(gecko_usb_drive_t *drive);

/* Format size for display (returns string like "1.5 GB") */
gecko_error_t gecko_usb_format_size(uint64_t size, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif
