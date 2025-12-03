#include "gecko.h"
#include "gecko/usb.h"
#include "gecko/util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef GECKO_WINDOWS

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <winioctl.h>

#pragma comment(lib, "setupapi.lib")

DEFINE_GUID(GUID_DEVINTERFACE_USB_DISK, 
    0x53f56307, 0xb6bf, 0x11d0, 
    0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);

gecko_error_t gecko_usb_enumerate(gecko_usb_drive_t **drives, uint32_t *count) {
    if (!drives || !count) return GECKO_ERR_INVALID_PARAM;
    
    *drives = NULL;
    *count = 0;
    
    uint32_t capacity = 8;
    gecko_usb_drive_t *result = calloc(capacity, sizeof(gecko_usb_drive_t));
    if (!result) return GECKO_ERR_NO_MEMORY;
    
    DWORD drive_mask = GetLogicalDrives();
    if (drive_mask == 0) { free(result); return GECKO_ERR_DEVICE; }
    
    for (int i = 0; i < 26; i++) {
        if (!(drive_mask & (1u << i))) continue;
        
        /* Build paths safely without snprintf */
        char root[4] = {(char)('A' + i), ':', '\\', '\0'};
        char device[8] = {'\\', '\\', '.', '\\', (char)('A' + i), ':', '\0'};
        
        UINT type = GetDriveTypeA(root);
        if (type != DRIVE_REMOVABLE) continue;
        
        HANDLE h = CreateFileA(device, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        
        DISK_GEOMETRY_EX geom;
        DWORD bytes_returned;
        BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                  NULL, 0, &geom, sizeof(geom), &bytes_returned, NULL);
        if (!ok) { CloseHandle(h); continue; }
        
        /* Check capacity overflow before realloc */
        if (*count >= capacity) {
            if (capacity > UINT32_MAX / 2) { CloseHandle(h); free(result); return GECKO_ERR_NO_MEMORY; }
            uint32_t new_cap = capacity * 2;
            gecko_usb_drive_t *new_result = realloc(result, new_cap * sizeof(gecko_usb_drive_t));
            if (!new_result) { CloseHandle(h); free(result); return GECKO_ERR_NO_MEMORY; }
            result = new_result;
            capacity = new_cap;
        }
        
        gecko_usb_drive_t *drive = &result[*count];
        memset(drive, 0, sizeof(*drive));
        
        memcpy(drive->path, root, 4);
        memcpy(drive->device, device, 7);
        drive->letter = (char)('A' + i);
        drive->size = geom.DiskSize.QuadPart;
        drive->is_removable = true;
        
        char volume_name[256] = {0};
        char fs_name[64] = {0};
        if (GetVolumeInformationA(root, volume_name, sizeof(volume_name) - 1,
                                  NULL, NULL, NULL, fs_name, sizeof(fs_name) - 1)) {
            strncpy(drive->label, volume_name, sizeof(drive->label) - 1);
            drive->label[sizeof(drive->label) - 1] = '\0';
            strncpy(drive->filesystem, fs_name, sizeof(drive->filesystem) - 1);
            drive->filesystem[sizeof(drive->filesystem) - 1] = '\0';
        }
        
        ULARGE_INTEGER free_bytes;
        if (GetDiskFreeSpaceExA(root, &free_bytes, NULL, NULL)) {
            drive->free_space = free_bytes.QuadPart;
        }
        
        CloseHandle(h);
        (*count)++;
    }
    
    if (*count == 0) { free(result); *drives = NULL; }
    else *drives = result;
    
    return GECKO_OK;
}

gecko_error_t gecko_usb_eject(gecko_usb_drive_t *drive) {
    if (!drive) return GECKO_ERR_INVALID_PARAM;
    if (drive->letter < 'A' || drive->letter > 'Z') return GECKO_ERR_INVALID_PARAM;
    
    char volume[8] = {'\\', '\\', '.', '\\', drive->letter, ':', '\0'};
    
    HANDLE h = CreateFileA(volume, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return GECKO_ERR_DEVICE;
    
    DWORD bytes;
    gecko_error_t result = GECKO_OK;
    
    /* Lock and dismount */
    DeviceIoControl(h, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytes, NULL);
    if (!DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytes, NULL)) {
        result = GECKO_ERR_DEVICE;
        goto done;
    }
    
    PREVENT_MEDIA_REMOVAL pmr = {FALSE};
    DeviceIoControl(h, IOCTL_STORAGE_MEDIA_REMOVAL, &pmr, sizeof(pmr), NULL, 0, &bytes, NULL);
    
    if (!DeviceIoControl(h, IOCTL_STORAGE_EJECT_MEDIA, NULL, 0, NULL, 0, &bytes, NULL)) {
        result = GECKO_ERR_DEVICE;
    }
    
done:
    CloseHandle(h);
    return result;
}

#else /* Linux */

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <dirent.h>
#include <unistd.h>
#include <mntent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

/* Validate device name contains only safe chars */
static bool validate_dev_name(const char *name) {
    if (!name || !*name) return false;
    for (const char *p = name; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) return false;
    }
    return true;
}

static bool is_usb_device(const char *device) {
    if (!device || strlen(device) < 6) return false;
    
    const char *dev_name = strrchr(device, '/');
    if (!dev_name || strlen(dev_name) < 2) return false;
    dev_name++;
    
    if (!validate_dev_name(dev_name)) return false;
    
    char sys_path[256];
    char link_path[256];
    
    int n = snprintf(sys_path, sizeof(sys_path), "/sys/block/%s/device", dev_name);
    if (n < 0 || (size_t)n >= sizeof(sys_path)) return false;
    
    memset(link_path, 0, sizeof(link_path));
    ssize_t len = readlink(sys_path, link_path, sizeof(link_path) - 1);
    if (len > 0 && len < (ssize_t)sizeof(link_path)) {
        link_path[len] = '\0';
        if (strstr(link_path, "usb")) return true;
    }
    
    /* Try parent for partitions */
    char parent[64];
    size_t dlen = strlen(dev_name);
    if (dlen >= sizeof(parent)) return false;
    memcpy(parent, dev_name, dlen + 1);
    
    while (dlen > 0 && parent[dlen - 1] >= '0' && parent[dlen - 1] <= '9') {
        parent[--dlen] = '\0';
    }
    if (dlen == 0) return false;
    
    n = snprintf(sys_path, sizeof(sys_path), "/sys/block/%s/device", parent);
    if (n < 0 || (size_t)n >= sizeof(sys_path)) return false;
    
    memset(link_path, 0, sizeof(link_path));
    len = readlink(sys_path, link_path, sizeof(link_path) - 1);
    if (len > 0 && len < (ssize_t)sizeof(link_path)) {
        link_path[len] = '\0';
        return strstr(link_path, "usb") != NULL;
    }
    
    return false;
}

static uint64_t get_device_size(const char *device) {
    if (!device) return 0;
    
    int fd = open(device, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return 0;
    
    uint64_t size = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) < 0) size = 0;
    
    close(fd);
    return size;
}

gecko_error_t gecko_usb_enumerate(gecko_usb_drive_t **drives, uint32_t *count) {
    if (!drives || !count) return GECKO_ERR_INVALID_PARAM;
    
    *drives = NULL;
    *count = 0;
    
    uint32_t capacity = 8;
    gecko_usb_drive_t *result = calloc(capacity, sizeof(gecko_usb_drive_t));
    if (!result) return GECKO_ERR_NO_MEMORY;
    
    FILE *mtab = setmntent("/proc/mounts", "r");
    if (!mtab) { free(result); return GECKO_ERR_IO; }
    
    struct mntent *ent;
    while ((ent = getmntent(mtab)) != NULL) {
        if (!ent->mnt_fsname || !ent->mnt_dir || !ent->mnt_type) continue;
        if (strncmp(ent->mnt_fsname, "/dev/", 5) != 0) continue;
        if (!is_usb_device(ent->mnt_fsname)) continue;
        
        if (*count >= capacity) {
            if (capacity > UINT32_MAX / 2) { endmntent(mtab); free(result); return GECKO_ERR_NO_MEMORY; }
            uint32_t new_cap = capacity * 2;
            gecko_usb_drive_t *new_result = realloc(result, new_cap * sizeof(gecko_usb_drive_t));
            if (!new_result) { endmntent(mtab); free(result); return GECKO_ERR_NO_MEMORY; }
            result = new_result;
            capacity = new_cap;
        }
        
        gecko_usb_drive_t *drive = &result[*count];
        memset(drive, 0, sizeof(*drive));
        
        strncpy(drive->device, ent->mnt_fsname, sizeof(drive->device) - 1);
        strncpy(drive->path, ent->mnt_dir, sizeof(drive->path) - 1);
        strncpy(drive->filesystem, ent->mnt_type, sizeof(drive->filesystem) - 1);
        drive->is_removable = true;
        drive->is_mounted = true;
        drive->size = get_device_size(ent->mnt_fsname);
        
        struct statvfs svfs;
        if (statvfs(ent->mnt_dir, &svfs) == 0) {
            /* Overflow-safe multiplication */
            if (svfs.f_bsize > 0 && svfs.f_bavail <= UINT64_MAX / svfs.f_bsize) {
                drive->free_space = (uint64_t)svfs.f_bsize * svfs.f_bavail;
            }
            if (drive->size == 0 && svfs.f_bsize > 0 && svfs.f_blocks <= UINT64_MAX / svfs.f_bsize) {
                drive->size = (uint64_t)svfs.f_bsize * svfs.f_blocks;
            }
        }
        
        (*count)++;
    }
    
    endmntent(mtab);
    
    /* Check /sys/block for unmounted USB */
    DIR *sys_block = opendir("/sys/block");
    if (sys_block) {
        struct dirent *de;
        while ((de = readdir(sys_block)) != NULL) {
            if (de->d_name[0] == '.') continue;
            if (!validate_dev_name(de->d_name)) continue;
            
            size_t name_len = strlen(de->d_name);
            if (name_len == 0 || name_len > 32) continue;
            
            char dev_path[64];
            int n = snprintf(dev_path, sizeof(dev_path), "/dev/%s", de->d_name);
            if (n < 0 || (size_t)n >= sizeof(dev_path)) continue;
            
            if (!is_usb_device(dev_path)) continue;
            
            /* Skip if already listed */
            bool found = false;
            for (uint32_t i = 0; i < *count; i++) {
                if (strcmp(result[i].device, dev_path) == 0) { found = true; break; }
            }
            if (found) continue;
            
            if (*count >= capacity) {
                if (capacity > UINT32_MAX / 2) { closedir(sys_block); free(result); return GECKO_ERR_NO_MEMORY; }
                uint32_t new_cap = capacity * 2;
                gecko_usb_drive_t *new_result = realloc(result, new_cap * sizeof(gecko_usb_drive_t));
                if (!new_result) { closedir(sys_block); free(result); return GECKO_ERR_NO_MEMORY; }
                result = new_result;
                capacity = new_cap;
            }
            
            gecko_usb_drive_t *drive = &result[*count];
            memset(drive, 0, sizeof(*drive));
            strncpy(drive->device, dev_path, sizeof(drive->device) - 1);
            drive->is_removable = true;
            drive->is_mounted = false;
            drive->size = get_device_size(dev_path);
            (*count)++;
        }
        closedir(sys_block);
    }
    
    if (*count == 0) { free(result); *drives = NULL; }
    else *drives = result;
    
    return GECKO_OK;
}

gecko_error_t gecko_usb_eject(gecko_usb_drive_t *drive) {
    if (!drive) return GECKO_ERR_INVALID_PARAM;
    
    /* Validate device path - must start with /dev/ and contain only safe chars */
    size_t dev_len = strlen(drive->device);
    if (dev_len < 6 || strncmp(drive->device, "/dev/", 5) != 0) return GECKO_ERR_INVALID_PARAM;
    if (!validate_dev_name(drive->device + 5)) return GECKO_ERR_INVALID_PARAM;
    
    sync();
    
    /* Unmount using syscall directly - no system() to avoid injection */
    if (drive->is_mounted && strlen(drive->path) > 0) {
        if (umount2(drive->path, MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
            return GECKO_ERR_DEVICE;
        }
    }
    
    /* Use ioctl for eject */
    int fd = open(drive->device, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return GECKO_ERR_DEVICE;
    
    ioctl(fd, BLKFLSBUF, 0);
    
    #ifndef CDROMEJECT
    #define CDROMEJECT 0x5309
    #endif
    ioctl(fd, CDROMEJECT, 0);
    
    close(fd);
    return GECKO_OK;
}

#endif /* Linux */

void gecko_usb_free(gecko_usb_drive_t *drives) {
    free(drives);
}

gecko_error_t gecko_usb_get_info(const char *path, gecko_usb_drive_t *drive) {
    if (!path || !drive || strlen(path) == 0) return GECKO_ERR_INVALID_PARAM;
    
    gecko_usb_drive_t *drives = NULL;
    uint32_t count = 0;
    
    gecko_error_t err = gecko_usb_enumerate(&drives, &count);
    if (err != GECKO_OK) return err;
    if (!drives) return GECKO_ERR_NOT_FOUND;
    
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(drives[i].path, path) == 0 || strcmp(drives[i].device, path) == 0) {
            memcpy(drive, &drives[i], sizeof(*drive));
            gecko_usb_free(drives);
            return GECKO_OK;
        }
    }
    
    gecko_usb_free(drives);
    return GECKO_ERR_NOT_FOUND;
}

gecko_error_t gecko_usb_format_size(uint64_t size, char *buf, size_t buf_len) {
    if (!buf || buf_len < 16) return GECKO_ERR_INVALID_PARAM;
    
    static const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double dsize = (double)size;
    
    while (dsize >= 1024.0 && unit < 4) {
        dsize /= 1024.0;
        unit++;
    }
    
    int n;
    if (unit == 0) n = snprintf(buf, buf_len, "%u B", (unsigned)size);
    else n = snprintf(buf, buf_len, "%.2f %s", dsize, units[unit]);
    
    if (n < 0 || (size_t)n >= buf_len) {
        buf[0] = '\0';
        return GECKO_ERR_INVALID_PARAM;
    }
    
    return GECKO_OK;
}

bool gecko_usb_is_usb_path(const char *path) {
    if (!path || strlen(path) == 0) return false;
    
    gecko_usb_drive_t *drives = NULL;
    uint32_t count = 0;
    
    if (gecko_usb_enumerate(&drives, &count) != GECKO_OK) return false;
    if (!drives) return false;
    
    bool result = false;
    for (uint32_t i = 0; i < count; i++) {
        size_t plen = strlen(drives[i].path);
        if (plen > 0 && strncmp(path, drives[i].path, plen) == 0) {
            char next = path[plen];
            if (next == '\0' || next == '/' || next == '\\') {
                result = true;
                break;
            }
        }
    }
    
    gecko_usb_free(drives);
    return result;
}
