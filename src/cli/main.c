/*
 * Gecko CLI - Extended command interface
 */

#include "gecko.h"
#include "gecko/vault.h"
#include "gecko/usb.h"
#include "gecko/crypto.h"
#include "gecko/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef GECKO_WINDOWS
#include <windows.h>
#include <conio.h>
#define getch _getch
#else
#include <termios.h>
#include <unistd.h>
#endif

#define MAX_PW 256
#define MIN_PW 8
#define MAX_FILE_SIZE (1ULL << 34)
#define EMERGENCY_PREFIX "WIPE:"
#define EMERGENCY_PREFIX_LEN 5

static bool check_emergency_prefix(const char *pw) {
    if (!pw) return false;
    size_t pw_len = strlen(pw);
    if (pw_len < EMERGENCY_PREFIX_LEN) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < EMERGENCY_PREFIX_LEN; i++)
        diff |= (uint8_t)pw[i] ^ (uint8_t)EMERGENCY_PREFIX[i];
    return diff == 0;
}

static int read_pw(const char *prompt, char *pw, size_t max) {
    if (!pw || max < MIN_PW + 1) return -1;
    memset(pw, 0, max);
    printf("%s", prompt);
    fflush(stdout);
#ifdef GECKO_WINDOWS
    size_t i = 0;
    int c;
    while (i < max - 1) {
        c = getch();
        if (c == '\r' || c == '\n') break;
        if (c == 3) { memset(pw, 0, max); return -1; }
        if ((c == '\b' || c == 127) && i > 0) { pw[--i] = '\0'; printf("\b \b"); fflush(stdout); }
        else if (c >= 32 && c < 127) { pw[i++] = (char)c; putchar('*'); fflush(stdout); }
    }
    pw[i] = '\0';
    putchar('\n');
#else
    struct termios old, new_term;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    new_term = old;
    new_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) return -1;
    if (!fgets(pw, (int)(max - 1), stdin)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        memset(pw, 0, max);
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    putchar('\n');
    size_t len = strlen(pw);
    while (len > 0 && (pw[len-1] == '\n' || pw[len-1] == '\r')) pw[--len] = '\0';
#endif
    return 0;
}

static int read_new_pw(char *pw, size_t max) {
    char confirm[MAX_PW];
    memset(confirm, 0, sizeof(confirm));
    if (read_pw("Password: ", pw, max) < 0) return -1;
    size_t len = strlen(pw);
    if (len < MIN_PW) {
        fprintf(stderr, "Error: minimum %d characters\n", MIN_PW);
        gecko_secure_zero(pw, max);
        return -1;
    }
    if (read_pw("Confirm: ", confirm, sizeof(confirm)) < 0) {
        gecko_secure_zero(pw, max);
        return -1;
    }
    size_t clen = strlen(confirm);
    if (len != clen || gecko_secure_compare(pw, confirm, len) != 0) {
        fprintf(stderr, "Error: passwords don't match\n");
        gecko_secure_zero(pw, max);
        gecko_secure_zero(confirm, sizeof(confirm));
        return -1;
    }
    gecko_secure_zero(confirm, sizeof(confirm));
    return 0;
}

static bool check_emergency(const char *pw, gecko_vault_t *v) {
    if (!pw || !v) return false;
    if (check_emergency_prefix(pw)) {
        printf("!!! EMERGENCY WIPE TRIGGERED !!!\n");
        gecko_vault_emergency_wipe(v);
        printf("Vault destroyed.\n");
        return true;
    }
    return false;
}

static void usage(void) {
    printf("gecko v%d.%d.%d - encrypted USB vault\n\n",
           GECKO_VERSION_MAJOR, GECKO_VERSION_MINOR, GECKO_VERSION_PATCH);
    printf("Usage: gecko <cmd> [args]\n\n");
    printf("Vault:\n");
    printf("  create <vault>              Create new vault\n");
    printf("  add <vault> <file> [name]   Add file to vault\n");
    printf("  get <vault> <name> [dest]   Extract file from vault\n");
    printf("  ls <vault>                  List vault contents\n");
    printf("  rm <vault> <name>           Remove file from vault\n");
    printf("  info <vault>                Show vault info\n");
    printf("  passwd <vault>              Change vault password\n");
    printf("  verify <vault>              Verify vault integrity\n\n");
    printf("Notes & Clipboard:\n");
    printf("  note <vault> <name>         Add encrypted note (prompts for text)\n");
    printf("  read <vault> <name>         Read encrypted note\n");
    printf("  clip <vault> <name>         Save clipboard to vault\n");
    printf("  paste <vault> <name>        Copy vault entry to clipboard\n\n");
    printf("Security:\n");
    printf("  shred <file> [passes]       Securely delete file (default: 3 passes)\n");
    printf("  addshred <vault> <file>     Add file then shred original\n\n");
    printf("Steganography:\n");
    printf("  hide <vault> <image.bmp>    Hide vault inside BMP image\n");
    printf("  unhide <image.bmp> <vault>  Extract vault from BMP image\n\n");
    printf("USB:\n");
    printf("  drives                      List USB drives\n");
    printf("  eject <drive>               Safely eject USB drive\n\n");
    printf("Emergency: Use password 'WIPE:yourpassword' to destroy vault\n");
}

static int cmd_create(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko create <vault>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_new_pw(pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_create(argv[0], pw, &v);
    gecko_secure_zero(pw, sizeof(pw));
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to create vault\n"); return 1; }
    
    gecko_vault_close(v);
    printf("Created: %s\n", argv[0]);
    return 0;
}

static int cmd_add(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko add <vault> <file> [name]\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    const char *name = argc > 2 ? argv[2] : NULL;
    e = gecko_vault_add(v, argv[1], name);
    if (e != GECKO_OK) {
        fprintf(stderr, "Error: failed to add file\n");
        gecko_vault_close(v);
        return 1;
    }
    gecko_vault_close(v);
    printf("Added: %s\n", name ? name : gecko_basename(argv[1]));
    return 0;
}

static int cmd_addshred(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko addshred <vault> <file>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    e = gecko_vault_add(v, argv[1], NULL);
    if (e != GECKO_OK) {
        fprintf(stderr, "Error: failed to add file\n");
        gecko_vault_close(v);
        return 1;
    }
    
    gecko_vault_close(v);
    printf("Added: %s\n", gecko_basename(argv[1]));
    
    e = gecko_shred_file(argv[1], 3);
    if (e != GECKO_OK) {
        fprintf(stderr, "Warning: shred failed\n");
        return 1;
    }
    printf("Shredded: %s\n", argv[1]);
    return 0;
}

static int cmd_get(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko get <vault> <name> [dest]\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    char dest[GECKO_MAX_PATH];
    memset(dest, 0, sizeof(dest));
    int n;
    if (argc > 2) {
        if (strstr(argv[2], "..") != NULL) {
            fprintf(stderr, "Error: invalid path\n");
            gecko_vault_close(v);
            return 1;
        }
        if (gecko_dir_exists(argv[2]))
            n = snprintf(dest, sizeof(dest), "%s%c%s", argv[2], GECKO_PATH_SEP, argv[1]);
        else
            n = snprintf(dest, sizeof(dest), "%s", argv[2]);
    } else {
        n = snprintf(dest, sizeof(dest), "%s", argv[1]);
    }
    if (n < 0 || (size_t)n >= sizeof(dest)) {
        fprintf(stderr, "Error: path too long\n");
        gecko_vault_close(v);
        return 1;
    }
    
    e = gecko_vault_extract(v, argv[1], dest);
    gecko_vault_close(v);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to extract file\n"); return 1; }
    printf("Extracted: %s\n", dest);
    return 0;
}

static int cmd_ls(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko ls <vault>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    gecko_vault_entry_t *entries = NULL;
    uint32_t count = 0;
    gecko_vault_list(v, &entries, &count);
    
    for (uint32_t i = 0; i < count; i++) {
        char sz[32];
        gecko_usb_format_size(entries[i].size, sz, sizeof(sz));
        printf("%-40s %s\n", entries[i].name, sz);
    }
    printf("\n%u file(s)\n", count);
    
    gecko_vault_close(v);
    return 0;
}

static int cmd_rm(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko rm <vault> <name>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    e = gecko_vault_remove(v, argv[1]);
    gecko_vault_close(v);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to remove file\n"); return 1; }
    printf("Removed: %s\n", argv[1]);
    return 0;
}

static int cmd_info(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko info <vault>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    uint32_t fc = 0;
    uint64_t ts = 0, es = 0;
    gecko_vault_stats(v, &fc, &ts, &es);
    gecko_vault_close(v);
    
    char tsz[32], esz[32];
    gecko_usb_format_size(ts, tsz, sizeof(tsz));
    gecko_usb_format_size(es, esz, sizeof(esz));
    
    printf("Vault: %s\n", argv[0]);
    printf("Files: %u\n", fc);
    printf("Size:  %s (encrypted: %s)\n", tsz, esz);
    return 0;
}

static int cmd_passwd(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko passwd <vault>\n"); return 1; }
    char pw[MAX_PW], newpw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    memset(newpw, 0, sizeof(newpw));
    if (read_pw("Current password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    gecko_secure_zero(pw, sizeof(pw));
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    
    if (read_new_pw(newpw, sizeof(newpw)) < 0) { gecko_vault_close(v); return 1; }
    
    e = gecko_vault_change_password(v, newpw);
    gecko_secure_zero(newpw, sizeof(newpw));
    gecko_vault_close(v);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to change password\n"); return 1; }
    printf("Password changed\n");
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko verify <vault>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    gecko_secure_zero(pw, sizeof(pw));
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    
    e = gecko_vault_verify(v);
    gecko_vault_close(v);
    
    if (e == GECKO_OK) {
        printf("Vault integrity: OK\n");
        return 0;
    } else {
        fprintf(stderr, "Vault integrity: FAILED\n");
        return 1;
    }
}

static int read_note_text(char *buf, size_t max) {
    if (!buf || max < 2) return -1;
    printf("Note text (end with empty line):\n");
    fflush(stdout);
    size_t total = 0;
    char line[1024];
    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len == 0 || (len == 1 && line[0] == '\n')) break;
        if (total + len >= max - 1) {
            fprintf(stderr, "Error: note too long\n");
            gecko_secure_zero(buf, max);
            return -1;
        }
        memcpy(buf + total, line, len);
        total += len;
    }
    buf[total] = '\0';
    if (total > 0 && buf[total-1] == '\n') buf[--total] = '\0';
    return (total > 0) ? 0 : -1;
}

static int cmd_note(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko note <vault> <name>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    char note_text[8192];
    memset(note_text, 0, sizeof(note_text));
    if (read_note_text(note_text, sizeof(note_text)) < 0) {
        fprintf(stderr, "Error: no note text provided\n");
        gecko_vault_close(v);
        return 1;
    }
    
    e = gecko_vault_add_note(v, argv[1], note_text);
    gecko_secure_zero(note_text, sizeof(note_text));
    gecko_vault_close(v);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to save note\n"); return 1; }
    printf("Note saved: %s\n", argv[1]);
    return 0;
}

static int cmd_read(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko read <vault> <name>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    char *content = NULL;
    e = gecko_vault_read_note(v, argv[1], &content);
    gecko_vault_close(v);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to read note\n"); return 1; }
    
    printf("%s\n", content);
    gecko_secure_zero(content, strlen(content));
    free(content);
    return 0;
}

static int cmd_clip(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko clip <vault> <name>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    char *text = NULL;
    size_t len = 0;
    e = gecko_clipboard_get(&text, &len);
    if (e != GECKO_OK || !text || len == 0) {
        fprintf(stderr, "Error: clipboard empty or unavailable\n");
        gecko_vault_close(v);
        return 1;
    }
    
    if (len > MAX_FILE_SIZE) {
        fprintf(stderr, "Error: clipboard data too large\n");
        gecko_secure_zero(text, len);
        free(text);
        gecko_vault_close(v);
        return 1;
    }
    
    e = gecko_vault_add_data(v, argv[1], (uint8_t *)text, len);
    gecko_secure_zero(text, len);
    free(text);
    gecko_vault_close(v);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to save clipboard\n"); return 1; }
    printf("Clipboard saved: %s (%zu bytes)\n", argv[1], len);
    return 0;
}

static int cmd_paste(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko paste <vault> <name>\n"); return 1; }
    char pw[MAX_PW];
    memset(pw, 0, sizeof(pw));
    if (read_pw("Password: ", pw, sizeof(pw)) < 0) return 1;
    
    gecko_vault_t *v = NULL;
    gecko_error_t e = gecko_vault_open(argv[0], pw, &v);
    if (e != GECKO_OK) { gecko_secure_zero(pw, sizeof(pw)); fprintf(stderr, "Error: failed to open vault\n"); return 1; }
    if (check_emergency(pw, v)) { gecko_secure_zero(pw, sizeof(pw)); return 0; }
    gecko_secure_zero(pw, sizeof(pw));
    
    uint8_t *data = NULL;
    size_t len = 0;
    e = gecko_vault_read_data(v, argv[1], &data, &len);
    gecko_vault_close(v);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to read entry\n"); return 1; }
    
    e = gecko_clipboard_set((char *)data, len);
    gecko_secure_zero(data, len);
    free(data);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: clipboard unavailable\n"); return 1; }
    printf("Copied to clipboard: %s\n", argv[1]);
    return 0;
}

static int cmd_shred(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko shred <file> [passes]\n"); return 1; }
    int passes = 3;
    if (argc > 1) {
        char *endptr = NULL;
        long val = strtol(argv[1], &endptr, 10);
        if (endptr == argv[1] || *endptr != '\0' || val < 1 || val > 100) {
            fprintf(stderr, "Error: passes must be 1-100\n");
            return 1;
        }
        passes = (int)val;
    }
    
    gecko_error_t e = gecko_shred_file(argv[0], passes);
    if (e != GECKO_OK) { fprintf(stderr, "Error: shred failed\n"); return 1; }
    printf("Shredded: %s (%d passes)\n", argv[0], passes);
    return 0;
}

static int cmd_hide(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko hide <vault> <image.bmp> [output.bmp]\n"); return 1; }
    
    const char *output = argc > 2 ? argv[2] : argv[1];
    
    uint8_t *vault_data = NULL;
    size_t vault_len = 0;
    gecko_error_t e = gecko_read_file(argv[0], &vault_data, &vault_len);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to read vault\n"); return 1; }
    
    if (vault_len > MAX_FILE_SIZE) {
        fprintf(stderr, "Error: vault too large for steganography\n");
        gecko_secure_zero(vault_data, vault_len);
        free(vault_data);
        return 1;
    }
    
    e = gecko_steg_hide(argv[1], vault_data, vault_len, output);
    gecko_secure_zero(vault_data, vault_len);
    free(vault_data);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: steganography failed\n"); return 1; }
    printf("Hidden in: %s\n", output);
    return 0;
}

static int cmd_unhide(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: gecko unhide <image.bmp> <vault>\n"); return 1; }
    
    uint8_t *data = NULL;
    size_t len = 0;
    gecko_error_t e = gecko_steg_extract(argv[0], &data, &len);
    if (e != GECKO_OK) { fprintf(stderr, "Error: extraction failed\n"); return 1; }
    
    e = gecko_write_file(argv[1], data, len);
    gecko_secure_zero(data, len);
    free(data);
    
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to write vault\n"); return 1; }
    printf("Extracted: %s\n", argv[1]);
    return 0;
}

static int cmd_drives(void) {
    gecko_usb_drive_t *drives = NULL;
    uint32_t count = 0;
    gecko_error_t e = gecko_usb_enumerate(&drives, &count);
    if (e != GECKO_OK) { fprintf(stderr, "Error: failed to enumerate drives\n"); return 1; }
    
    if (count == 0) { printf("No USB drives found\n"); return 0; }
    
    for (uint32_t i = 0; i < count; i++) {
        char sz[32], fr[32];
        gecko_usb_format_size(drives[i].size, sz, sizeof(sz));
        gecko_usb_format_size(drives[i].free_space, fr, sizeof(fr));
        printf("%-12s %10s %10s free  %s\n", drives[i].path, sz, fr, drives[i].label);
    }
    gecko_usb_free(drives);
    return 0;
}

static int cmd_eject(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: gecko eject <drive>\n"); return 1; }
    gecko_usb_drive_t d;
    memset(&d, 0, sizeof(d));
    gecko_error_t e = gecko_usb_get_info(argv[0], &d);
    if (e != GECKO_OK) { fprintf(stderr, "Error: drive not found\n"); return 1; }
    
    e = gecko_usb_eject(&d);
    if (e != GECKO_OK) { fprintf(stderr, "Error: eject failed\n"); return 1; }
    printf("Ejected: %s\n", d.path);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    
    const char *cmd = argv[1];
    int cargc = argc - 2;
    char **cargv = argv + 2;
    
    if (!strcmp(cmd, "create"))     return cmd_create(cargc, cargv);
    if (!strcmp(cmd, "add"))        return cmd_add(cargc, cargv);
    if (!strcmp(cmd, "addshred"))   return cmd_addshred(cargc, cargv);
    if (!strcmp(cmd, "get"))        return cmd_get(cargc, cargv);
    if (!strcmp(cmd, "ls"))         return cmd_ls(cargc, cargv);
    if (!strcmp(cmd, "rm"))         return cmd_rm(cargc, cargv);
    if (!strcmp(cmd, "info"))       return cmd_info(cargc, cargv);
    if (!strcmp(cmd, "passwd"))     return cmd_passwd(cargc, cargv);
    if (!strcmp(cmd, "verify"))     return cmd_verify(cargc, cargv);
    if (!strcmp(cmd, "note"))       return cmd_note(cargc, cargv);
    if (!strcmp(cmd, "read"))       return cmd_read(cargc, cargv);
    if (!strcmp(cmd, "clip"))       return cmd_clip(cargc, cargv);
    if (!strcmp(cmd, "paste"))      return cmd_paste(cargc, cargv);
    if (!strcmp(cmd, "shred"))      return cmd_shred(cargc, cargv);
    if (!strcmp(cmd, "hide"))       return cmd_hide(cargc, cargv);
    if (!strcmp(cmd, "unhide"))     return cmd_unhide(cargc, cargv);
    if (!strcmp(cmd, "drives"))     return cmd_drives();
    if (!strcmp(cmd, "eject"))      return cmd_eject(cargc, cargv);
    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h")) { usage(); return 0; }
    
    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
