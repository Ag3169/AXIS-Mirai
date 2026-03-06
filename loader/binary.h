#ifndef _LOADER_BINARY_H
#define _LOADER_BINARY_H

#include "includes.h"

struct binary {
    char *arch;
    char *hex_payload;
    int hex_payload_len;
};

BOOL binary_init(void);
char *binary_get_by_arch(char *);

#endif
