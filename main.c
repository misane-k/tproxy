#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>                                               #include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef SO_ORIGINAL_DST
#include <linux/netfilter_ipv4.h>
#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#endif

#define PEEK_BUF 8192
#define RELAY_BUF 16384
int port;

static int tls_parse_sni_from(const unsigned char *b, ssize_t n,
                              char *out, size_t outlen)
{
    if (n < 5 || b[0] != 0x16) return -1;           // not TLS handshake
    unsigned int rec_len = (b[3] << 8) | b[4];
    if (n < 5 + (ssize_t)rec_len) return -2;        // incomplete record

    const unsigned char *p = b + 5;
    ssize_t rem = rec_len;
    if (rem < 4 || p[0] != 0x01) return -3;         // not ClientHello

    p += 4; rem -= 4;                              // handshake header
    if (rem < 34) return -4;
    p += 34; rem -= 34;                            // version + random

    if (rem < 1) return -5;
    unsigned int sid = p[0]; p++; rem--;
    if (rem < (ssize_t)sid) return -6;
    p += sid; rem -= sid;

    if (rem < 2) return -7;
    unsigned int cs = (p[0] << 8) | p[1]; p += 2; rem -= 2;
    if (rem < (ssize_t)cs) return -8;
    p += cs; rem -= cs;

    if (rem < 1) return -9;
    unsigned int comp = p[0]; p++; rem--;
    if (rem < (ssize_t)comp) return -10;
    p += comp; rem -= comp;

    if (rem < 2) return -11;
    unsigned int extlen = (p[0] << 8) | p[1]; p += 2;
    if (rem < (ssize_t)(2 + extlen)) return -12;

    const unsigned char *end = p + extlen;
    while (p + 4 <= end) {
        unsigned int type = (p[0] << 8) | p[1];
        unsigned int len  = (p[2] << 8) | p[3];
        p += 4;
        if (p + len > end) break;
        if (type == 0x0000 && len > 2) {            // SNI
            const unsigned char *q = p + 2;
            if (q + 3 > p + len) break;
            unsigned int namelen = (q[1] << 8) | q[2];
            q += 3;
            if (q + namelen <= p + len) {
                size_t c = namelen < outlen - 1 ? namelen : outlen - 1;
                memcpy(out, q, c);
                out[c] = 0;
                return 0;
            }
        }
        p += len;
    }
    return -14;
}

static int parse_http_host(const unsigned char *b, ssize_t n,
                           char *out, size_t outlen, int *p)
{
    const char *s = (const char *)b;
    const char *end = s + n;
    for (const char *ptr = s; ptr + 5 < end; ++ptr) {
        if ((ptr[0] | 0x20) == 'h' && (ptr[1] | 0x20) == 'o' &&
            (ptr[2] | 0x20) == 's' && (ptr[3] | 0x20) == 't' && ptr[4] == ':') {
            ptr += 5;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ptr++;
            const char *q = ptr;
            while (q < end && *q != '\r' && *q != '\n') q++;
            size_t len = q - ptr;
            if (len >= outlen) len = outlen - 1;
            memcpy(out, ptr, len);
            out[len] = 0;

            char *colon = strchr(out, ':');
            if (colon) {
                *colon = 0;
                *p = atoi(colon + 1);
            } else {
                *p = 80;
            }
            return 0;
        }
    }
    return -1;
}


static void relay_loop(int a, int b) {
    struct pollfd fds[2] = {
        { .fd = a, .events = POLLIN },
        { .fd = b, .events = POLLIN }
    };
    unsigned char buf[RELAY_BUF];

    while (1) {
        int rc = poll(fds, 2, -1);
        if (rc <= 0) break;
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(a, buf, sizeof(buf));
            if (n <= 0) break;
            write(b, buf, n);
        }
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(b, buf, sizeof(buf));
            if (n <= 0) break;
            write(a, buf, n);
        }
    }
}

static void handle_client(int c, struct sockaddr_in *cli) {
    int ret = 0;
    struct sockaddr_in mid;
    socklen_t len = sizeof(mid);
    memset(&mid, 0, sizeof(mid));
    ret = getsockopt(c, SOL_IP, SO_ORIGINAL_DST, &mid, &len);
    assert(ret == 0);

    struct pollfd pfd = {
        .fd = c,
        .events = POLLIN
    };
    ret = poll(&pfd, 1, 1000);
    assert(ret > 0);
    unsigned char peek[PEEK_BUF];
    ssize_t n = recv(c, peek, sizeof(peek), MSG_PEEK);
    assert(n > 0);

    char host[256] = {0};
    int p = ntohs(mid.sin_port);
    if (parse_http_host(peek, n, host, sizeof(host), &p) == 0) {
        fprintf(stderr, "HTTP Host: %s\n", host);
        if (p == port) p = 80;
    } else if ((ret = tls_parse_sni_from(peek, n, host, sizeof(host))) == 0) {
        fprintf(stderr, "TLS SNI: %s\n", host);
        if (p == port) p = 443;
    } else {
        fprintf(stderr, "unknown connection: %d\n", ret);
        assert(0);
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(host, NULL, &hints, &res);
    assert(ret == 0);
    struct sockaddr_in *dst = (struct sockaddr_in*)res->ai_addr;
    dst->sin_port = htons(p);


    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    assert(s >= 0);
    ret = connect(s, dst, res->ai_addrlen);
    assert(ret == 0);

    char src_addr[INET_ADDRSTRLEN], mid_addr[INET_ADDRSTRLEN], dst_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli->sin_addr, src_addr, sizeof(src_addr));
    inet_ntop(AF_INET, &mid.sin_addr,  mid_addr, sizeof(mid_addr));
    inet_ntop(AF_INET, &dst->sin_addr, dst_addr, sizeof(dst_addr));
    fprintf(stderr, "conn %s:%d -> %s:%d -> %s[%s]:%d\n",
        src_addr, ntohs(cli->sin_port),
        mid_addr, ntohs(mid.sin_port),
        host, dst_addr, ntohs(dst->sin_port));

    relay_loop(c, s);
    close(s);
    close(c);
}

static int make_listener() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    assert(s >= 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);

    assert(bind(s, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    assert(listen(s, 4096) == 0);
    return s;
}

int main(int argc, char **argv) {
    signal(SIGCHLD, SIG_IGN);

    port = (argc > 1) ? atoi(argv[1]) : 12345;
    int listenfd = make_listener();

    fprintf(stderr, "tproxy listening on %d\n", port);

    while(1) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int c = accept(listenfd, (struct sockaddr *)&cli, &clilen);
        assert(c >= 0);

        pid_t pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
            close(listenfd);
            handle_client(c, &cli);
            exit(0);
        }
        close(c);
    }
}
