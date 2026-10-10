#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Disposable transport fixture: no SPLAT credentials, policy, or BPF state is loaded. */
int main(int argc, char **argv)
{
    if (argc != 4 || (strcmp(argv[1], "serve") && strcmp(argv[1], "check"))) return 2;
    char *end;
    long port = strtol(argv[2], &end, 10);
    if (*end || port < 1 || port > 65535 || strlen(argv[3]) != 53 ||
        strncmp(argv[3], "SPLAT_IDENTITY_PROBE_", 21)) return 2;
    for (const char *p = argv[3] + 21; *p; ++p)
        if (!strchr("0123456789abcdef", *p)) return 2;
    char response[55];
    int length = snprintf(response, sizeof response, "%s\n", argv[3]);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 1; }
    alarm(strcmp(argv[1], "serve") == 0 ? 480 : 5);
    if (strcmp(argv[1], "check") == 0) {
        if (connect(fd, (struct sockaddr *)&address, sizeof address)) { perror("connect"); return 1; }
        char received[55];
        size_t count = 0;
        while (count < (size_t)length) {
            ssize_t n = read(fd, received + count, (size_t)length - count);
            if (n <= 0) break;
            count += (size_t)n;
        }
        close(fd);
        if (count != (size_t)length || memcmp(response, received, count)) return 1;
        puts("MARKER_MATCH");
        return 0;
    }
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse) ||
        bind(fd, (struct sockaddr *)&address, sizeof address) || listen(fd, 8)) {
        perror("listen"); return 1;
    }
    puts("READY");
    fflush(stdout);
    for (;;) {
        int client = accept(fd, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; perror("accept"); return 1; }
        size_t sent = 0;
        while (sent < (size_t)length) {
            ssize_t n = send(client, response + sent, (size_t)length - sent, MSG_NOSIGNAL);
            if (n <= 0) break;
            sent += (size_t)n;
        }
        close(client);
    }
}
