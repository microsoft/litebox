// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Static guest for the shim tests. argv[1] selects the behavior; every mode first describes its
// startup on stdout.
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void describe(int argc, char **argv) {
    char cwd[256];
    printf("ids=%d,%d cwd=%s\n", (int)getuid(), (int)getgid(), getcwd(cwd, sizeof cwd) ? cwd : "?");
    for (int i = 0; i < argc; i++) printf("argv[%d]=[%s]\n", i, argv[i]);
    for (char **e = environ; *e; e++) printf("env=[%s]\n", *e);
    fflush(stdout);
}

// Copies stdin to stdout until its end; at a line `exit <status>`, exits with that status.
static int cat(void) {
    char line[256];
    while (fgets(line, sizeof line, stdin)) {
        if (strncmp(line, "exit ", 5) == 0) return atoi(line + 5);
        printf("line=[%.*s]\n", (int)strcspn(line, "\r\n"), line);
        fflush(stdout);
    }
    printf("eof\n");
    return 0;
}

static void on_signal(int signal) {
    char message[64];
    int length = snprintf(message, sizeof message, "caught %d\n", signal);
    if (write(1, message, (size_t)length)) {}
    if (signal == SIGTERM) _exit(7);
}

static void on_resize(int signal) {
    (void)signal;
    struct winsize size = {0};
    ioctl(0, TIOCGWINSZ, &size);
    char message[64];
    int length = snprintf(message, sizeof message, "resized %dx%d\n", size.ws_row, size.ws_col);
    if (write(1, message, (size_t)length)) {}
}

// Reports SIGINT, SIGWINCH and SIGTERM (then exits 7), and describes its terminal, if any.
static int signals(void) {
    struct sigaction action = {.sa_handler = on_signal, .sa_flags = SA_RESTART};
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    action.sa_handler = on_resize;
    sigaction(SIGWINCH, &action, NULL);
    struct winsize size = {0};
    ioctl(0, TIOCGWINSZ, &size);
    printf("tty=%d%d%d foreground=%d size=%dx%d\n", isatty(0), isatty(1), isatty(2),
           tcgetpgrp(0) == getpgrp(), size.ws_row, size.ws_col);
    fflush(stdout);
    return cat();
}

int main(int argc, char **argv) {
    describe(argc, argv);
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "exit") == 0) {
        fprintf(stderr, "stderr\n");
        return argc > 2 ? atoi(argv[2]) : 0;
    }
    if (strcmp(mode, "cat") == 0) return cat();
    // Tries to kill the guest service, then waits for signals.
    if (strcmp(mode, "kill-service") == 0) {
        int sent = kill(1, SIGTERM) == 0 && kill(1, SIGINT) == 0 && kill(1, SIGHUP) == 0 &&
                   kill(1, SIGKILL) == 0;
        printf("sent %d\n", sent);
        fflush(stdout);
        for (;;) pause();
    }
    if (strcmp(mode, "signals") == 0) return signals();
    // Forks a child that outlives this process, then waits for signals.
    if (strcmp(mode, "family") == 0) {
        if (fork() == 0) {
            printf("child\n");
            fflush(stdout);
        }
        for (;;) pause();
    }
    // Prints argv[2] numbered lines, then exits; with argv[3], from a child, as this exits.
    if (strcmp(mode, "lines") == 0) {
        if (argc > 3 && fork() != 0) return 0;
        for (int i = 0; i < atoi(argv[2]); i++) printf("line %d\n", i);
        return 0;
    }
    // Exits, leaving a child that keeps stdout: printing a line every argv[2] seconds, or never.
    if (strcmp(mode, "hold") == 0 && argc > 2) {
        if (fork() != 0) return 0;
        for (;;) {
            if (atoi(argv[2]) == 0) pause();
            sleep((unsigned)atoi(argv[2]));
            printf("tick\n");
            fflush(stdout);
        }
    }
    // Prints the target of the symlink argv[2], then the files that follow it.
    if (strcmp(mode, "read") == 0 && argc > 3) {
        char target[256];
        ssize_t length = readlink(argv[2], target, sizeof target - 1);
        if (length < 0) return 81;
        target[length] = '\0';
        printf("link=%s\n", target);
        for (int i = 3; i < argc; i++) {
            FILE *file = fopen(argv[i], "r");
            if (!file) return 82;
            int c;
            while ((c = fgetc(file)) != EOF) putchar(c);
            fclose(file);
        }
        return 0;
    }
    // Writes argv[3] to the file argv[2]; on failure, prints why and exits 51.
    if (strcmp(mode, "write") == 0 && argc > 3) {
        FILE *file = fopen(argv[2], "w");
        if (file && fputs(argv[3], file) >= 0 && fclose(file) == 0) return 0;
        printf("write: %s\n", strerror(errno));
        return 51;
    }
    // Opens the directory argv[2], then prints the file argv[3] relative to it.
    if (strcmp(mode, "readat") == 0 && argc > 3) {
        int dir = open(argv[2], O_RDONLY | O_DIRECTORY);
        int file = dir < 0 ? -1 : openat(dir, argv[3], O_RDONLY);
        if (file < 0) {
            printf("openat: %s\n", strerror(errno));
            return 52;
        }
        char content[256];
        ssize_t size = read(file, content, sizeof content);
        if (size < 0) return 53;
        printf("%.*s", (int)size, content);
        return 0;
    }
    // Listens on port 80, then writes "hello" to one client.
    if (strcmp(mode, "serve") == 0) {
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(80)};
        int server = socket(AF_INET, SOCK_STREAM, 0);
        if (bind(server, (struct sockaddr *)&addr, sizeof addr) || listen(server, 1)) return 61;
        dprintf(1, "listening\n");
        return write(accept(server, NULL, NULL), "hello", 5) == 5 ? 0 : 62;
    }
    // Connects to 10.0.2.1 at a port over TCP, sends "ping", and prints the reply.
    if (strcmp(mode, "tcp") == 0 && argc > 2) {
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2])),
                                   .sin_addr.s_addr = htonl(0x0a000201)};
        int client = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(client, (struct sockaddr *)&addr, sizeof addr)) {
            printf("connect: %s\n", strerror(errno));
            return 71;
        }
        if (write(client, "ping", 4) != 4 || shutdown(client, SHUT_WR)) return 72;
        char reply[64];
        size_t size = 0;
        ssize_t got;
        while (size < sizeof reply && (got = read(client, reply + size, sizeof reply - size)) > 0)
            size += (size_t)got;
        // Until an orderly EOF, not a reset.
        if (got != 0) return 73;
        printf("tcp=[%.*s]\n", (int)size, reply);
        return 0;
    }
    // Connects to 10.0.2.1 at the port, prints what it reads until EOF, then sends "ping".
    if (strcmp(mode, "tcp-server-first") == 0 && argc > 2) {
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2])),
                                   .sin_addr.s_addr = htonl(0x0a000201)};
        int client = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(client, (struct sockaddr *)&addr, sizeof addr)) return 71;
        char reply[64];
        size_t size = 0;
        ssize_t got;
        while (size < sizeof reply && (got = read(client, reply + size, sizeof reply - size)) > 0)
            size += (size_t)got;
        if (got != 0) return 73;
        printf("tcp=[%.*s]\n", (int)size, reply);
        return write(client, "ping", 4) == 4 ? 0 : 72;
    }
    // Sends "ping" over a UDP socket connected to 10.0.2.1 at the port, then prints the
    // receive's error.
    if (strcmp(mode, "udp-connected") == 0 && argc > 2) {
        struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2])),
                                   .sin_addr.s_addr = htonl(0x0a000201)};
        int client = socket(AF_INET, SOCK_DGRAM, 0);
        if (connect(client, (struct sockaddr *)&addr, sizeof addr) || send(client, "ping", 4, 0) != 4)
            return 81;
        char reply[64];
        if (recv(client, reply, sizeof reply, 0) >= 0) return 82;
        printf("recv: %s\n", strerror(errno));
        return 0;
    }
    // Sends "ping" over UDP to 10.0.2.1 at a closed port, then at another, from one socket, then
    // prints the reply.
    if (strcmp(mode, "udp-past-refused") == 0 && argc > 3) {
        int client = socket(AF_INET, SOCK_DGRAM, 0);
        for (int i = 2; i < 4; i++) {
            struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[i])),
                                       .sin_addr.s_addr = htonl(0x0a000201)};
            if (sendto(client, "ping", 4, 0, (struct sockaddr *)&addr, sizeof addr) != 4) return 81;
        }
        char reply[64];
        ssize_t got = recv(client, reply, sizeof reply, 0);
        if (got < 0) return 82;
        printf("udp=[%.*s]\n", (int)got, reply);
        return 0;
    }
    // Sends "ping" over UDP to 10.0.2.1 at each port, from one socket, then prints each reply.
    if (strcmp(mode, "udp") == 0 && argc > 2) {
        int client = socket(AF_INET, SOCK_DGRAM, 0);
        for (int i = 2; i < argc; i++) {
            struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[i])),
                                       .sin_addr.s_addr = htonl(0x0a000201)};
            if (sendto(client, "ping", 4, 0, (struct sockaddr *)&addr, sizeof addr) != 4) return 81;
        }
        for (int i = 2; i < argc; i++) {
            char reply[64];
            struct sockaddr_in from;
            socklen_t length = sizeof from;
            ssize_t got = recvfrom(client, reply, sizeof reply, 0, (struct sockaddr *)&from, &length);
            if (got < 0) return 82;
            printf("udp=[%.*s] from %d\n", (int)got, reply, ntohs(from.sin_port));
        }
        return 0;
    }
    for (;;) pause();
}
