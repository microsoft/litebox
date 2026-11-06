// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Static guest for the shim tests. argv[1] selects the behavior; every mode first describes its
// startup on stdout.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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
    // Kills the guest service, then waits for signals.
    if (strcmp(mode, "kill-service") == 0) {
        kill(1, SIGKILL);
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
    // Prints argv[2] numbered lines, then exits.
    if (strcmp(mode, "lines") == 0) {
        for (int i = 0; i < atoi(argv[2]); i++) printf("line %d\n", i);
        return 0;
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
    for (;;) pause();
}
