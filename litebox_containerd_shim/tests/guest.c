// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Static guest for the shim tests. argv[1] selects the behavior; every mode first describes its
// startup on stdout.
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void describe(int argc, char **argv) {
    char cwd[256];
    printf("pid=%d ids=%d,%d cwd=%s\n", (int)getpid(), (int)getuid(), (int)getgid(),
           getcwd(cwd, sizeof cwd) ? cwd : "?");
    for (int i = 0; i < argc; i++) printf("argv[%d]=[%s]\n", i, argv[i]);
    for (char **e = environ; *e; e++) printf("env=[%s]\n", *e);
    fflush(stdout);
}

// Copies stdin to stdout until its end.
static int cat(void) {
    char buffer[256];
    ssize_t n;
    while ((n = read(0, buffer, sizeof buffer)) > 0)
        if (write(1, buffer, (size_t)n) != n) return 41;
    printf("eof\n");
    return 0;
}

static void on_term(int signal) {
    (void)signal;
    static const char message[] = "caught 15\n";
    if (write(1, message, sizeof message - 1)) {}
    _exit(7);
}

// Waits for SIGTERM and exits 7.
static int term(void) {
    struct sigaction action = {.sa_handler = on_term};
    sigaction(SIGTERM, &action, NULL);
    printf("ready\n");
    fflush(stdout);
    for (;;) pause();
}

static void report(int signal) {
    (void)signal;
    static const char message[] = "trapped\n";
    if (write(1, message, sizeof message - 1)) {}
}

// Reports each SIGTERM, and exits once its stdin ends.
static int trap(void) {
    struct sigaction action = {.sa_handler = report};
    sigaction(SIGTERM, &action, NULL);
    printf("ready\n");
    fflush(stdout);
    char buffer[256];
    ssize_t n;
    while ((n = read(0, buffer, sizeof buffer)) != 0)
        if (n < 0 && errno != EINTR) return 42;
    return 0;
}

// Forks a child that outlives this process, vforks and execs another that exits 5, and exits
// once its stdin ends.
static int family(char *self) {
    pid_t child = fork();
    if (child < 0) return 71;
    if (child == 0) {
        printf("child pid=%d\n", (int)getpid());
        fflush(stdout);
        for (;;) pause();
    }
    pid_t vchild = vfork();
    if (vchild < 0) return 72;
    if (vchild == 0) {
        char *argv[] = {"exec-child", "exit", "5", NULL};
        execv(self, argv);
        _exit(73);
    }
    int status = 0;
    if (waitpid(vchild, &status, 0) != vchild) return 74;
    printf("vfork child exited %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    fflush(stdout);
    char buffer[256];
    while (read(0, buffer, sizeof buffer) > 0) {}
    return 0;
}

static void *square(void *n) { return (void *)((long)n * (long)n); }

// Squares 2 and 3 in two threads, joins them, and prints the sum.
static int threads(void) {
    pthread_t thread[2];
    for (long i = 0; i < 2; i++)
        if (pthread_create(&thread[i], NULL, square, (void *)(i + 2)) != 0) return 91;
    long sum = 0;
    for (int i = 0; i < 2; i++) {
        void *square;
        if (pthread_join(thread[i], &square) != 0) return 92;
        sum += (long)square;
    }
    printf("threads=%ld\n", sum);
    return 0;
}

int main(int argc, char **argv) {
    describe(argc, argv);
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "exit") == 0) {
        fprintf(stderr, "stderr\n");
        return argc > 2 ? atoi(argv[2]) : 0;
    }
    if (strcmp(mode, "cat") == 0) return cat();
    if (strcmp(mode, "term") == 0) return term();
    if (strcmp(mode, "trap") == 0) return trap();
    if (strcmp(mode, "family") == 0) return family(argv[0]);
    if (strcmp(mode, "threads") == 0) return threads();
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
    if (strcmp(mode, "shm") == 0) {
        struct stat shm;
        if (stat("/dev/shm", &shm) != 0) return 61;
        printf("shm=%o\n", (unsigned)(shm.st_mode & 07777));
        return 0;
    }
    // Writes argv[3] to the new file argv[2].
    if (strcmp(mode, "write") == 0 && argc > 3) {
        FILE *file = fopen(argv[2], "w");
        if (!file || fputs(argv[3], file) < 0 || fclose(file) != 0) return 51;
        return 0;
    }
    for (;;) pause();
}
