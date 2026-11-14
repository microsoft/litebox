// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int disposition_is(int signal, void (*handler)(int)) {
    struct sigaction action;
    return sigaction(signal, NULL, &action) == 0 && action.sa_handler == handler;
}

static volatile sig_atomic_t usr1_count;
static volatile pid_t usr1_pid;
static volatile int usr1_code;
static volatile int usr1_uid_matches;

static void on_usr1(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    usr1_count++;
    usr1_pid = info->si_pid;
    usr1_code = info->si_code;
    usr1_uid_matches = info->si_uid == getuid();
}

// Takes `signal` if it is pending for this thread or its process, without waiting, storing its
// siginfo at `info`.
static int take_now(int signal, siginfo_t *info) {
    static const struct timespec no_wait;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signal);
    return sigtimedwait(&set, info, &no_wait);
}

static int usr1_from_self;
static int pipe_from_worker;

// Runs in a thread other than the one that started the program.
static void *take_from_worker(void *unused) {
    siginfo_t info;
    usr1_from_self = take_now(SIGUSR1, &info) == SIGUSR1 && info.si_code == SI_USER &&
                     info.si_pid == getpid();
    pipe_from_worker = !(take_now(SIGPIPE, &info) == -1 && errno == EAGAIN);
    return unused;
}

// Returns whether a child exiting with `code` is reaped automatically instead of being waitable.
static int child_is_reaped(int code) {
    pid_t child = vfork();
    if (child == 0) {
        _exit(code);
    }
    if (child < 0) {
        perror("vfork");
        exit(4);
    }
    return waitpid(child, NULL, 0) == -1 && errno == ECHILD;
}

int main(int argc, char **argv) {
    const char *marker = argc > 1 ? argv[1] : "";
    if (strcmp(marker, "abort") == 0) {
        abort();
    }
    if (strcmp(marker, "gate") == 0 && argc > 2) {
        while (access(argv[2], F_OK) != 0) {
            usleep(1000);
        }
        return 42;
    }
    if (strcmp(marker, "sleep") == 0) {
        usleep(100 * 1000);
        return 42;
    }
    if (strcmp(marker, "kill-wait") == 0) {
        sleep(5);
        return 42;
    }
    if (strcmp(marker, "kill-handshake") == 0) {
        struct sigaction action = {.sa_sigaction = on_usr1, .sa_flags = SA_SIGINFO};
        if (sigaction(SIGUSR1, &action, NULL) != 0) {
            perror("sigaction");
            return 3;
        }
        if (kill(getppid(), SIGUSR2) != 0) {
            perror("kill");
            return 4;
        }
        for (int i = 0; i < 5000 && usr1_count == 0; i++) {
            usleep(1000);
        }
        printf("child-kill count=%d pid=%d ppid=%d code=%d uid=%d\n", usr1_count, usr1_pid,
               getppid(), usr1_code, usr1_uid_matches);
        return 42;
    }
    if (strcmp(marker, "reap-inherited") == 0) {
        printf("reap-inherited reaped=%d\n", child_is_reaped(24));
        return 42;
    }
    if (strcmp(marker, "reap-nocldwait") == 0) {
        struct sigaction action = {.sa_handler = SIG_DFL, .sa_flags = SA_NOCLDWAIT};
        if (sigaction(SIGCHLD, &action, NULL) != 0) {
            perror("sigaction");
            return 3;
        }
        execl(argv[0], argv[0], "reap-reset", (char *)NULL);
        perror("execl");
        return 5;
    }
    if (strcmp(marker, "reap-reset") == 0) {
        printf("reap-reset reaped=%d\n", child_is_reaped(25));
        return 42;
    }
    if (strcmp(marker, "signals") == 0) {
        sigset_t blocked;
        sigset_t pending;
        sigprocmask(SIG_BLOCK, NULL, &blocked);
        sigpending(&pending);
        // A signal pending for the process reaches any thread, and one pending for the thread
        // that called `execve` only the main thread.
        pthread_t worker;
        if (pthread_create(&worker, NULL, take_from_worker, NULL) != 0 ||
            pthread_join(worker, NULL) != 0) {
            return 6;
        }
        siginfo_t info;
        int pipe_from_main = take_now(SIGPIPE, &info) == SIGPIPE;
        int rt_without_sender =
            take_now(SIGRTMIN, &info) == SIGRTMIN && info.si_code == SI_USER && info.si_pid == 0;
        printf("child-signals pipe_ignored=%d hup_ignored=%d usr2_default=%d "
               "ill_default=%d term_blocked=%d usr2_blocked=%d usr1_pending=%d term_pending=%d "
               "usr1_from_self=%d pipe_from_worker=%d pipe_from_main=%d rt_without_sender=%d\n",
               disposition_is(SIGPIPE, SIG_IGN), disposition_is(SIGHUP, SIG_IGN),
               disposition_is(SIGUSR2, SIG_DFL), disposition_is(SIGILL, SIG_DFL),
               sigismember(&blocked, SIGTERM), sigismember(&blocked, SIGUSR2),
               sigismember(&pending, SIGUSR1), sigismember(&pending, SIGTERM), usr1_from_self,
               pipe_from_worker, pipe_from_main, rt_without_sender);
        return 42;
    }
    if (strcmp(marker, "fds") == 0 && argc > 4) {
        int log = atoi(argv[2]);
        int stdin_alias = atoi(argv[3]);
        int hidden = atoi(argv[4]);
        printf("child-fds via-stdout\n");
        fflush(stdout);
        dprintf(log, "child-fds via-log\n");
        int stdin_flags = fcntl(stdin_alias, F_GETFL);
        int stdin_setfl =
            stdin_flags >= 0 && fcntl(stdin_alias, F_SETFL, stdin_flags | O_NONBLOCK) == 0;
        int hidden_closed = fcntl(hidden, F_GETFD) == -1 && errno == EBADF;
        printf("child-fds stdin_setfl=%d hidden_closed=%d\n", stdin_setfl, hidden_closed);
        return 42;
    }
    if ((strcmp(marker, "unix-fd") == 0 || strcmp(marker, "inet-fd") == 0) && argc > 3) {
        int socket_fd = atoi(argv[2]);
        int hidden = atoi(argv[3]);
        int type = 0;
        socklen_t length = sizeof type;
        int is_stream = getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
                        type == SOCK_STREAM;
        int sent = write(socket_fd, "exec", 4) == 4;
        char reply[8] = {0};
        // Bounded like the parent's waits, so a lost reply fails instead of hanging.
        struct pollfd poll_fd = {.fd = socket_fd, .events = POLLIN};
        int replied = poll(&poll_fd, 1, 30000) == 1 &&
                      read(socket_fd, reply, sizeof reply - 1) == 5 && strcmp(reply, "reply") == 0;
        int hidden_closed = fcntl(hidden, F_GETFD) == -1 && errno == EBADF;
        printf("child-%.4s stream=%d sent=%d replied=%d hidden_closed=%d\n", marker, is_stream,
               sent, replied, hidden_closed);
        return 42;
    }
    if (strcmp(marker, "stdout-mode") == 0) {
        printf("child-stdout wronly=%d\n", (fcntl(1, F_GETFL) & O_ACCMODE) == O_WRONLY);
        marker = "open-fds";
    }
    if (strcmp(marker, "open-fds") == 0) {
        printf("child-open-fds");
        for (int fd = 0; fd < 64; fd++) {
            if (fcntl(fd, F_GETFD) != -1) {
                printf(" %d", fd);
            }
        }
        printf("\n");
        return 42;
    }
    if (strcmp(marker, "cat") == 0) {
        int flags = fcntl(0, F_GETFL);
        size_t total = 0;
        int ok = 1;
        char buffer[4096];
        for (;;) {
            struct pollfd readable = {.fd = 0, .events = POLLIN};
            if (poll(&readable, 1, -1) != 1) {
                ok = 0;
                break;
            }
            ssize_t n = read(0, buffer, sizeof buffer);
            if (n == 0) {
                break;
            }
            if (n < 0) {
                ok &= errno == EAGAIN;
                continue;
            }
            for (ssize_t i = 0; i < n; i++) {
                ok &= buffer[i] == 'a' + (total + i) % 26;
            }
            total += n;
        }
        ok &= fcntl(0, F_SETFL, flags & ~O_NONBLOCK) == 0;
        printf("child-cat bytes=%zu ok=%d rdonly=%d nonblock=%d\n", total, ok,
               (flags & O_ACCMODE) == O_RDONLY, (flags & O_NONBLOCK) != 0);
        return 42;
    }
    if (strcmp(marker, "read-byte") == 0) {
        char byte = 0;
        ssize_t n = read(0, &byte, 1);
        printf("child-read-byte n=%zd byte=%c\n", n, byte);
        return 42;
    }
    const char *environment = getenv("VFORK_EXEC_TEST");
    printf("child pid=%d ppid=%d tid=%ld marker=%s env=%s\n", getpid(),
           getppid(), syscall(SYS_gettid), marker,
           environment == NULL ? "" : environment);
    return 42;
}
