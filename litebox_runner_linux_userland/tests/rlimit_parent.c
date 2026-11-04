// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that every resource limit can be read and set, that fork, vfork, and execve keep the
// limits and descriptors above a lowered NOFILE limit, that a vfork child's limits are its own,
// and that real-time signals queue.
// Usage: rlimit_parent [child]; with "child", exits 0 if the inherited limits are as expected.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

// Limits set before creating children, which every child must inherit.
#define CORE_MAX 12345
#define NOFILE_CUR 200
// A descriptor opened before lowering NOFILE_CUR below it, which every child must keep.
#define HIGH_FD 250
#define RT_SIGNALS 3

extern char **environ;

static int failures;

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            printf("FAIL line %d: %s\n", __LINE__, #condition);                             \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

static struct rlimit get(int resource) {
    struct rlimit limit;
    if (getrlimit(resource, &limit) != 0) {
        perror("getrlimit");
        exit(1);
    }
    return limit;
}

static int set(int resource, rlim_t cur, rlim_t max) {
    struct rlimit limit = {cur, max};
    return setrlimit(resource, &limit) == 0 ? 0 : errno;
}

static int has_inherited_limits(void) {
    struct rlimit core = get(RLIMIT_CORE);
    return core.rlim_cur == 0 && core.rlim_max == CORE_MAX &&
           get(RLIMIT_NOFILE).rlim_cur == NOFILE_CUR && fcntl(HIGH_FD, F_GETFD) != -1;
}

static pid_t fork_flushed(void) {
    fflush(stdout);
    return fork();
}

// Waits for `child`, returning its exit code, or -1 if it did not exit normally.
static int wait_code(pid_t child) {
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static volatile sig_atomic_t rt_deliveries;

static void on_rt_signal(int signal) {
    (void)signal;
    rt_deliveries++;
}

static void check_get_and_set(void) {
    for (int resource = 0; resource < RLIM_NLIMITS; resource++) {
        struct rlimit limit = get(resource);
        CHECK(limit.rlim_cur <= limit.rlim_max);
        CHECK(set(resource, limit.rlim_cur, limit.rlim_max) == 0);
        struct rlimit old;
        CHECK(prlimit(0, resource, NULL, &old) == 0);
        CHECK(old.rlim_cur == limit.rlim_cur && old.rlim_max == limit.rlim_max);
    }
    CHECK(get(RLIMIT_SIGPENDING).rlim_cur > 0);
    struct rlimit limit;
    CHECK(getrlimit(RLIM_NLIMITS, &limit) == -1 && errno == EINVAL);

    CHECK(set(RLIMIT_CORE, 0, CORE_MAX) == 0);
    CHECK(set(RLIMIT_CORE, 1, 0) == EINVAL);
    CHECK(set(RLIMIT_CORE, 0, CORE_MAX + 1) == EPERM);
    struct rlimit core = get(RLIMIT_CORE);
    CHECK(core.rlim_cur == 0 && core.rlim_max == CORE_MAX);
    CHECK(dup2(STDOUT_FILENO, HIGH_FD) == HIGH_FD);
    CHECK(set(RLIMIT_NOFILE, NOFILE_CUR, get(RLIMIT_NOFILE).rlim_max) == 0);
    CHECK(prlimit(0, RLIMIT_CORE, NULL, (struct rlimit *)8) == -1 && errno == EFAULT);
    CHECK(prlimit(0, RLIMIT_CORE, (struct rlimit *)8, NULL) == -1 && errno == EFAULT);
}

static void check_fork(char *self) {
    pid_t child = fork_flushed();
    if (child == 0) {
        _exit(has_inherited_limits() ? 0 : 1);
    }
    CHECK(child > 0 && wait_code(child) == 0);

    child = fork_flushed();
    if (child == 0) {
        char *argv[] = {self, "child", NULL};
        execv(self, argv);
        _exit(2);
    }
    CHECK(child > 0 && wait_code(child) == 0);
}

static void check_vfork(char *self) {
    fflush(stdout);
    pid_t child = vfork();
    if (child == 0) {
        int inherited = has_inherited_limits();
        struct rlimit core = {1, CORE_MAX};
        _exit(inherited && setrlimit(RLIMIT_CORE, &core) == 0 ? 0 : 1);
    }
    CHECK(child > 0 && wait_code(child) == 0);
    // The child's change was its own.
    CHECK(get(RLIMIT_CORE).rlim_cur == 0);

    char *argv[] = {self, "child", NULL};
    fflush(stdout);
    CHECK(posix_spawn(&child, self, NULL, NULL, argv, environ) == 0);
    CHECK(wait_code(child) == 0);
}

static void check_rt_signals(void) {
    int signal = SIGRTMIN;
    struct sigaction action = {.sa_handler = on_rt_signal};
    CHECK(sigaction(signal, &action, NULL) == 0);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signal);
    CHECK(sigprocmask(SIG_BLOCK, &set, NULL) == 0);
    for (int i = 0; i < RT_SIGNALS; i++) {
        CHECK(kill(getpid(), signal) == 0);
    }
    CHECK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0);
    CHECK(rt_deliveries == RT_SIGNALS);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        return has_inherited_limits() ? 0 : 1;
    }
    check_get_and_set();
    check_fork(argv[0]);
    check_vfork(argv[0]);
    check_rt_signals();
    printf("rlimit failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
