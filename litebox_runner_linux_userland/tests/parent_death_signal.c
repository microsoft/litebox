// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks `prctl(PR_SET_PDEATHSIG)` and `prctl(PR_GET_PDEATHSIG)`: invalid arguments, the signal
// sent when the parent exits, and how fork, vfork and execve carry the setting. Usage:
// parent_death_signal [exec-child SIGNAL]; an exec-child exits 0 if its setting is SIGNAL.

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static int failures;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// This program's path, which children exec.
static char *self_path;

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// Calls `prctl` directly, with the unused arguments zero.
static long pr(int option, unsigned long arg2) {
    return syscall(SYS_prctl, option, arg2, 0, 0, 0);
}

static int set_death_signal(unsigned long signal) {
    return pr(PR_SET_PDEATHSIG, signal) == 0;
}

// Returns this process's parent-death signal, or -1 if it can't be read.
static int death_signal(void) {
    int value = -1;
    return pr(PR_GET_PDEATHSIG, (unsigned long)&value) == 0 ? value : -1;
}

// Waits for `pid`, returning whether it exited with `code`.
static int exited_with(pid_t pid, int code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static void invalid_arguments_fail(void) {
    CHECK(death_signal() == 0);
    errno = 0;
    CHECK(pr(PR_SET_PDEATHSIG, 65) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(pr(PR_SET_PDEATHSIG, (1UL << 32) | SIGUSR1) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(pr(PR_GET_PDEATHSIG, 1) == -1 && errno == EFAULT);
    CHECK(death_signal() == 0);
    CHECK(set_death_signal(64) && death_signal() == 64);
    CHECK(set_death_signal(0) && death_signal() == 0);
}

// A forked child starts with no parent-death signal.
static void fork_child_starts_with_none(void) {
    CHECK(set_death_signal(SIGUSR2));
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        _exit(death_signal() == 0 ? 0 : 1);
    }
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(death_signal() == SIGUSR2 && set_death_signal(0));
}

// Runs in a child whose parent `parent` exits once it writes to `ready`: checks that the signal
// arrives from the exiting parent, after the child has moved to `reaper`.
static int await_death_signal(pid_t parent, pid_t reaper, int ready) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0 || !set_death_signal(SIGUSR1)) {
        return 1;
    }
    if (getppid() != parent || write(ready, "x", 1) != 1) {
        return 2;
    }
    // glibc's sigtimedwait rewrites some codes, so ask the kernel directly.
    struct timespec timeout = {.tv_sec = 10};
    siginfo_t info;
    memset(&info, 0, sizeof info);
    long received;
    do {
        received = syscall(SYS_rt_sigtimedwait, &set, &info, &timeout, 8);
    } while (received == -1 && errno == EINTR);
    if (received != SIGUSR1) {
        return 3;
    }
    if (info.si_code != SI_USER || info.si_pid != parent || info.si_uid != getuid()) {
        return 4;
    }
    return getppid() == reaper && death_signal() == SIGUSR1 ? 0 : 5;
}

// The signal is sent to a child when its parent exits.
static void parent_exit_sends_the_signal(void) {
    pid_t reaper = getpid();
    CHECK(pr(PR_SET_CHILD_SUBREAPER, 1) == 0);
    fflush(stdout);
    pid_t parent = fork();
    if (parent == 0) {
        // Exits once its child is ready.
        int ready[2];
        if (pipe(ready) != 0) {
            _exit(1);
        }
        pid_t self = getpid();
        pid_t child = fork();
        if (child == 0) {
            close(ready[0]);
            _exit(await_death_signal(self, reaper, ready[1]));
        }
        close(ready[1]);
        char byte;
        _exit(child > 0 && read(ready[0], &byte, 1) == 1 ? 0 : 2);
    }
    CHECK(parent > 0 && exited_with(parent, 0));
    int status = 0;
    pid_t orphan = wait(&status);
    if (!(orphan > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        printf("orphan status=%#x\n", status);
        failures++;
    }
    CHECK(pr(PR_SET_CHILD_SUBREAPER, 0) == 0);
}

static int vfork_child_sets_its_own(void *arg) {
    if (death_signal() != 0 || !set_death_signal(SIGUSR1) || death_signal() != SIGUSR1) {
        _exit(1);
    }
    char expected[4];
    snprintf(expected, sizeof expected, "%d", SIGUSR1);
    char *const argv[] = {self_path, "exec-child", expected, NULL};
    execve(self_path, argv, environ);
    _exit(2);
}

// A vfork child starts with none and sets its own, which the program it runs keeps, while its
// parent's stays as it was.
static void vfork_child_sets_its_own_and_execve_keeps_it(void) {
    CHECK(set_death_signal(SIGUSR2));
    pid_t child = clone(vfork_child_sets_its_own, vfork_stack + sizeof vfork_stack,
                        CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(death_signal() == SIGUSR2 && set_death_signal(0));
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "exec-child") == 0) {
        return death_signal() == atoi(argv[2]) ? 0 : 1;
    }
    self_path = argv[0];
    setvbuf(stdout, NULL, _IONBF, 0);
    invalid_arguments_fail();
    fork_child_starts_with_none();
    parent_exit_sends_the_signal();
    vfork_child_sets_its_own_and_execve_keeps_it();
    printf("parent-death-signal failures=%d\n", failures);
    return failures != 0;
}
