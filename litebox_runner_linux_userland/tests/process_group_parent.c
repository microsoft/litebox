// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks process groups and sessions across forked and vforked children.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t usr1_count;
static volatile sig_atomic_t usr2_count;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static void on_usr1(int signal) {
    (void)signal;
    usr1_count++;
}

static void on_usr2(int signal) {
    (void)signal;
    usr2_count++;
}

// Unblocks `SIGUSR1` and `SIGUSR2` and waits until one of them is handled.
static void wait_for_signal(const sigset_t *blocked) {
    sigprocmask(SIG_UNBLOCK, blocked, NULL);
    // Sleeping briefly rather than pausing cannot miss a signal handled just before waiting.
    const struct timespec delay = {.tv_nsec = 1000000};
    while (usr1_count == 0 && usr2_count == 0) {
        nanosleep(&delay, NULL);
    }
}

// Forks a child that joins `process_group`, leads a new group if it is zero, or stays in this
// process's group if it is negative. The child exits with `code` once signaled.
static pid_t fork_member(pid_t process_group, int code, const sigset_t *blocked) {
    pid_t child = fork();
    if (child == 0) {
        if (process_group >= 0 && setpgid(0, process_group) != 0) {
            _exit(1);
        }
        wait_for_signal(blocked);
        _exit(code);
    }
    // Moving the child from the parent too makes its group known before either continues.
    if (child > 0 && process_group >= 0) {
        CHECK(setpgid(child, process_group == 0 ? child : process_group) == 0);
    }
    return child;
}

// Returns whether `kill(target, 0)` fails with `ESRCH` within five seconds. A reaped child stays
// visible to signals until LiteBox's supervision of it ends shortly after.
static int no_process_remains(pid_t target) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000; i++) {
        if (kill(target, 0) == -1 && errno == ESRCH) {
            return 1;
        }
        nanosleep(&delay, NULL);
    }
    return 0;
}

// Reaps a child selected by `pid`, returning its process ID and storing its exit code.
static pid_t reap(pid_t pid, int *code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    *code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return waited;
}

int main(void) {
    pid_t self = getpid();
    // LiteBox's initial process leads its own process group and session.
    CHECK(getpgrp() == self);
    CHECK(getpgid(0) == self);
    CHECK(getpgid(self) == self);
    CHECK(getsid(0) == self);
    CHECK(setsid() == -1 && errno == EPERM);
    CHECK(getpgid(-1) == -1 && errno == ESRCH);
    CHECK(getsid(-1) == -1 && errno == ESRCH);
    CHECK(getpgid(0x7fffff) == -1 && errno == ESRCH);
    CHECK(setpgid(0, -1) == -1 && errno == EINVAL);
    // Like Linux, a session leader cannot change its process group.
    CHECK(setpgid(0, 0) == -1 && errno == EPERM);

    struct sigaction action = {0};
    action.sa_handler = on_usr1;
    sigaction(SIGUSR1, &action, NULL);
    action.sa_handler = on_usr2;
    sigaction(SIGUSR2, &action, NULL);
    // Children start with both signals blocked, so none arrives before they wait for it.
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    sigprocmask(SIG_BLOCK, &blocked, NULL);

    // Two children in a new group and one in this process's group.
    pid_t leader = fork_member(0, 10, &blocked);
    pid_t member = fork_member(leader, 20, &blocked);
    pid_t sibling = fork_member(-1, 30, &blocked);
    CHECK(leader > 0 && member > 0 && sibling > 0);
    CHECK(getpgid(leader) == leader);
    CHECK(getpgid(member) == leader);
    CHECK(getpgid(sibling) == self);
    CHECK(getsid(member) == self);
    // A group must exist in the caller's session to be joined.
    CHECK(setpgid(sibling, 0x7fffff) == -1 && errno == EPERM);
    CHECK(kill(-leader, 0) == 0);
    CHECK(kill(-1, 0) == 0);

    // Signaling this process's group delivers to this process before `kill` returns.
    sigprocmask(SIG_UNBLOCK, &blocked, NULL);
    CHECK(kill(0, SIGUSR2) == 0);
    CHECK(usr2_count == 1);
    CHECK(usr1_count == 0);

    int code = 0;
    // Waiting for this process's group skips the other group's children.
    CHECK(reap(0, &code) == sibling && code == 30);
    CHECK(waitpid(0, NULL, WNOHANG) == -1 && errno == ECHILD);

    CHECK(kill(-leader, SIGUSR1) == 0);
    CHECK(usr1_count == 0);
    int codes = 0;
    for (int i = 0; i < 2; i++) {
        pid_t waited = reap(-leader, &code);
        CHECK(waited == leader || waited == member);
        codes += code;
    }
    CHECK(codes == 30);
    CHECK(waitpid(-leader, NULL, 0) == -1 && errno == ECHILD);
    CHECK(no_process_remains(-leader));

    // A forked child starts a session, after which it can neither start another nor be moved.
    int ready[2];
    int release[2];
    CHECK(pipe(ready) == 0 && pipe(release) == 0);
    pid_t session = fork();
    if (session == 0) {
        close(ready[0]);
        close(release[1]);
        char byte = 0;
        int ok = setsid() == getpid() && getsid(0) == getpid() && getpgrp() == getpid();
        ok = ok && setsid() == -1 && errno == EPERM;
        ok = ok && setpgid(0, self) == -1 && errno == EPERM;
        ok = ok && write(ready[1], &byte, 1) == 1 && read(release[0], &byte, 1) == 0;
        _exit(ok ? 40 : 41);
    }
    close(ready[1]);
    close(release[0]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(getsid(session) == session);
    CHECK(getpgid(session) == session);
    CHECK(setpgid(session, session) == -1 && errno == EPERM);
    close(release[1]);
    CHECK(reap(session, &code) == session && code == 40);

    // A vforked child starts a session before it exits.
    pid_t vforked = vfork();
    if (vforked == 0) {
        _exit(setsid() == getpid() && getsid(0) == getpid() && getpgid(0) == getpid() ? 50 : 51);
    }
    CHECK(reap(vforked, &code) == vforked && code == 50);

    // No other process remains to signal.
    CHECK(no_process_remains(-1));

    printf("process-group failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
