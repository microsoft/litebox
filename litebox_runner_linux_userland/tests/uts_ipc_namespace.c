// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks creating UTS and IPC namespaces with `clone`, `clone3`, and `unshare`. Runs as guest root,
// or, with the argument `unprivileged`, as another user, who can't create them.
//
// LiteBox's host and domain names are fixed and it has no IPC objects, so nothing tells a new UTS
// or IPC namespace apart from its creator's. These checks see only whether creating one succeeds.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

// The code each new child exits with.
#define CHILD_CODE 7

static int failures;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// Creates a child like `fork`, with clone `flags` and `SIGCHLD` as its exit signal.
static pid_t clone_child(unsigned long flags) {
    return (pid_t)syscall(SYS_clone, flags | SIGCHLD, 0, 0, 0, 0);
}

// Creates a child like `fork` with `clone3`, with clone `flags` and `SIGCHLD` as its exit signal.
static pid_t clone3_child(uint64_t flags) {
    struct clone_args args = {.flags = flags, .exit_signal = SIGCHLD};
    return (pid_t)syscall(SYS_clone3, &args, sizeof args);
}

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// Creates a vfork-style child, as `posix_spawn` does, with clone `flags`, which runs `function`
// with `argument`.
static pid_t vfork_child(int flags, int (*function)(void *), void *argument) {
    return clone(function, vfork_stack + sizeof vfork_stack,
                 CLONE_VM | CLONE_VFORK | flags | SIGCHLD, argument);
}

// Returns whether `pid` exited with `code`.
static int exited_with(pid_t pid, int code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static int exit_now(void *unused) {
    (void)unused;
    _exit(CHILD_CODE);
}

// `clone`, `clone3`, and a vfork-style `clone` create children in new UTS and IPC namespaces.
static void clone_creates_namespaces(void) {
    pid_t child = clone_child(CLONE_NEWUTS | CLONE_NEWIPC);
    if (child == 0) {
        _exit(CHILD_CODE);
    }
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
    child = clone3_child(CLONE_NEWUTS | CLONE_NEWIPC);
    if (child == 0) {
        _exit(CHILD_CODE);
    }
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
    child = vfork_child(CLONE_NEWUTS | CLONE_NEWIPC, exit_now, NULL);
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
}

// Runs `check` in a new child, which `check` may change, and returns whether it returned 0.
static int in_a_child(int (*check)(void)) {
    pid_t child = fork();
    if (child == 0) {
        _exit(check());
    }
    return child > 0 && exited_with(child, 0);
}

static int unshare_alone(void) {
    return unshare(CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 1;
}

static int unshare_with_a_pid_namespace(void) {
    return unshare(CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 1;
}

// Waits for a byte from the pipe whose read end `fd` points to.
static void *wait_for_byte(void *fd) {
    char byte;
    return read(*(int *)fd, &byte, 1) == 1 ? NULL : fd;
}

static int unshare_with_another_thread(void) {
    int release[2];
    pthread_t thread;
    if (pipe(release) != 0 || pthread_create(&thread, NULL, wait_for_byte, &release[0]) != 0) {
        return 1;
    }
    int code = unshare(CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 2;
    if (write(release[1], "x", 1) != 1 || pthread_join(thread, NULL) != 0) {
        return 3;
    }
    return code;
}

// An `unshare` a vfork child makes: its flags, and the error it got, or 0.
struct vfork_unshare {
    int flags;
    int error;
};

// Runs in a vfork child: makes the `unshare` that `request`, a `struct vfork_unshare`, describes.
static int unshare_and_exit(void *request) {
    struct vfork_unshare *unshare_request = request;
    unshare_request->error = unshare(unshare_request->flags) == -1 ? errno : 0;
    _exit(CHILD_CODE);
}

// Calls `unshare(flags)` in a vfork-style child, returning the error it got, 0 if it succeeded, or
// -1 if the child didn't run as expected.
static int unshare_in_a_vfork_child(int flags) {
    struct vfork_unshare request = {flags, -1};
    pid_t child = vfork_child(0, unshare_and_exit, &request);
    if (child <= 0 || !exited_with(child, CHILD_CODE)) {
        return -1;
    }
    return request.error;
}

// `unshare` creates UTS and IPC namespaces, alone, with a PID namespace, with another thread, and
// in a vfork child.
static void unshare_creates_namespaces(void) {
    CHECK(in_a_child(unshare_alone));
    CHECK(in_a_child(unshare_with_a_pid_namespace));
    CHECK(in_a_child(unshare_with_another_thread));
    CHECK(unshare_in_a_vfork_child(CLONE_NEWUTS | CLONE_NEWIPC) == 0);
}

// Without root, neither `unshare` nor `clone`, also vfork-style, creates a UTS or IPC namespace.
static void unprivileged_creates_nothing(void) {
    const int flags[] = {CLONE_NEWUTS, CLONE_NEWIPC};
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        CHECK(unshare(flags[i]) == -1 && errno == EPERM);
        pid_t child = clone_child((unsigned long)flags[i]);
        if (child == 0) {
            _exit(CHILD_CODE);
        }
        CHECK(child == -1 && errno == EPERM);
        if (child > 0) {
            exited_with(child, CHILD_CODE);
        }
        child = vfork_child(flags[i], exit_now, NULL);
        CHECK(child == -1 && errno == EPERM);
        if (child > 0) {
            exited_with(child, CHILD_CODE);
        }
    }
    // LiteBox refuses `CLONE_NEWPID` in a vfork child, but only after the permission check.
    CHECK(unshare_in_a_vfork_child(CLONE_NEWPID | CLONE_NEWUTS) == EPERM);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "unprivileged") == 0) {
        unprivileged_creates_nothing();
        printf("uts-ipc-namespace unprivileged failures=%d\n", failures);
        return failures != 0;
    }
    clone_creates_namespaces();
    unshare_creates_namespaces();
    printf("uts-ipc-namespace failures=%d\n", failures);
    return failures != 0;
}
