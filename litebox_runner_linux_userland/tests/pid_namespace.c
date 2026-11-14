// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks PID namespaces: creating them with `clone` and `unshare`, the IDs processes see in them,
// orphans, the first process's signal rules and exit, and `CLONE_PARENT`. Runs as guest root, or,
// with the argument `unprivileged`, as another user, who can't create namespaces.
//
// Unlike Linux, LiteBox keeps the PID namespace for a process's children per process, so
// `unshare(CLONE_NEWPID)` fails in a process with more than one thread, and in a vfork child, whose
// requests go to the broker as its parent's.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

// Creates a child like `fork` with `clone3`, with clone `flags` and `exit_signal`.
static pid_t clone3_child(uint64_t flags, uint64_t exit_signal) {
    struct clone_args args = {.flags = flags, .exit_signal = exit_signal};
    return (pid_t)syscall(SYS_clone3, &args, sizeof args);
}

// Waits for the child selected by `pid`, returning its process ID and storing its wait status.
static pid_t reap(pid_t pid, int *status) {
    pid_t waited;
    do {
        waited = waitpid(pid, status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited;
}

// Returns whether `pid` exited with `code`.
static int exited_with(pid_t pid, int code) {
    int status = 0;
    return reap(pid, &status) == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

// Waits up to five seconds for this process's parent to stop being `parent`, returning the new
// parent.
static pid_t wait_for_new_parent(pid_t parent) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000 && getppid() == parent; i++) {
        nanosleep(&delay, NULL);
    }
    return getppid();
}

// Reads one byte from `fd`, waiting up to five seconds, and returns whether one arrived.
static int read_byte(int fd) {
    struct pollfd readable = {.fd = fd, .events = POLLIN};
    char byte;
    int ready;
    do {
        ready = poll(&readable, 1, 5000);
    } while (ready == -1 && errno == EINTR);
    return ready == 1 && read(fd, &byte, 1) == 1;
}

static void sleep_ms(long milliseconds) {
    const struct timespec delay = {.tv_nsec = milliseconds * 1000000};
    nanosleep(&delay, NULL);
}

static void *no_op(void *argument) { return argument; }

// Waits for a byte from the pipe whose read end `fd` points to.
static void *wait_for_byte(void *fd) {
    char byte;
    return read(*(int *)fd, &byte, 1) == 1 ? NULL : fd;
}

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// The process ID a vfork-style child saw before `execve`, which it reports through the memory it
// shares with its parent.
static volatile pid_t vfork_child_pid;

// This program's path, which children exec.
static char *self_path;

// Runs in a vfork-style child on its own stack, as `posix_spawn`'s child does. Records the child's
// own process ID, checks that its parent is outside its namespace, so it sees none, then execs this
// program to check that it keeps the ID after `execve`.
static int exec_identity_check(void *unused) {
    (void)unused;
    char pid[16];
    vfork_child_pid = getpid();
    if (getppid() != 0 || syscall(SYS_gettid) != vfork_child_pid) {
        _exit(3);
    }
    // Its parent's group and session are outside its namespace too, so it sees them as 0, while a
    // group it leads has its own ID.
    if (getpgid(0) != 0 || getsid(0) != 0 || setpgid(0, 0) != 0 || getpgrp() != vfork_child_pid) {
        _exit(4);
    }
    // Alone in a new namespace, it sees no other process.
    if (vfork_child_pid == 1 && (getpgid(2) != -1 || errno != ESRCH)) {
        _exit(5);
    }
    snprintf(pid, sizeof pid, "%d", (int)vfork_child_pid);
    char *const argv[] = {self_path, "identity", pid, NULL};
    execve(self_path, argv, NULL);
    _exit(2);
}

// Creates a vfork-style child, with clone `flags`, that runs `exec_identity_check`.
static pid_t vfork_identity_check(unsigned long flags) {
    vfork_child_pid = 0;
    return clone(exec_identity_check, vfork_stack + sizeof vfork_stack,
                 CLONE_VM | CLONE_VFORK | flags | SIGCHLD, NULL);
}

// A child created in a new namespace is its first process, 1, and sees no parent; its parent sees
// it under another ID and collects it.
static void clone_makes_a_first_process(void) {
    pid_t child = clone_child(CLONE_NEWPID);
    if (child == 0) {
        _exit(getpid() == 1 && getppid() == 0 ? 0 : 1);
    }
    CHECK(child > 1);
    CHECK(exited_with(child, 0));
}

// After `unshare`, the caller keeps its ID, its next child is the new namespace's first process,
// and the children after it join that namespace. Orphans there go to the first process, and once
// it is gone, no process can join the namespace.
static int unshare_sends_children_to_a_new_namespace(void) {
    pid_t self = getpid();
    if (unshare(CLONE_NEWPID) != 0 || getpid() != self) {
        return 10;
    }
    // Another namespace can't nest in the new one, through `unshare` or `clone`, and a new thread
    // can't be created, since it would be in the new namespace rather than its process's.
    if (unshare(CLONE_NEWPID) == 0 || errno != EINVAL) {
        return 11;
    }
    pid_t nested = clone_child(CLONE_NEWPID);
    if (nested == 0) {
        _exit(0);
    }
    if (nested != -1 || errno != EINVAL) {
        return 18;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, no_op, NULL) != EINVAL) {
        return 12;
    }
    int go[2];
    if (pipe(go) != 0) {
        return 13;
    }
    pid_t first = fork();
    if (first == 0) {
        if (getpid() != 1 || getppid() != 0 || !read_byte(go[0])) {
            _exit(1);
        }
        // The second child's orphan is this process's now.
        int status = 0;
        _exit(reap(-1, &status) > 1 && WIFEXITED(status) ? WEXITSTATUS(status) : 2);
    }
    pid_t second = fork();
    if (second == 0) {
        pid_t second_self = getpid();
        pid_t orphan = fork();
        if (orphan == 0) {
            _exit(wait_for_new_parent(second_self) == 1 ? 0 : 3);
        }
        // Its parent is outside the namespace.
        _exit(second_self > 1 && getppid() == 0 ? 0 : 1);
    }
    if (first <= 0 || second <= 0 || !exited_with(second, 0)) {
        return 14;
    }
    // A vfork-style child joins the namespace too, and sees its ID there before `execve`.
    pid_t spawned = vfork_identity_check(0);
    if (spawned <= 0 || vfork_child_pid <= 1 || !exited_with(spawned, 0)) {
        return 17;
    }
    if (write(go[1], "x", 1) != 1 || !exited_with(first, 0)) {
        return 15;
    }
    // The namespace ended with its first process.
    pid_t too_late = fork();
    if (too_late == 0) {
        _exit(0);
    }
    return too_late == -1 && errno == ENOMEM ? 0 : 16;
}

// Unlike Linux, `unshare(CLONE_NEWPID)` fails in a process with another thread.
static int unshare_with_another_thread(void) {
    int release[2];
    pthread_t thread;
    if (pipe(release) != 0 || pthread_create(&thread, NULL, wait_for_byte, &release[0]) != 0) {
        return 1;
    }
    int code = unshare(CLONE_NEWPID) == -1 && errno == EINVAL ? 0 : 2;
    if (write(release[1], "x", 1) != 1 || pthread_join(thread, NULL) != 0) {
        return 3;
    }
    return code;
}

// Runs `unshare_with_another_thread` in a child, which a successful unshare would leave changed.
static void unshare_needs_a_single_thread(void) {
    pid_t helper = fork();
    if (helper == 0) {
        _exit(unshare_with_another_thread());
    }
    CHECK(exited_with(helper, 0));
}

// Records the result of `unshare(CLONE_NEWPID)` in a vfork child at `result`.
static int unshare_in_a_vfork_child(void *result) {
    *(int *)result = unshare(CLONE_NEWPID) == -1 ? errno : 0;
    _exit(0);
}

// Unlike Linux, `unshare(CLONE_NEWPID)` fails in a vfork child, whose requests go to the broker as
// its parent's. Runs in a helper, which a successful unshare would leave changed.
static void unshare_fails_in_a_vfork_child(void) {
    pid_t helper = fork();
    if (helper == 0) {
        int result = -1;
        pid_t child = clone(unshare_in_a_vfork_child, vfork_stack + sizeof vfork_stack,
                            CLONE_VM | CLONE_VFORK | SIGCHLD, &result);
        _exit(child > 0 && exited_with(child, 0) && result == EINVAL ? 0 : 1);
    }
    CHECK(exited_with(helper, 0));
}

// Runs `unshare_sends_children_to_a_new_namespace` in a child, which the unshare leaves changed.
static void unshare_makes_a_namespace_for_children(void) {
    pid_t helper = fork();
    if (helper == 0) {
        _exit(unshare_sends_children_to_a_new_namespace());
    }
    int status = 0;
    CHECK(reap(helper, &status) == helper && WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        printf("unshare case failed code=%d\n", WEXITSTATUS(status));
        failures++;
    }
}

static volatile sig_atomic_t usr2_handled;

static void on_usr2(int signal) {
    (void)signal;
    usr2_handled = 1;
}

// Runs in a vfork-style child, and faults without a handler.
static int fault_now(void *unused) {
    (void)unused;
    *(volatile int *)0 = 0;
    _exit(0);
}

// Returns whether `signal` is pending for this process.
static int is_pending(int signal) {
    sigset_t pending;
    return sigpending(&pending) == 0 && sigismember(&pending, signal) == 1;
}

// The first process of a namespace takes no signal it has no handler for, except `SIGKILL` from
// an ancestor namespace; `kill(-1)` from inside spares it. A signal it handles still arrives, and
// one it blocks stays pending until unblocked, when it is dropped instead of taking its default
// action. A vfork-style child that faults dies of it without ending its parent's exemption.
static void the_first_process_ignores_unhandled_signals(void) {
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        close(ready[0]);
        signal(SIGUSR2, on_usr2);
        sigset_t usr1;
        sigemptyset(&usr1);
        sigaddset(&usr1, SIGUSR1);
        sigprocmask(SIG_BLOCK, &usr1, NULL);
        // The signals below check that the parent keeps its exemption.
        pid_t faulty = clone(fault_now, vfork_stack + sizeof vfork_stack,
                             CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        int status = 0;
        int faulty_died = faulty > 0 && reap(faulty, &status) == faulty && WIFSIGNALED(status) &&
                          WTERMSIG(status) == SIGSEGV;
        pid_t victim = fork();
        if (victim == 0) {
            pause();
            _exit(0);
        }
        pid_t sender = fork();
        if (sender == 0) {
            kill(1, SIGTERM);
            kill(1, SIGKILL);
            kill(1, SIGUSR1);
            kill(1, SIGUSR2);
            _exit(kill(-1, SIGKILL) == 0 ? 0 : 1);
        }
        raise(SIGTERM);
        int code = exited_with(sender, 0) ? 0 : 1;
        if (reap(victim, &status) != victim || !WIFSIGNALED(status) ||
            WTERMSIG(status) != SIGKILL) {
            code = 2;
        }
        if (!faulty_died) {
            code = 7;
        } else if (!usr2_handled) {
            code = 4;
        } else if (!is_pending(SIGUSR1)) {
            code = 5;
        } else if (sigprocmask(SIG_UNBLOCK, &usr1, NULL) != 0 || is_pending(SIGUSR1)) {
            code = 6;
        }
        // Still here: report it, then wait for the parent's `SIGKILL`.
        char byte = (char)code;
        if (write(ready[1], &byte, 1) != 1) {
            _exit(3);
        }
        for (;;) {
            pause();
        }
    }
    close(ready[1]);
    char code = -1;
    CHECK(first > 0 && read(ready[0], &code, 1) == 1 && code == 0);
    close(ready[0]);
    // A signal it has no handler for is ignored even from the parent namespace.
    CHECK(kill(first, SIGTERM) == 0);
    sleep_ms(100);
    int status = 0;
    CHECK(waitpid(first, &status, WNOHANG) == 0);
    CHECK(kill(first, SIGKILL) == 0);
    CHECK(reap(first, &status) == first && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

// A fault the first process doesn't handle ends its exemption from default actions, so it dies
// of it.
static void the_first_process_dies_of_an_unhandled_fault(void) {
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        *(volatile int *)0 = 0;
        _exit(0);
    }
    int status = 0;
    CHECK(reap(first, &status) == first && WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
}

// `SIGKILL` from the parent namespace gets past the first process's exemption through `tgkill`
// too. Otherwise, it exits on its own.
static void tgkill_from_outside_kills_the_first_process(void) {
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        sleep(5);
        _exit(0);
    }
    CHECK(syscall(SYS_tgkill, first, first, SIGKILL) == 0);
    int status = 0;
    CHECK(reap(first, &status) == first && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

// When the first process exits, the rest of its namespace is killed, and its parent collects it
// only once they are gone.
static void the_namespace_ends_with_its_first_process(void) {
    int alive[2];
    CHECK(pipe(alive) == 0);
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        close(alive[0]);
        pid_t other = fork();
        if (other == 0) {
            // Holds the pipe's write end until it is killed.
            pause();
            _exit(0);
        }
        close(alive[1]);
        _exit(other > 0 ? 7 : 8);
    }
    close(alive[1]);
    CHECK(exited_with(first, 7));
    // The other process is gone, so the pipe has no writer left.
    struct pollfd readable = {.fd = alive[0], .events = POLLIN};
    char byte;
    CHECK(poll(&readable, 1, 0) == 1 && read(alive[0], &byte, 1) == 0);
    close(alive[0]);
}

// `CLONE_PARENT` makes the child the caller's sibling, which the caller's parent collects, even
// from a process whose parent is outside its namespace; no namespace's first process may use it.
static void clone_parent_makes_a_sibling(void) {
    // This process is its namespace's first process.
    CHECK(clone_child(CLONE_PARENT) == -1 && errno == EINVAL);
    int report[2];
    CHECK(pipe(report) == 0);
    pid_t helper = fork();
    if (helper == 0) {
        // Like runc: `unshare` a new namespace for children, then create a sibling as its first
        // process.
        if (unshare(CLONE_NEWPID) != 0) {
            _exit(1);
        }
        pid_t sibling = clone_child(CLONE_PARENT);
        if (sibling == 0) {
            _exit(getpid() == 1 && getppid() == 0 ? 0 : 1);
        }
        // `clone3` takes no exit signal for a sibling.
        if (clone3_child(CLONE_PARENT, SIGCHLD) != -1 || errno != EINVAL) {
            _exit(2);
        }
        _exit(write(report[1], &sibling, sizeof sibling) == sizeof sibling ? 0 : 3);
    }
    pid_t sibling = 0;
    CHECK(exited_with(helper, 0));
    CHECK(read(report[0], &sibling, sizeof sibling) == sizeof sibling && sibling > 0);
    CHECK(sibling > 0 && exited_with(sibling, 0));
    close(report[0]);
    close(report[1]);
    // From a namespace's first process, it fails.
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        _exit(clone3_child(CLONE_PARENT, 0) == -1 && errno == EINVAL ? 0 : 1);
    }
    CHECK(exited_with(first, 0));
}

// A vfork-style child with a new namespace is its first process, before and after `execve`.
static void vfork_makes_a_first_process(void) {
    pid_t child = vfork_identity_check(CLONE_NEWPID);
    CHECK(child > 1);
    CHECK(vfork_child_pid == 1);
    CHECK(exited_with(child, 0));
}

// Runs in a vfork-style child with a new namespace, and exits with whether it could signal itself.
static int kill_own_id(void *unused) {
    (void)unused;
    _exit(kill(1, SIGKILL) == 0 ? 0 : 1);
}

// A vfork-style child with a new namespace may signal itself by its own ID, 1, which is also this
// process's, and, as its namespace's first process, ignores its own `SIGKILL`. Run from the test's
// root, which is the first process of its own namespace.
static void a_vfork_first_process_ignores_its_own_sigkill(void) {
    CHECK(getpid() == 1);
    pid_t child = clone(kill_own_id, vfork_stack + sizeof vfork_stack,
                        CLONE_VM | CLONE_VFORK | CLONE_NEWPID | SIGCHLD, NULL);
    CHECK(child > 1);
    CHECK(exited_with(child, 0));
}

// Without root, neither `unshare` nor `clone` creates a namespace.
static int unprivileged_creates_no_namespace(void) {
    int code = unshare(CLONE_NEWPID) == -1 && errno == EPERM ? 0 : 1;
    pid_t child = clone_child(CLONE_NEWPID);
    if (child == 0) {
        _exit(0);
    }
    if (child != -1 || errno != EPERM) {
        code = 2;
    }
    printf("pid-namespace unprivileged code=%d\n", code);
    return code;
}

int main(int argc, char **argv) {
    // A child checks that it has the ID it saw before `execve`, and no parent.
    if (argc > 2 && strcmp(argv[1], "identity") == 0) {
        return getpid() == atoi(argv[2]) && getppid() == 0 ? 0 : 1;
    }
    if (argc > 1 && strcmp(argv[1], "unprivileged") == 0) {
        return unprivileged_creates_no_namespace();
    }
    self_path = argv[0];
    setvbuf(stdout, NULL, _IONBF, 0);
    clone_makes_a_first_process();
    unshare_needs_a_single_thread();
    unshare_fails_in_a_vfork_child();
    unshare_makes_a_namespace_for_children();
    the_first_process_ignores_unhandled_signals();
    the_first_process_dies_of_an_unhandled_fault();
    tgkill_from_outside_kills_the_first_process();
    the_namespace_ends_with_its_first_process();
    clone_parent_makes_a_sibling();
    vfork_makes_a_first_process();
    a_vfork_first_process_ignores_its_own_sigkill();
    printf("pid-namespace failures=%d\n", failures);
    return failures != 0;
}
