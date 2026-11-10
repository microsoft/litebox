// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks PID namespaces: creating them with `clone` and `unshare`, the IDs processes see in them,
// orphans, the first process's signal rules and exit, and `CLONE_PARENT`. Runs as guest root.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
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
// and later children join that namespace. Orphans there go to the first process, and once it is
// gone, nothing joins the namespace.
static int unshare_numbers_later_children(void) {
    pid_t self = getpid();
    if (unshare(CLONE_NEWPID) != 0 || getpid() != self) {
        return 10;
    }
    // A thread group stays in one namespace, and another namespace can't nest in this one yet.
    if (unshare(CLONE_NEWPID) == 0 || errno != EINVAL) {
        return 11;
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
        // The later child's orphan is this process's now.
        int status = 0;
        _exit(reap(-1, &status) > 1 && WIFEXITED(status) ? WEXITSTATUS(status) : 2);
    }
    pid_t later = fork();
    if (later == 0) {
        pid_t later_self = getpid();
        pid_t orphan = fork();
        if (orphan == 0) {
            _exit(wait_for_new_parent(later_self) == 1 ? 0 : 3);
        }
        // Its parent is outside the namespace.
        _exit(later_self > 1 && getppid() == 0 ? 0 : 1);
    }
    if (first <= 0 || later <= 0 || !exited_with(later, 0)) {
        return 14;
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

// Runs `unshare_numbers_later_children` in a child, which the unshare leaves changed.
static void unshare_makes_a_namespace_for_later_children(void) {
    pid_t helper = fork();
    if (helper == 0) {
        _exit(unshare_numbers_later_children());
    }
    int status = 0;
    CHECK(reap(helper, &status) == helper && WIFEXITED(status));
    if (WEXITSTATUS(status) != 0) {
        printf("unshare case failed code=%d\n", WEXITSTATUS(status));
        failures++;
    }
}

// The first process of a namespace takes no signal it has no handler for, except `SIGKILL` from
// an ancestor namespace; `kill(-1)` from inside spares it.
static void the_first_process_ignores_unhandled_signals(void) {
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t first = clone_child(CLONE_NEWPID);
    if (first == 0) {
        close(ready[0]);
        pid_t victim = fork();
        if (victim == 0) {
            pause();
            _exit(0);
        }
        pid_t sender = fork();
        if (sender == 0) {
            kill(1, SIGTERM);
            kill(1, SIGKILL);
            _exit(kill(-1, SIGKILL) == 0 ? 0 : 1);
        }
        raise(SIGTERM);
        int status = 0;
        int code = exited_with(sender, 0) ? 0 : 1;
        if (reap(victim, &status) != victim || !WIFSIGNALED(status) ||
            WTERMSIG(status) != SIGKILL) {
            code = 2;
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
        _exit(7);
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
        // Like runc: a new namespace for children, then a sibling that is its first process.
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

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// Runs in a vfork-style child on its own stack, as `posix_spawn`'s child does: execs `self`
// to check that it is a namespace's first process.
static int exec_first_process_check(void *self) {
    char *const argv[] = {self, "first-process", NULL};
    execve(self, argv, NULL);
    _exit(2);
}

// A vfork-style child with a new namespace is its first process after `execve`.
static void vfork_makes_a_first_process(char *self) {
    pid_t child = clone(exec_first_process_check, vfork_stack + sizeof vfork_stack,
                        CLONE_VM | CLONE_VFORK | CLONE_NEWPID | SIGCHLD, self);
    CHECK(child > 1);
    CHECK(exited_with(child, 0));
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "first-process") == 0) {
        return getpid() == 1 && getppid() == 0 ? 0 : 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    clone_makes_a_first_process();
    unshare_makes_a_namespace_for_later_children();
    the_first_process_ignores_unhandled_signals();
    the_namespace_ends_with_its_first_process();
    clone_parent_makes_a_sibling();
    vfork_makes_a_first_process(argv[0]);
    printf("pid-namespace failures=%d\n", failures);
    return failures != 0;
}
