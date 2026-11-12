// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks PID namespaces: creating them with `clone` and `unshare`, the IDs processes see in them,
// orphans, the first process's signal rules and exit, and `CLONE_PARENT`. Runs as guest root.
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

int main(int argc, char **argv) {
    // A child checks that it has the ID it saw before `execve`, and no parent.
    if (argc > 2 && strcmp(argv[1], "identity") == 0) {
        return getpid() == atoi(argv[2]) && getppid() == 0 ? 0 : 1;
    }
    self_path = argv[0];
    setvbuf(stdout, NULL, _IONBF, 0);
    clone_makes_a_first_process();
    unshare_needs_a_single_thread();
    unshare_fails_in_a_vfork_child();
    unshare_makes_a_namespace_for_children();
    the_first_process_ignores_unhandled_signals();
    the_namespace_ends_with_its_first_process();
    clone_parent_makes_a_sibling();
    vfork_makes_a_first_process();
    printf("pid-namespace failures=%d\n", failures);
    return failures != 0;
}
