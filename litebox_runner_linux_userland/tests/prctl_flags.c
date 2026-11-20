// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks the dumpable, no_new_privs, and keepcaps flags of `prctl`: their defaults, invalid
// arguments, and how threads, fork, vfork and execve carry them. Like Linux, dumpable belongs to
// the process and a vfork child shares its parent's, while no_new_privs belongs to each thread and
// can't be cleared, and execve clears keepcaps. Usage: prctl_flags [exec-child NO_NEW_PRIVS]; an
// exec-child exits 0 if it is dumpable, its no_new_privs is NO_NEW_PRIVS, and keepcaps is clear.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
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

// Calls `prctl` with every argument set, since Linux requires some unused ones to be zero.
static long pr(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
               unsigned long arg5) {
    return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

static long dumpable(void) {
    return pr(PR_GET_DUMPABLE, 0, 0, 0, 0);
}

static long no_new_privs(void) {
    return pr(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
}

static int set_dumpable(unsigned long value) {
    return pr(PR_SET_DUMPABLE, value, 0, 0, 0) == 0;
}

static int set_no_new_privs(void) {
    return pr(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
}

// Returns whether `prctl` with these arguments fails with `EINVAL`.
static int einval(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
                  unsigned long arg5) {
    errno = 0;
    return pr(option, arg2, arg3, arg4, arg5) == -1 && errno == EINVAL;
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

// Runs this program as an exec-child expecting `no_new_privs`, in place of the caller.
static void exec_child(const char *expected) {
    char *const argv[] = {self_path, "exec-child", (char *)expected, NULL};
    execve(self_path, argv, environ);
    _exit(100);
}

static void defaults(void) {
    CHECK(dumpable() == 1);
    CHECK(no_new_privs() == 0);
}

static void invalid_arguments_fail(void) {
    // Only 0 and 1 can be set, compared as full-width values.
    CHECK(einval(PR_SET_DUMPABLE, 2, 0, 0, 0));
    CHECK(einval(PR_SET_DUMPABLE, (1UL << 32) | 1, 0, 0, 0));
    // no_new_privs can only be set, with 1, and both of its options need zero unused arguments.
    CHECK(einval(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0));
    CHECK(einval(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0));
    CHECK(einval(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0));
    CHECK(einval(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 1));
    CHECK(einval(PR_GET_NO_NEW_PRIVS, 1, 0, 0, 0));
    CHECK(einval(PR_GET_NO_NEW_PRIVS, 0, 0, 1, 0));
    CHECK(dumpable() == 1 && no_new_privs() == 0);
    // The dumpable options ignore their unused arguments.
    CHECK(pr(PR_SET_DUMPABLE, 0, 1, 1, 1) == 0);
    CHECK(pr(PR_GET_DUMPABLE, 1, 1, 1, 1) == 0);
    CHECK(set_dumpable(1) && dumpable() == 1);
}

static void *clear_dumpable(void *arg) {
    return (void *)(intptr_t)set_dumpable(0);
}

static void threads_share_dumpable(void) {
    pthread_t thread;
    void *result = NULL;
    CHECK(pthread_create(&thread, NULL, clear_dumpable, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)1);
    CHECK(dumpable() == 0);
}

static int vfork_child_sets_flags(void *arg) {
    // A launcher may drop credentials before exec. Keeping its own uid and dropping every
    // capability succeed, as on Linux, without terminating the waiting parent.
    struct __user_cap_header_struct caps = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct empty[2] = {0};
    if (syscall(SYS_setuid, *(uid_t *)arg) != 0 || syscall(SYS_capset, &caps, empty) != 0) {
        _exit(3);
    }
    if (dumpable() != 0 || no_new_privs() != 0 || pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) != 0) {
        _exit(1);
    }
    if (!set_dumpable(1) || !set_no_new_privs() || no_new_privs() != 1 ||
        pr(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 || pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) != 1) {
        _exit(2);
    }
    _exit(0);
}

// A vfork child shares its parent's dumpable flag, as they share memory, but has its own
// no_new_privs and keepcaps.
static void vfork_child_shares_only_dumpable(void) {
    CHECK(set_dumpable(0));
    uid_t uid = getuid();
    CHECK(syscall(SYS_setuid, uid) == 0);
    pid_t child = clone(vfork_child_sets_flags, vfork_stack + sizeof vfork_stack,
                        CLONE_VM | CLONE_VFORK | SIGCHLD, &uid);
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(dumpable() == 1);
    CHECK(no_new_privs() == 0);
    CHECK(pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0);
}

static int vfork_child_sets_no_new_privs_and_execs(void *arg) {
    if (!set_no_new_privs()) {
        _exit(1);
    }
    exec_child("1");
    return 0;
}

// A vfork child's program keeps the child's no_new_privs and is dumpable, while its parent's
// flags stay as they were.
static void vfork_child_execs_with_its_own_flags(void) {
    CHECK(set_dumpable(0));
    pid_t child = clone(vfork_child_sets_no_new_privs_and_execs, vfork_stack + sizeof vfork_stack,
                        CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(dumpable() == 0);
    CHECK(no_new_privs() == 0);
}

static void *set_no_new_privs_and_exec(void *arg) {
    if (set_no_new_privs()) {
        exec_child("1");
    }
    _exit(1);
}

// A program run by a thread keeps that thread's no_new_privs, not its main thread's.
static void execve_from_a_thread_keeps_its_flag(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        pthread_t thread;
        if (no_new_privs() != 0 ||
            pthread_create(&thread, NULL, set_no_new_privs_and_exec, NULL) != 0) {
            _exit(2);
        }
        for (;;) {
            pause();
        }
    }
    CHECK(child > 0 && exited_with(child, 0));
}

static void *read_no_new_privs_after_byte(void *arg) {
    char byte;
    if (read(*(int *)arg, &byte, 1) != 1) {
        return (void *)-1;
    }
    return (void *)(intptr_t)no_new_privs();
}

static void *read_no_new_privs(void *arg) {
    return (void *)(intptr_t)no_new_privs();
}

// Setting no_new_privs sticks, and is copied to the threads the setting thread creates after,
// but not to its existing ones.
static void no_new_privs_sticks_to_its_thread(void) {
    int release[2];
    pthread_t before;
    pthread_t after;
    void *result = NULL;
    CHECK(pipe(release) == 0);
    CHECK(pthread_create(&before, NULL, read_no_new_privs_after_byte, &release[0]) == 0);
    CHECK(set_no_new_privs() && no_new_privs() == 1);
    CHECK(set_no_new_privs());
    CHECK(einval(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) && no_new_privs() == 1);
    CHECK(write(release[1], "x", 1) == 1);
    CHECK(pthread_join(before, &result) == 0 && result == (void *)0);
    CHECK(pthread_create(&after, NULL, read_no_new_privs, NULL) == 0);
    CHECK(pthread_join(after, &result) == 0 && result == (void *)1);
    close(release[0]);
    close(release[1]);
}

// A forked child copies all three flags; a new program, whether run in place or by
// `posix_spawn`, keeps no_new_privs, is dumpable, and has keepcaps clear.
static void fork_and_execve_carry_the_flags(void) {
    CHECK(set_dumpable(0));
    CHECK(pr(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        _exit(dumpable() == 0 && no_new_privs() == 1 && pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1
                  ? 0 : 1);
    }
    CHECK(child > 0 && exited_with(child, 0));

    child = fork();
    if (child == 0) {
        exec_child("1");
    }
    CHECK(child > 0 && exited_with(child, 0));

    char *const argv[] = {self_path, "exec-child", "1", NULL};
    CHECK(posix_spawn(&child, self_path, NULL, NULL, argv, environ) == 0);
    CHECK(exited_with(child, 0));
    // The spawned program's exec clears only its own keepcaps.
    CHECK(dumpable() == 0);
    CHECK(pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1);
}

// An unknown capability version fails with EINVAL and is rewritten to the preferred one, with
// which dropping every capability then succeeds. In a child, so natively the test keeps its own.
static void capset_negotiates_its_version(void) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        struct __user_cap_header_struct caps = {.version = 0};
        struct __user_cap_data_struct empty[2] = {0};
        errno = 0;
        if (syscall(SYS_capset, &caps, empty) != -1 || errno != EINVAL) {
            _exit(1);
        }
        if (caps.version != _LINUX_CAPABILITY_VERSION_3) {
            _exit(2);
        }
        _exit(syscall(SYS_capset, &caps, empty) == 0 ? 0 : 3);
    }
    CHECK(child > 0 && exited_with(child, 0));
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "exec-child") == 0) {
        return dumpable() == 1 && no_new_privs() == atoi(argv[2]) &&
                       pr(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0 ? 0 : 1;
    }
    self_path = argv[0];
    setvbuf(stdout, NULL, _IONBF, 0);
    // The cases before no_new_privs_sticks_to_its_thread run before this thread sets no_new_privs.
    defaults();
    invalid_arguments_fail();
    threads_share_dumpable();
    vfork_child_shares_only_dumpable();
    vfork_child_execs_with_its_own_flags();
    execve_from_a_thread_keeps_its_flag();
    no_new_privs_sticks_to_its_thread();
    fork_and_execve_carry_the_flags();
    capset_negotiates_its_version();
    printf("prctl-flags failures=%d\n", failures);
    return failures != 0;
}
