// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char *child_path;
static char child_stack[64 * 1024] __attribute__((aligned(16)));

static void on_signal(int signal) { (void)signal; }

static void on_ill(int signal) {
    (void)signal;
    _exit(57);
}

static void report(const char *label, pid_t child) {
    int status = 0;
    pid_t waited = waitpid(child, &status, 0);
    printf("%s child=%d waited=%d exited=%d code=%d signaled=%d signal=%d\n", label, child,
           waited, WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status),
           WTERMSIG(status));
    fflush(stdout);
}

static int clone_child(void *marker) {
    char *argv[] = {child_path, marker, NULL};
    char *envp[] = {"VFORK_EXEC_TEST=clone", NULL};
    execve(child_path, argv, envp);
    return 111;
}

// Runs on the child's own stack. With `CLONE_CLEAR_SIGHAND`, the parent's SIGILL handler does not
// apply, so the fault kills the child.
static void __attribute__((noreturn, used)) clear_sighand_child(void) {
    __asm__ volatile("ud2");
    _exit(56);
}

static pid_t clone3_clear_sighand(void) {
    struct clone_args args = {
        .flags = CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND,
        .exit_signal = SIGCHLD,
        .stack = (uintptr_t)child_stack,
        .stack_size = sizeof(child_stack),
    };
    long ret;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "call clear_sighand_child\n\t"
                     "1:"
                     : "=a"(ret)
                     : "a"((long)SYS_clone3), "D"(&args), "S"(sizeof(args))
                     : "rcx", "r11", "memory");
    return ret;
}

static int handler_is(int signal, void (*handler)(int)) {
    struct sigaction action;
    return sigaction(signal, NULL, &action) == 0 && action.sa_handler == handler;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    child_path = argv[1];

    struct sigaction handled = {.sa_handler = on_signal};
    struct sigaction ill = {.sa_handler = on_ill};
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || signal(SIGHUP, SIG_IGN) == SIG_ERR ||
        sigaction(SIGUSR2, &handled, NULL) != 0 || sigaction(SIGILL, &ill, NULL) != 0) {
        perror("signal setup");
        return 3;
    }
    printf("parent pid=%d\n", getpid());
    fflush(stdout);

    // glibc's `posix_spawn` uses `clone3` with `CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND` and a
    // separate child stack.
    pid_t child;
    char *spawn_argv[] = {child_path, "from-spawn", NULL};
    char *spawn_envp[] = {"VFORK_EXEC_TEST=spawn", NULL};
    int ret = posix_spawn(&child, child_path, NULL, NULL, spawn_argv, spawn_envp);
    if (ret != 0) {
        printf("spawn-error ret=%d\n", ret);
        return 4;
    }
    report("spawn", child);

    // Spawn attributes change the child's signal state before it execs.
    posix_spawnattr_t attr;
    sigset_t defaults;
    sigset_t mask;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGHUP);
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    char *signals_argv[] = {child_path, "signals", NULL};
    if (posix_spawnattr_init(&attr) != 0 || posix_spawnattr_setsigdefault(&attr, &defaults) != 0 ||
        posix_spawnattr_setsigmask(&attr, &mask) != 0 ||
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK) != 0) {
        printf("spawnattr-error\n");
        return 5;
    }
    ret = posix_spawn(&child, child_path, NULL, &attr, signals_argv, spawn_envp);
    if (ret != 0) {
        printf("spawn-error ret=%d\n", ret);
        return 6;
    }
    report("signals", child);

    // The child reports a failed exec to `posix_spawn`, which reaps it.
    ret = posix_spawn(&child, "/missing-spawn-executable", NULL, NULL, spawn_argv, spawn_envp);
    pid_t again = waitpid(-1, NULL, WNOHANG);
    printf("missing ret=%d echild=%d\n", ret, again == -1 && errno == ECHILD);
    fflush(stdout);

    // glibc's `clone` wrapper uses the `clone` syscall with a separate child stack.
    child = clone(clone_child, child_stack + sizeof(child_stack),
                  CLONE_VM | CLONE_VFORK | SIGCHLD, "from-clone");
    if (child < 0) {
        perror("clone");
        return 7;
    }
    report("clone", child);

    child = clone3_clear_sighand();
    if (child < 0) {
        printf("clone3-error ret=%d\n", child);
        return 8;
    }
    report("clear-sighand", child);

    // The children's signal changes do not reach the parent.
    sigset_t blocked;
    sigprocmask(SIG_BLOCK, NULL, &blocked);
    printf("parent-signals hup_ignored=%d usr2_handled=%d ill_handled=%d term_blocked=%d\n",
           handler_is(SIGHUP, SIG_IGN), handler_is(SIGUSR2, on_signal),
           handler_is(SIGILL, on_ill), sigismember(&blocked, SIGTERM));
    return 0;
}
