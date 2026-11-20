// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Children created by `posix_spawn`, which uses `clone3`, and by glibc's `clone` wrapper, each with
// a separate child stack, start like vfork children, as the processes the parent got for them;
// spawn attributes change their signal state, and `CLONE_CLEAR_SIGHAND` drops the parent's
// handlers.

#include "helpers.h"
#include <errno.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char *child_path;
static char parent_variable[32];
static struct pid_report clone_report;
static char child_stack[64 * 1024] __attribute__((aligned(16)));

static void on_signal(int signal) { (void)signal; }

static void on_ill(int signal) {
    (void)signal;
    _exit(57);
}

// Reaps `child`, reporting it as `label`, and returns its wait status, or -1 if `child` isn't
// another process this one reaped.
static int report(const char *label, pid_t child) {
    int status = 0;
    pid_t waited = waitpid(child, &status, 0);
    printf("%s child=%d waited=%d exited=%d code=%d signaled=%d signal=%d\n", label, child,
           waited, WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status),
           WTERMSIG(status));
    fflush(stdout);
    return child != getpid() && waited == child ? status : -1;
}

// Returns whether wait status `status` is an exit with `code`.
static int exited_with(int status, int code) {
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static int clone_child(void *marker) {
    char *argv[] = {child_path, marker, NULL};
    // The child checks that it is this process's child, with the marker `from-clone`.
    char *envp[] = {"VFORK_EXEC_TEST=clone", parent_variable, clone_report.variable, NULL};
    execve(child_path, argv, envp);
    return 111;
}

// Must run on `child_stack`. With `CLONE_CLEAR_SIGHAND`, the parent's SIGILL handler does not
// apply, so the fault kills the child.
static void __attribute__((noreturn, used)) clear_sighand_child(void) {
    uintptr_t frame = (uintptr_t)__builtin_frame_address(0);
    if (frame < (uintptr_t)child_stack || frame >= (uintptr_t)child_stack + sizeof(child_stack)) {
        _exit(55);
    }
#if defined(__x86_64__)
    __asm__ volatile("ud2");
#elif defined(__aarch64__)
    __asm__ volatile("udf #0");
#else
#error "unsupported architecture"
#endif
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
#if defined(__x86_64__)
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "call clear_sighand_child\n\t"
                     "1:"
                     : "=a"(ret)
                     : "a"((long)SYS_clone3), "D"(&args), "S"(sizeof(args))
                     : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = (long)&args;
    register long x1 __asm__("x1") = sizeof(args);
    register long x8 __asm__("x8") = SYS_clone3;
    __asm__ volatile("svc #0\n\t"
                     "cbnz x0, 1f\n\t"
                     "bl clear_sighand_child\n\t"
                     "1:"
                     : "+r"(x0)
                     : "r"(x1), "r"(x8)
                     : "x30", "memory");
    ret = x0;
#else
#error "unsupported architecture"
#endif
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
    snprintf(parent_variable, sizeof parent_variable, "VFORK_EXEC_PARENT=%d", getpid());

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
    // The child checks that it is this process's child, with the marker `from-spawn`.
    char *spawn_envp[] = {"VFORK_EXEC_TEST=spawn", parent_variable, NULL};
    struct pid_report spawn_report;
    open_pid_report(&spawn_report);
    char *reporting_envp[] = {"VFORK_EXEC_TEST=spawn", parent_variable, spawn_report.variable,
                              NULL};
    int ret = posix_spawn(&child, child_path, NULL, NULL, spawn_argv, reporting_envp);
    if (ret != 0) {
        printf("spawn-error ret=%d\n", ret);
        return 4;
    }
    int failures = !exited_with(report("spawn", child), 42);
    failures += !pid_reported(&spawn_report, child);

    // Spawn attributes change the child's signal state before it execs.
    posix_spawnattr_t attr;
    sigset_t defaults;
    sigset_t mask;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGHUP);
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    // In the order `vfork_exec_child.c` reports them: SIGPIPE still ignored but SIGHUP reset, SIGUSR2
    // default, SIGTERM but not SIGUSR2 blocked, and no signals pending.
    char *signals_argv[] = {child_path, "signals", "101.100000000", NULL};
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
    failures += !exited_with(report("signals", child), 42);

    // The child reports a failed exec to `posix_spawn`, which reaps it.
    ret = posix_spawn(&child, "/missing-spawn-executable", NULL, NULL, spawn_argv, spawn_envp);
    pid_t again = waitpid(-1, NULL, WNOHANG);
    int echild = again == -1 && errno == ECHILD;
    printf("missing ret=%d echild=%d\n", ret, echild);
    fflush(stdout);
    failures += ret != ENOENT || !echild;

    // glibc's `clone` wrapper uses the `clone` syscall with a separate child stack.
    open_pid_report(&clone_report);
    child = clone(clone_child, child_stack + sizeof(child_stack),
                  CLONE_VM | CLONE_VFORK | SIGCHLD, "from-clone");
    if (child < 0) {
        perror("clone");
        return 7;
    }
    failures += !exited_with(report("clone", child), 42);
    failures += !pid_reported(&clone_report, child);

    child = clone3_clear_sighand();
    if (child < 0) {
        printf("clone3-error ret=%d\n", child);
        return 8;
    }
    int status = report("clear-sighand", child);
    failures += status == -1 || !WIFSIGNALED(status) || WTERMSIG(status) != SIGILL;

    // The children's handler resets do not reach the parent.
    int hup_ignored = handler_is(SIGHUP, SIG_IGN);
    int usr2_handled = handler_is(SIGUSR2, on_signal);
    int ill_handled = handler_is(SIGILL, on_ill);
    printf("parent-signals hup_ignored=%d usr2_handled=%d ill_handled=%d\n", hup_ignored,
           usr2_handled, ill_handled);
    failures += !hup_ignored || !usr2_handled || !ill_handled;
    printf("vfork-spawn failures=%d\n", failures);
    return failures != 0;
}
