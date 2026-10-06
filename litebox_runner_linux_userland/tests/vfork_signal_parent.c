// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static volatile pid_t usr2_pid;
static volatile pid_t ill_pid;
static volatile int ill_on_child_stack;
// Raises SIGILL.
#if defined(__x86_64__)
#define UNDEFINED_INSTRUCTION() __asm__ volatile("ud2")
#elif defined(__aarch64__)
#define UNDEFINED_INSTRUCTION() __asm__ volatile("udf #0")
#else
#error "unsupported architecture"
#endif

static char child_stack[64 * 1024];

static void on_usr2(int signal) {
    (void)signal;
    usr2_pid = getpid();
}

static void on_ill(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)info;
    char local;
    ill_pid = getpid();
    ill_on_child_stack = (uintptr_t)&local - (uintptr_t)child_stack < sizeof(child_stack);
    // Resume after the faulting instruction.
#if defined(__x86_64__)
    ((ucontext_t *)context)->uc_mcontext.gregs[REG_RIP] += 2;
#elif defined(__aarch64__)
    ((ucontext_t *)context)->uc_mcontext.pc += 4;
#else
#error "unsupported architecture"
#endif
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }

    struct sigaction usr2 = {.sa_handler = on_usr2};
    struct sigaction ill = {.sa_sigaction = on_ill, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    sigset_t usr2_set;
    sigemptyset(&usr2_set);
    sigaddset(&usr2_set, SIGUSR2);
    sigset_t blocked = usr2_set;
    sigaddset(&blocked, SIGTERM);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || sigaction(SIGUSR2, &usr2, NULL) != 0 ||
        sigaction(SIGILL, &ill, NULL) != 0 || sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
        perror("signal setup");
        return 3;
    }
    // SIGUSR2 stays pending in the parent while blocked.
    raise(SIGUSR2);
    fflush(stdout);

    // The inherited handler runs in the child on the child's own alternate stack and returns
    // past the fault.
    pid_t fault_child = vfork();
    if (fault_child == 0) {
        stack_t ss = {.ss_sp = child_stack, .ss_size = sizeof(child_stack)};
        if (sigaltstack(&ss, NULL) != 0) {
            _exit(57);
        }
        UNDEFINED_INSTRUCTION();
        _exit(ill_pid == getpid() && ill_on_child_stack ? 55 : 56);
    }
    if (fault_child < 0) {
        perror("vfork");
        return 4;
    }
    int status = 0;
    pid_t waited = waitpid(fault_child, &status, 0);
    printf("fault child=%d waited=%d exited=%d code=%d handler_pid=%d\n", fault_child, waited,
           WIFEXITED(status), WEXITSTATUS(status), ill_pid);

    // The child changes its own signal state before exec.
    char *child_argv[] = {argv[1], "signals", NULL};
    char *child_envp[] = {NULL};
    pid_t exec_child = vfork();
    if (exec_child == 0) {
        // The parent's pending SIGUSR2 must not reach the child.
        if (signal(SIGHUP, SIG_IGN) == SIG_ERR ||
            sigprocmask(SIG_UNBLOCK, &usr2_set, NULL) != 0) {
            _exit(112);
        }
        execve(argv[1], child_argv, child_envp);
        _exit(111);
    }
    if (exec_child < 0) {
        perror("vfork");
        return 5;
    }
    waited = waitpid(exec_child, &status, 0);
    printf("exec child=%d waited=%d exited=%d code=%d\n", exec_child, waited, WIFEXITED(status),
           WEXITSTATUS(status));

    // The children's signal changes did not affect the parent.
    struct sigaction hup;
    sigset_t current;
    stack_t altstack;
    sigaction(SIGHUP, NULL, &hup);
    sigprocmask(SIG_BLOCK, NULL, &current);
    sigaltstack(NULL, &altstack);
    pid_t usr2_before_unblock = usr2_pid;
    sigprocmask(SIG_UNBLOCK, &usr2_set, NULL);
    printf("parent pid=%d hup_default=%d term_blocked=%d altstack_disabled=%d "
           "usr2_before_unblock=%d usr2_pid=%d\n",
           getpid(), hup.sa_handler == SIG_DFL, sigismember(&current, SIGTERM),
           (altstack.ss_flags & SS_DISABLE) != 0, usr2_before_unblock, usr2_pid);
    return 0;
}
