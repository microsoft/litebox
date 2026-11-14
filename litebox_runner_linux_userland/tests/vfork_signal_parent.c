// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static volatile pid_t usr2_pid;
static volatile pid_t ill_pid;
static volatile pid_t pipe_sender;
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

static void on_pipe(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    pipe_sender = info->si_pid;
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

    // Ignoring signals in the child discards none of the parent's pending ones.
    kill(getpid(), SIGTERM);
    pid_t ignore_child = vfork();
    if (ignore_child == 0) {
        if (signal(SIGUSR2, SIG_IGN) == SIG_ERR || signal(SIGTERM, SIG_IGN) == SIG_ERR) {
            _exit(62);
        }
        _exit(60);
    }
    if (ignore_child < 0) {
        perror("vfork");
        return 6;
    }
    waited = waitpid(ignore_child, &status, 0);
    uint64_t parent_pending = 0;
    syscall(SYS_rt_sigpending, &parent_pending, sizeof(parent_pending));
    printf("ignore child=%d waited=%d exited=%d code=%d usr2_pending=%d term_pending=%d\n",
           ignore_child, waited, WIFEXITED(status), WEXITSTATUS(status),
           (int)(parent_pending >> (SIGUSR2 - 1) & 1), (int)(parent_pending >> (SIGTERM - 1) & 1));

    // Like Linux, the SIGPIPE a child raises names the child, not its parent, as its sender.
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0 || close(pipe_fds[0]) != 0) {
        perror("pipe");
        return 7;
    }
    struct sigaction pipe_action = {.sa_sigaction = on_pipe, .sa_flags = SA_SIGINFO};
    pid_t pipe_child = vfork();
    if (pipe_child == 0) {
        if (sigaction(SIGPIPE, &pipe_action, NULL) != 0) {
            _exit(72);
        }
        _exit(write(pipe_fds[1], "x", 1) == -1 ? 70 : 71);
    }
    if (pipe_child < 0) {
        perror("vfork");
        return 8;
    }
    close(pipe_fds[1]);
    waited = waitpid(pipe_child, &status, 0);
    printf("sigpipe child=%d waited=%d code=%d sender=%d\n", pipe_child, waited,
           WEXITSTATUS(status), pipe_sender);

    // A child may signal itself, and its fatal signal ends only the child.
    pid_t kill_self_child = vfork();
    if (kill_self_child == 0) {
        kill(getpid(), SIGKILL);
        _exit(80);
    }
    if (kill_self_child < 0) {
        perror("vfork");
        return 9;
    }
    waited = waitpid(kill_self_child, &status, 0);
    printf("kill-self child=%d waited=%d signaled=%d signal=%d\n", kill_self_child, waited,
           WIFSIGNALED(status), WTERMSIG(status));

    // Unlike Linux, LiteBox refuses any other target in a child, whose requests go to the broker
    // as its parent's.
    pid_t kill_other_child = vfork();
    if (kill_other_child == 0) {
        _exit(kill(getppid(), 0) == -1 && errno == EINVAL ? 81 : 82);
    }
    if (kill_other_child < 0) {
        perror("vfork");
        return 10;
    }
    waited = waitpid(kill_other_child, &status, 0);
    printf("kill-other child=%d waited=%d exited=%d code=%d\n", kill_other_child, waited,
           WIFEXITED(status), WEXITSTATUS(status));

    // The child changes its own signal state, and leaves signals pending, before exec.
    char *child_argv[] = {argv[1], "signals", NULL};
    char *child_envp[] = {NULL};
    int broken_pipe[2];
    struct rlimit sigpending_limit;
    if (pipe(broken_pipe) != 0 || close(broken_pipe[0]) != 0 ||
        getrlimit(RLIMIT_SIGPENDING, &sigpending_limit) != 0) {
        perror("exec setup");
        return 11;
    }
    pid_t exec_child = vfork();
    if (exec_child == 0) {
        // The parent's pending SIGUSR2 must not reach the child.
        if (signal(SIGHUP, SIG_IGN) == SIG_ERR ||
            sigprocmask(SIG_UNBLOCK, &usr2_set, NULL) != 0) {
            _exit(112);
        }
        // The signals the child sends itself are pending for its process. At the limit, a
        // real-time one loses its sender.
        sigset_t carried;
        sigemptyset(&carried);
        sigaddset(&carried, SIGUSR1);
        sigaddset(&carried, SIGPIPE);
        sigaddset(&carried, SIGRTMIN);
        struct rlimit no_queue = {.rlim_cur = 0, .rlim_max = sigpending_limit.rlim_max};
        if (sigprocmask(SIG_BLOCK, &carried, NULL) != 0 || kill(getpid(), SIGUSR1) != 0 ||
            kill(getpid(), SIGPIPE) != 0 || setrlimit(RLIMIT_SIGPENDING, &no_queue) != 0 ||
            kill(getpid(), SIGRTMIN) != 0 || setrlimit(RLIMIT_SIGPENDING, &sigpending_limit) != 0) {
            _exit(113);
        }
        // Ignoring SIGPIPE discards the pending one, and the broken pipe raises another for this
        // thread, which, blocked, is not ignored.
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR || write(broken_pipe[1], "x", 1) != -1 ||
            errno != EPIPE) {
            _exit(114);
        }
        execve(argv[1], child_argv, child_envp);
        _exit(111);
    }
    if (exec_child < 0) {
        perror("vfork");
        return 5;
    }
    close(broken_pipe[1]);
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
