// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <sched.h>
#include <stdatomic.h>
#include <sys/mman.h>

#define ROUNDS 100

// Requests from this process to the child, which sends each one's signal back.
struct requests {
    // The signal to send, 0 when none is requested, or -1 to exit.
    atomic_int signal;
    // The number of signals sent, each once its `kill` returned.
    atomic_uint sent;
};

static struct requests *requests;
static unsigned requested;
static volatile sig_atomic_t handled;

static void count_signal(int signal) {
    (void)signal;
    handled++;
}

// Spins until a signal is requested, mostly without syscalls so that this process sends it as
// soon as it is requested, then sends it to `parent`, until asked to exit.
static void send_requested_signals(pid_t parent) {
    for (unsigned spins = 1;; spins++) {
        int signal = atomic_exchange(&requests->signal, 0);
        if (signal < 0) {
            _exit(0);
        }
        if (signal > 0) {
            TEST_ASSERT(kill(parent, signal) == 0, "kill failed");
            atomic_fetch_add(&requests->sent, 1);
            continue;
        }
        SPIN_HINT();
        if (spins % 4096 == 0) {
            // Stop if this process's parent failed.
            TEST_ASSERT(getppid() == parent, "the parent exited");
            sched_yield();
        }
    }
}

// Asks the child to send `signal`, without waiting for it to.
static void request_signal_from_child(int signal) {
    requested++;
    atomic_store(&requests->signal, signal);
}

// Spins, mostly without syscalls, until `child` sent every requested signal.
static void await_sent(pid_t child) {
    for (unsigned spins = 1; atomic_load(&requests->sent) != requested; spins++) {
        SPIN_HINT();
        if (spins % 4096 == 0) {
            TEST_ASSERT(waitpid(child, NULL, WNOHANG) == 0, "the child exited");
        }
    }
}

// Has `child` send `signal`, returning once its `kill` returned.
static void send_from_child(pid_t child, int signal) {
    request_signal_from_child(signal);
    await_sent(child);
}

static long sigtimedwait_for(int signal, siginfo_t *info, const struct timespec *timeout) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signal);
    return syscall(SYS_rt_sigtimedwait, &set, info, timeout, _NSIG / 8);
}

int main(void) {
    sigset_t usr1, both;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, SIGUSR2);
    set_handler(SIGUSR1, count_signal, 0);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &both, NULL) == 0, "block SIGUSR1 and SIGUSR2 failed");
    requests = mmap(NULL, sizeof(*requests), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                    -1, 0);
    TEST_ASSERT(requests != MAP_FAILED, "mmap failed");
    pid_t parent = getpid();
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork failed");
    if (child == 0) {
        send_requested_signals(parent);
    }
    const struct timespec zero = {0, 0};
    const struct timespec ten_seconds = {10, 0};

    for (int round = 0; round < ROUNDS; round++) {
        send_from_child(child, SIGUSR1);
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        TEST_ASSERT(sigtimedwait_for(SIGUSR1, &info, &zero) == SIGUSR1 &&
                        info.si_signo == SIGUSR1 && info.si_code == SI_USER &&
                        info.si_pid == child && info.si_uid == getuid(),
                    "a zero-timeout wait should take a signal another process sent");
        errno = 0;
        TEST_ASSERT(sigtimedwait_for(SIGUSR1, NULL, &zero) == -1 && errno == EAGAIN,
                    "a zero-timeout wait should take the signal only once");

        send_from_child(child, SIGUSR2);
        errno = 0;
        TEST_ASSERT(sigtimedwait_for(SIGUSR1, NULL, &zero) == -1 && errno == EAGAIN,
                    "a wait for SIGUSR1 should not take SIGUSR2");
        TEST_ASSERT(sigtimedwait_for(SIGUSR2, NULL, &zero) == SIGUSR2,
                    "a wait for other signals should leave SIGUSR2 pending");

        send_from_child(child, SIGUSR2);
        sigset_t pending;
        TEST_ASSERT(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR2),
                    "sigpending should report a signal another process sent");
        TEST_ASSERT(sigtimedwait_for(SIGUSR2, NULL, &zero) == SIGUSR2,
                    "a zero-timeout wait should take the pending SIGUSR2");

        handled = 0;
        send_from_child(child, SIGUSR1);
        TEST_ASSERT(sigprocmask(SIG_UNBLOCK, &usr1, NULL) == 0, "unblock SIGUSR1 failed");
        TEST_ASSERT(handled == 1,
                    "unblocking a signal another process sent should run its handler at once");
        TEST_ASSERT(sigprocmask(SIG_BLOCK, &usr1, NULL) == 0, "block SIGUSR1 failed");

        // The child sends SIGUSR2 while, or before, this process waits for it.
        request_signal_from_child(SIGUSR2);
        TEST_ASSERT(sigtimedwait_for(SIGUSR2, NULL, &ten_seconds) == SIGUSR2,
                    "a wait should take a signal another process sends meanwhile");
        await_sent(child);
    }

    request_signal_from_child(-1);
    TEST_ASSERT(reap(child, 1) == 0, "the child should exit cleanly");
    puts("sigtimedwait-fork ok");
    return 0;
}
