// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <signal.h>
#include <time.h>

static volatile sig_atomic_t handled;

static void on_signal(int signal) {
    (void)signal;
    handled++;
}

int main(void) {
    struct sigaction action = {.sa_handler = on_signal};
    TEST_ASSERT(sigaction(SIGUSR1, &action, NULL) == 0, "sigaction SIGUSR1 failed");
    TEST_ASSERT(sigaction(SIGALRM, &action, NULL) == 0, "sigaction SIGALRM failed");
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &usr1, NULL) == 0, "block SIGUSR1 failed");

    // Nothing pending: a zero timeout fails at once, and a short one once it passes.
    struct timespec zero = {0, 0};
    errno = 0;
    TEST_ASSERT(sigtimedwait(&usr1, NULL, &zero) == -1 && errno == EAGAIN,
                "a zero timeout with nothing pending should fail with EAGAIN");
    struct timespec short_wait = {0, 20 * 1000 * 1000};
    errno = 0;
    TEST_ASSERT(sigtimedwait(&usr1, NULL, &short_wait) == -1 && errno == EAGAIN,
                "a timeout with nothing pending should fail with EAGAIN");

    // A pending signal is taken without running its handler.
    TEST_ASSERT(kill(getpid(), SIGUSR1) == 0, "kill failed");
    siginfo_t info = {0};
    TEST_ASSERT(sigwaitinfo(&usr1, &info) == SIGUSR1, "sigwaitinfo should take SIGUSR1");
    TEST_ASSERT(info.si_signo == SIGUSR1 && info.si_pid == getpid() && info.si_code == SI_USER,
                "sigwaitinfo should describe the signal");
    TEST_ASSERT(handled == 0, "a taken signal should not run its handler");
    sigset_t pending;
    TEST_ASSERT(sigpending(&pending) == 0 && !sigismember(&pending, SIGUSR1),
                "a taken signal should no longer be pending");

    // A signal raised for this thread is taken too, at once with a zero timeout.
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise failed");
    TEST_ASSERT(sigtimedwait(&usr1, NULL, &zero) == SIGUSR1,
                "sigtimedwait should take a pending signal at once");
    int signal = 0;
    TEST_ASSERT(raise(SIGUSR1) == 0 && sigwait(&usr1, &signal) == 0 && signal == SIGUSR1,
                "sigwait should take a raised signal");

    // Another signal whose handler runs ends the wait.
    alarm(1);
    errno = 0;
    TEST_ASSERT(sigwaitinfo(&usr1, NULL) == -1 && errno == EINTR && handled == 1,
                "a handled signal outside the set should interrupt the wait");

    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr1, NULL, &zero, 4) == -1 && errno == EINVAL,
                "a wrong set size should fail with EINVAL");
    puts("All sigtimedwait tests passed.");
    return 0;
}
