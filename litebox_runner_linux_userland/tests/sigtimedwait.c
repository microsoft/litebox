// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <pthread.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t handled;

static void on_signal(int signal) {
    (void)signal;
    handled++;
}

static void *kill_process_later(void *arg) {
    (void)arg;
    usleep(50 * 1000);
    TEST_ASSERT(kill(getpid(), SIGUSR1) == 0, "kill from another thread failed");
    return NULL;
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
    TEST_ASSERT(info.si_signo == SIGUSR1 && info.si_pid == getpid() && info.si_uid == getuid() &&
                    info.si_code == SI_USER,
                "sigwaitinfo should describe the signal");
    TEST_ASSERT(handled == 0, "a taken signal should not run its handler");
    sigset_t pending;
    TEST_ASSERT(sigpending(&pending) == 0 && !sigismember(&pending, SIGUSR1),
                "a taken signal should no longer be pending");

    // A signal raised for this thread is taken too, at once with a zero timeout.
    TEST_ASSERT(raise(SIGUSR1) == 0, "raise failed");
    memset(&info, 0, sizeof(info));
    TEST_ASSERT(sigtimedwait(&usr1, &info, &zero) == SIGUSR1 && info.si_signo == SIGUSR1 &&
                    info.si_pid == getpid(),
                "sigtimedwait should take a pending signal at once and describe it");
    int signal = 0;
    TEST_ASSERT(raise(SIGUSR1) == 0 && sigwait(&usr1, &signal) == 0 && signal == SIGUSR1,
                "sigwait should take a raised signal");

    // A process-directed signal sent by another thread while this one waits is taken. Both
    // threads block it, so only the wait can take it. A finite timeout keeps a lost wakeup from
    // hanging the test.
    pthread_t killer;
    TEST_ASSERT(pthread_create(&killer, NULL, kill_process_later, NULL) == 0,
                "pthread_create failed");
    struct timespec long_wait = {5, 0};
    memset(&info, 0, sizeof(info));
    TEST_ASSERT(sigtimedwait(&usr1, &info, &long_wait) == SIGUSR1 && info.si_pid == getpid() &&
                    info.si_code == SI_USER,
                "sigtimedwait should take a signal another thread sends the process");
    TEST_ASSERT(pthread_join(killer, NULL) == 0, "pthread_join failed");
    TEST_ASSERT(handled == 0, "a taken signal should not run its handler");

    // Another signal whose handler runs ends the wait.
    alarm(1);
    errno = 0;
    TEST_ASSERT(sigwaitinfo(&usr1, NULL) == -1 && errno == EINTR && handled == 1,
                "a handled signal outside the set should interrupt the wait");

    // Like Linux, the wait is never restarted, even after an SA_RESTART handler runs. A finite
    // timeout keeps a wrongly restarted wait from hanging the test.
    struct sigaction restart = {.sa_handler = on_signal, .sa_flags = SA_RESTART};
    TEST_ASSERT(sigaction(SIGALRM, &restart, NULL) == 0, "sigaction SA_RESTART failed");
    alarm(1);
    errno = 0;
    TEST_ASSERT(sigtimedwait(&usr1, NULL, &long_wait) == -1 && errno == EINTR && handled == 2,
                "an SA_RESTART handler should still interrupt the wait");

    // Like Linux, a signal waited for is taken even if ignored, as it arrives during the wait
    // while blocked. Linux only discards an ignored signal that the thread did not block.
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    TEST_ASSERT(sigaction(SIGALRM, &ignore, NULL) == 0, "ignoring SIGALRM failed");
    sigset_t alrm;
    sigemptyset(&alrm);
    sigaddset(&alrm, SIGALRM);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &alrm, NULL) == 0, "block SIGALRM failed");
    struct itimerval timer = {.it_value = {0, 20 * 1000}};
    TEST_ASSERT(setitimer(ITIMER_REAL, &timer, NULL) == 0, "setitimer failed");
    TEST_ASSERT(sigtimedwait(&alrm, NULL, &long_wait) == SIGALRM,
                "a blocked, ignored signal arriving during the wait should be taken");

    // Like Linux's send_sig(SIGPIPE, current, 0), a write to a broken pipe names this process and
    // its user as the sender of the SIGPIPE it raises.
    sigset_t pipe_set;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &pipe_set, NULL) == 0, "block SIGPIPE failed");
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0 && close(fds[0]) == 0, "pipe setup failed");
    errno = 0;
    TEST_ASSERT(write(fds[1], "x", 1) == -1 && errno == EPIPE, "write should fail with EPIPE");
    close(fds[1]);
    memset(&info, 0, sizeof(info));
    TEST_ASSERT(sigtimedwait(&pipe_set, &info, &zero) == SIGPIPE && info.si_code == SI_USER &&
                    info.si_pid == getpid() && info.si_uid == getuid(),
                "SIGPIPE should name this process as its sender");

    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr1, NULL, &zero, 4) == -1 && errno == EINVAL,
                "a wrong set size should fail with EINVAL");
    struct timespec bad_nsec = {0, 1000 * 1000 * 1000};
    errno = 0;
    TEST_ASSERT(sigtimedwait(&usr1, NULL, &bad_nsec) == -1 && errno == EINVAL,
                "an invalid timeout should fail with EINVAL");
    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, (void *)8, NULL, &zero, _NSIG / 8) == -1 &&
                    errno == EFAULT,
                "an unreadable set should fail with EFAULT");
    puts("All sigtimedwait tests passed.");
    return 0;
}
