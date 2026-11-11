// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// `tkill` and `tgkill` direct signals to the threads of another process.

#include "helpers.h"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

// State the child shares with this process.
struct shared {
    // This process.
    atomic_int parent;
    // The child's second thread.
    atomic_int thread_tid;
    // Set by the child's second thread: 1 once it started, 2 once it took the first SIGUSR1
    // without a handler, and 3 once it ran the handler for the second.
    atomic_int stage;
    // Set by this process once its first `tgkill` returned.
    atomic_int sent;
    // For SIGUSR1 and SIGUSR2, the number of times the handler ran, and the thread it last ran
    // on.
    atomic_int count[2];
    atomic_int tid[2];
};

static struct shared *shared;

static void on_signal(int signal) {
    int slot = signal == SIGUSR1 ? 0 : 1;
    atomic_store(&shared->tid[slot], gettid());
    atomic_fetch_add(&shared->count[slot], 1);
}

static int usr1_pending(void *arg) {
    (void)arg;
    sigset_t pending;
    TEST_ASSERT(sigpending(&pending) == 0, "sigpending failed");
    return sigismember(&pending, SIGUSR1);
}

static void expect_esrch(long result, const char *message) {
    TEST_ASSERT(result == -1 && errno == ESRCH, message);
    errno = 0;
}

// Runs in the child's second thread, which starts with SIGUSR1 and SIGUSR2 blocked.
static void *child_thread(void *arg) {
    (void)arg;
    atomic_store(&shared->thread_tid, gettid());
    atomic_store(&shared->stage, 1);
    sigset_t usr1;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    // A sent signal is pending at once, even before this process may be notified of it.
    while (atomic_load(&shared->sent) == 0) {
        SPIN_HINT();
    }
    siginfo_t info;
    struct timespec zero = {0, 0};
    // Unlike glibc's `sigtimedwait`, the syscall reports the code unchanged.
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr1, &info, &zero, _NSIG / 8) == SIGUSR1,
                "a sent SIGUSR1 should be pending at once");
    TEST_ASSERT(info.si_code == SI_TKILL && info.si_pid == atomic_load(&shared->parent),
                "the taken SIGUSR1 should describe its sender");
    atomic_store(&shared->stage, 2);
    // SIGUSR1 stays pending for this thread, though the main thread would take it.
    wait_until(usr1_pending, NULL, "SIGUSR1 never became pending");
    TEST_ASSERT(atomic_load(&shared->count[0]) == 0, "SIGUSR1 ran on another thread");
    TEST_ASSERT(pthread_sigmask(SIG_UNBLOCK, &usr1, NULL) == 0, "unblock SIGUSR1 failed");
    TEST_ASSERT(atomic_load(&shared->count[0]) == 1, "unblocking should run the handler");
    // No syscall follows, so the next SIGUSR1 must interrupt guest code. The sender times the
    // wait, and the child's alarm ends it should the sender fail.
    atomic_store(&shared->stage, 3);
    while (atomic_load(&shared->count[0]) != 2) {
        SPIN_HINT();
    }
    return NULL;
}

static void child_main(void) {
    // Ends the child should this process fail before sending it SIGUSR2.
    alarm(10);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0, "sigprocmask failed");
    pthread_t thread;
    TEST_ASSERT(pthread_create(&thread, NULL, child_thread, NULL) == 0, "pthread_create failed");
    // Waits with both signals unblocked, so it would take any SIGUSR1 meant for the process.
    sigset_t none;
    sigemptyset(&none);
    while (atomic_load(&shared->count[1]) == 0) {
        sigsuspend(&none);
    }
    TEST_ASSERT(pthread_join(thread, NULL) == 0, "pthread_join failed");
    _exit(0);
}

int main(void) {
    // Ends the test should a signal never arrive.
    alarm(30);
    shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1,
                  0);
    TEST_ASSERT(shared != MAP_FAILED, "mmap failed");
    struct sigaction action = {.sa_handler = on_signal};
    TEST_ASSERT(sigaction(SIGUSR1, &action, NULL) == 0, "sigaction SIGUSR1 failed");
    TEST_ASSERT(sigaction(SIGUSR2, &action, NULL) == 0, "sigaction SIGUSR2 failed");

    // SIGCHLD reports the child's exit without reaping it.
    sigset_t chld_blocked;
    sigemptyset(&chld_blocked);
    sigaddset(&chld_blocked, SIGCHLD);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &chld_blocked, NULL) == 0, "sigprocmask failed");

    atomic_store(&shared->parent, getpid());
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork failed");
    if (child == 0) {
        child_main();
    }
    wait_for_value(&shared->stage, 1, "the child's thread never started");
    int tid = atomic_load(&shared->thread_tid);

    // Signal zero only checks that the thread belongs to the process.
    TEST_ASSERT(syscall(SYS_tgkill, child, tid, 0) == 0, "tgkill probe failed");
    TEST_ASSERT(syscall(SYS_tkill, child, 0) == 0, "tkill probe of main thread failed");
    errno = 0;
    expect_esrch(syscall(SYS_tgkill, tid, tid, 0),
                 "tgkill naming a thread as the process should fail");
    expect_esrch(syscall(SYS_tgkill, tid, child, 0),
                 "tgkill naming a thread as the main thread's process should fail");
    TEST_ASSERT(syscall(SYS_tgkill, child, tid, 1000) == -1 && errno == EINVAL,
                "tgkill to a live remote thread with an invalid signal should fail with EINVAL");
    errno = 0;
    expect_esrch(syscall(SYS_tgkill, tid, child, 1000),
                 "tgkill with the wrong process and an invalid signal should fail with ESRCH");

    // `tgkill` signals the child's second thread, which can take the signal once it returns.
    TEST_ASSERT(syscall(SYS_tgkill, child, tid, SIGUSR1) == 0, "tgkill failed");
    atomic_store(&shared->sent, 1);
    wait_for_value(&shared->stage, 2, "the child's thread never took SIGUSR1");

    // `tgkill` signals the child's second thread alone.
    TEST_ASSERT(syscall(SYS_tgkill, child, tid, SIGUSR1) == 0, "tgkill failed");
    wait_for_value(&shared->stage, 3, "the child's thread never handled SIGUSR1");
    TEST_ASSERT(atomic_load(&shared->tid[0]) == tid, "SIGUSR1 ran on the wrong thread");

    // `tkill` interrupts it while it runs guest code.
    TEST_ASSERT(syscall(SYS_tkill, tid, SIGUSR1) == 0, "tkill failed");
    wait_for_value(&shared->count[0], 2, "the spinning thread never took SIGUSR1");
    TEST_ASSERT(atomic_load(&shared->tid[0]) == tid, "SIGUSR1 ran on the wrong thread");

    // The child's main thread has the child's ID, and wakes from `sigsuspend`.
    TEST_ASSERT(syscall(SYS_tgkill, child, child, SIGUSR2) == 0, "tgkill to main thread failed");
    wait_for_value(&shared->count[1], 1, "the child's main thread never took SIGUSR2");
    TEST_ASSERT(atomic_load(&shared->tid[1]) == child, "SIGUSR2 ran on the wrong thread");

    // Until it is reaped, the exited child's main thread can still be signaled, but its other
    // thread is gone.
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    struct timespec timeout = {10, 0};
    TEST_ASSERT(sigtimedwait(&chld, NULL, &timeout) == SIGCHLD, "the child never exited");
    TEST_ASSERT(syscall(SYS_tgkill, child, child, 0) == 0, "tgkill probe of a zombie failed");
    TEST_ASSERT(syscall(SYS_tgkill, child, child, SIGUSR1) == 0, "tgkill to a zombie failed");
    expect_esrch(syscall(SYS_tgkill, child, tid, 0), "tgkill to a zombie's other thread");

    int status;
    TEST_ASSERT(waitpid(child, &status, 0) == child, "waitpid failed");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the child failed");

    // The main thread is gone once the child is reaped.
    expect_esrch(syscall(SYS_tgkill, child, child, 0), "tgkill to a reaped process should fail");

    printf("thread-kill-process ok\n");
    return 0;
}
