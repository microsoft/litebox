// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests for signal mask support in pselect, ppoll, and epoll_pwait

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/epoll.h>

// Test 1: ppoll with signal mask - mask should be restored after call
int test_ppoll_sigmask_restored(void) {
    int pipefd[2];
    sigset_t original_mask, ppoll_mask, after_mask;

    // Create a pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Set up initial signal mask (block SIGUSR1)
    sigemptyset(&original_mask);
    sigaddset(&original_mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &original_mask, NULL) == -1) {
        perror("sigprocmask");
        return 1;
    }

    // Create a different mask for ppoll (block SIGUSR2 instead)
    sigemptyset(&ppoll_mask);
    sigaddset(&ppoll_mask, SIGUSR2);

    // Call ppoll with the new mask (write end should be ready immediately)
    struct pollfd fds[1] = {
        { .fd = pipefd[1], .events = POLLOUT, .revents = 0 }
    };
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };

    int ret = ppoll(fds, 1, &timeout, &ppoll_mask);
    if (ret < 0) {
        perror("ppoll");
        return 1;
    }

    // Check that the original mask is restored
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) == -1) {
        perror("sigprocmask get");
        return 1;
    }

    // Verify SIGUSR1 is still blocked (from original mask)
    if (!sigismember(&after_mask, SIGUSR1)) {
        fprintf(stderr, "FAIL: SIGUSR1 should be blocked after ppoll\n");
        return 1;
    }

    // Verify SIGUSR2 is NOT blocked (ppoll mask should not persist)
    if (sigismember(&after_mask, SIGUSR2)) {
        fprintf(stderr, "FAIL: SIGUSR2 should NOT be blocked after ppoll\n");
        return 1;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_ppoll_sigmask_restored: PASS\n");
    return 0;
}

// Test 2: pselect with signal mask - mask should be restored after call
int test_pselect_sigmask_restored(void) {
    int pipefd[2];
    sigset_t original_mask, pselect_mask, after_mask;

    // Create a pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Set up initial signal mask (block SIGUSR1)
    sigemptyset(&original_mask);
    sigaddset(&original_mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &original_mask, NULL) == -1) {
        perror("sigprocmask");
        return 1;
    }

    // Create a different mask for pselect (block SIGUSR2 instead)
    sigemptyset(&pselect_mask);
    sigaddset(&pselect_mask, SIGUSR2);

    // Call pselect with the new mask
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(pipefd[1], &writefds);
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };

    int ret = pselect(pipefd[1] + 1, NULL, &writefds, NULL, &timeout, &pselect_mask);
    if (ret < 0) {
        perror("pselect");
        return 1;
    }

    // Check that the original mask is restored
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) == -1) {
        perror("sigprocmask get");
        return 1;
    }

    // Verify SIGUSR1 is still blocked (from original mask)
    if (!sigismember(&after_mask, SIGUSR1)) {
        fprintf(stderr, "FAIL: SIGUSR1 should be blocked after pselect\n");
        return 1;
    }

    // Verify SIGUSR2 is NOT blocked (pselect mask should not persist)
    if (sigismember(&after_mask, SIGUSR2)) {
        fprintf(stderr, "FAIL: SIGUSR2 should NOT be blocked after pselect\n");
        return 1;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_pselect_sigmask_restored: PASS\n");
    return 0;
}

// Test 3: epoll_pwait with signal mask - mask should be restored after call
int test_epoll_pwait_sigmask_restored(void) {
    int pipefd[2];
    sigset_t original_mask, epoll_mask, after_mask;

    // Create a pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Create epoll instance
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd == -1) {
        perror("epoll_create1");
        return 1;
    }

    // Add write end to epoll
    struct epoll_event ev = {
        .events = EPOLLOUT,
        .data.fd = pipefd[1]
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == -1) {
        perror("epoll_ctl");
        return 1;
    }

    // Set up initial signal mask (block SIGUSR1)
    sigemptyset(&original_mask);
    sigaddset(&original_mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &original_mask, NULL) == -1) {
        perror("sigprocmask");
        return 1;
    }

    // Create a different mask for epoll_pwait (block SIGUSR2 instead)
    sigemptyset(&epoll_mask);
    sigaddset(&epoll_mask, SIGUSR2);

    // Call epoll_pwait with the new mask
    struct epoll_event events[1];
    int ret = epoll_pwait(epfd, events, 1, 0, &epoll_mask);
    if (ret < 0) {
        perror("epoll_pwait");
        return 1;
    }

    // Check that the original mask is restored
    if (sigprocmask(SIG_SETMASK, NULL, &after_mask) == -1) {
        perror("sigprocmask get");
        return 1;
    }

    // Verify SIGUSR1 is still blocked (from original mask)
    if (!sigismember(&after_mask, SIGUSR1)) {
        fprintf(stderr, "FAIL: SIGUSR1 should be blocked after epoll_pwait\n");
        return 1;
    }

    // Verify SIGUSR2 is NOT blocked (epoll_pwait mask should not persist)
    if (sigismember(&after_mask, SIGUSR2)) {
        fprintf(stderr, "FAIL: SIGUSR2 should NOT be blocked after epoll_pwait\n");
        return 1;
    }

    close(epfd);
    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_epoll_pwait_sigmask_restored: PASS\n");
    return 0;
}

// Test 4: ppoll with NULL sigmask should still work
int test_ppoll_null_sigmask(void) {
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    struct pollfd fds[1] = {
        { .fd = pipefd[1], .events = POLLOUT, .revents = 0 }
    };
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };

    int ret = ppoll(fds, 1, &timeout, NULL);
    if (ret < 0) {
        perror("ppoll with NULL sigmask");
        return 1;
    }
    if (ret != 1 || !(fds[0].revents & POLLOUT)) {
        fprintf(stderr, "FAIL: ppoll should report write ready\n");
        return 1;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_ppoll_null_sigmask: PASS\n");
    return 0;
}

// Test 5: pselect with NULL sigmask should still work
int test_pselect_null_sigmask(void) {
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(pipefd[1], &writefds);
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };

    int ret = pselect(pipefd[1] + 1, NULL, &writefds, NULL, &timeout, NULL);
    if (ret < 0) {
        perror("pselect with NULL sigmask");
        return 1;
    }
    if (ret != 1 || !FD_ISSET(pipefd[1], &writefds)) {
        fprintf(stderr, "FAIL: pselect should report write ready\n");
        return 1;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_pselect_null_sigmask: PASS\n");
    return 0;
}

// Test 6: epoll_pwait with NULL sigmask should still work
int test_epoll_pwait_null_sigmask(void) {
    int pipefd[2];

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd == -1) {
        perror("epoll_create1");
        return 1;
    }

    struct epoll_event ev = {
        .events = EPOLLOUT,
        .data.fd = pipefd[1]
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[1], &ev) == -1) {
        perror("epoll_ctl");
        return 1;
    }

    struct epoll_event events[1];
    int ret = epoll_pwait(epfd, events, 1, 0, NULL);
    if (ret < 0) {
        perror("epoll_pwait with NULL sigmask");
        return 1;
    }
    if (ret != 1 || !(events[0].events & EPOLLOUT)) {
        fprintf(stderr, "FAIL: epoll_pwait should report write ready\n");
        return 1;
    }

    close(epfd);
    close(pipefd[0]);
    close(pipefd[1]);
    printf("test_epoll_pwait_null_sigmask: PASS\n");
    return 0;
}

int main(void) {
    int failed = 0;

    printf("=== Signal mask tests for ppoll/pselect/epoll_pwait ===\n\n");

    failed += test_ppoll_null_sigmask();
#if defined(__x86_64__) || defined(__aarch64__)
    // pselect tests are skipped on 32-bit as pselect6 syscall isn't handled
    failed += test_pselect_null_sigmask();
#else
    printf("test_pselect_null_sigmask: SKIPPED (32-bit)\n");
#endif
    failed += test_epoll_pwait_null_sigmask();
    failed += test_ppoll_sigmask_restored();
#if defined(__x86_64__) || defined(__aarch64__)
    failed += test_pselect_sigmask_restored();
#else
    printf("test_pselect_sigmask_restored: SKIPPED (32-bit)\n");
#endif
    failed += test_epoll_pwait_sigmask_restored();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    } else {
        printf("%d test(s) failed.\n", failed);
        return 1;
    }
}
