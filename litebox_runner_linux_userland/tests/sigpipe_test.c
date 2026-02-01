// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests for SIGPIPE signal delivery

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

static volatile sig_atomic_t sigpipe_received = 0;

static void sigpipe_handler(int sig) {
    (void)sig;
    sigpipe_received = 1;
}

// Test 1: SIGPIPE on write to closed pipe
int test_pipe_sigpipe(void) {
    int pipefd[2];
    sigpipe_received = 0;

    // Set up SIGPIPE handler
    struct sigaction sa, old_sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigpipe_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &old_sa) == -1) {
        perror("sigaction");
        return 1;
    }

    // Create pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Close read end
    close(pipefd[0]);

    // Write to pipe should get SIGPIPE and EPIPE
    char buf[] = "test";
    ssize_t ret = write(pipefd[1], buf, sizeof(buf));

    if (ret != -1) {
        fprintf(stderr, "FAIL: write should have returned -1, got %zd\n", ret);
        return 1;
    }
    if (errno != EPIPE) {
        fprintf(stderr, "FAIL: errno should be EPIPE (%d), got %d\n", EPIPE, errno);
        return 1;
    }
    if (!sigpipe_received) {
        fprintf(stderr, "FAIL: SIGPIPE handler was not called\n");
        return 1;
    }

    close(pipefd[1]);
    sigaction(SIGPIPE, &old_sa, NULL);
    printf("test_pipe_sigpipe: PASS\n");
    return 0;
}

// Test 2: SIGPIPE ignored (SIG_IGN)
int test_pipe_sigpipe_ignored(void) {
    int pipefd[2];

    // Set SIGPIPE to SIG_IGN
    struct sigaction sa, old_sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &old_sa) == -1) {
        perror("sigaction");
        return 1;
    }

    // Create pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Close read end
    close(pipefd[0]);

    // Write to pipe should get EPIPE (no signal because ignored)
    char buf[] = "test";
    ssize_t ret = write(pipefd[1], buf, sizeof(buf));

    if (ret != -1) {
        fprintf(stderr, "FAIL: write should have returned -1, got %zd\n", ret);
        return 1;
    }
    if (errno != EPIPE) {
        fprintf(stderr, "FAIL: errno should be EPIPE (%d), got %d\n", EPIPE, errno);
        return 1;
    }

    close(pipefd[1]);
    sigaction(SIGPIPE, &old_sa, NULL);
    printf("test_pipe_sigpipe_ignored: PASS\n");
    return 0;
}

// Test 3: SIGPIPE blocked (signal pending but not delivered)
int test_pipe_sigpipe_blocked(void) {
    int pipefd[2];

    // Block SIGPIPE
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &block_set, &old_set) == -1) {
        perror("sigprocmask");
        return 1;
    }

    // Create pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }

    // Close read end
    close(pipefd[0]);

    // Write to pipe should get EPIPE (signal blocked)
    char buf[] = "test";
    ssize_t ret = write(pipefd[1], buf, sizeof(buf));

    if (ret != -1) {
        fprintf(stderr, "FAIL: write should have returned -1, got %zd\n", ret);
        return 1;
    }
    if (errno != EPIPE) {
        fprintf(stderr, "FAIL: errno should be EPIPE (%d), got %d\n", EPIPE, errno);
        return 1;
    }

    // Check that SIGPIPE is pending
    sigset_t pending;
    if (sigpending(&pending) == -1) {
        perror("sigpending");
        return 1;
    }
    if (!sigismember(&pending, SIGPIPE)) {
        fprintf(stderr, "FAIL: SIGPIPE should be pending\n");
        return 1;
    }

    close(pipefd[1]);

    // Clear the pending signal by setting handler to SIG_IGN and unblocking
    struct sigaction sa, old_sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, &old_sa);
    sigprocmask(SIG_SETMASK, &old_set, NULL);
    sigaction(SIGPIPE, &old_sa, NULL);

    printf("test_pipe_sigpipe_blocked: PASS\n");
    return 0;
}

// Test 4: Unix socket MSG_NOSIGNAL flag
int test_unix_socket_nosignal(void) {
    int sv[2];
    sigpipe_received = 0;

    // Set up SIGPIPE handler
    struct sigaction sa, old_sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigpipe_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &old_sa) == -1) {
        perror("sigaction");
        return 1;
    }

    // Create socket pair
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        return 1;
    }

    // Close read end
    close(sv[0]);

    // Send with MSG_NOSIGNAL - should NOT generate SIGPIPE
    char buf[] = "test";
    ssize_t ret = send(sv[1], buf, sizeof(buf), MSG_NOSIGNAL);

    if (ret != -1) {
        fprintf(stderr, "FAIL: send should have returned -1, got %zd\n", ret);
        return 1;
    }
    if (errno != EPIPE) {
        fprintf(stderr, "FAIL: errno should be EPIPE (%d), got %d\n", EPIPE, errno);
        return 1;
    }
    if (sigpipe_received) {
        fprintf(stderr, "FAIL: SIGPIPE should NOT have been received with MSG_NOSIGNAL\n");
        return 1;
    }

    close(sv[1]);
    sigaction(SIGPIPE, &old_sa, NULL);
    printf("test_unix_socket_nosignal: PASS\n");
    return 0;
}

// Test 5: Unix socket without MSG_NOSIGNAL (should get SIGPIPE)
int test_unix_socket_sigpipe(void) {
    int sv[2];
    sigpipe_received = 0;

    // Set up SIGPIPE handler
    struct sigaction sa, old_sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigpipe_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, &old_sa) == -1) {
        perror("sigaction");
        return 1;
    }

    // Create socket pair
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        perror("socketpair");
        return 1;
    }

    // Close read end
    close(sv[0]);

    // Send without MSG_NOSIGNAL - SHOULD generate SIGPIPE
    char buf[] = "test";
    ssize_t ret = send(sv[1], buf, sizeof(buf), 0);

    if (ret != -1) {
        fprintf(stderr, "FAIL: send should have returned -1, got %zd\n", ret);
        return 1;
    }
    if (errno != EPIPE) {
        fprintf(stderr, "FAIL: errno should be EPIPE (%d), got %d\n", EPIPE, errno);
        return 1;
    }
    if (!sigpipe_received) {
        fprintf(stderr, "FAIL: SIGPIPE handler should have been called\n");
        return 1;
    }

    close(sv[1]);
    sigaction(SIGPIPE, &old_sa, NULL);
    printf("test_unix_socket_sigpipe: PASS\n");
    return 0;
}

int main(void) {
    int failures = 0;

    failures += test_pipe_sigpipe();
    failures += test_pipe_sigpipe_ignored();
    failures += test_pipe_sigpipe_blocked();
    failures += test_unix_socket_nosignal();
    failures += test_unix_socket_sigpipe();

    if (failures > 0) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }

    printf("\nAll SIGPIPE tests passed!\n");
    return 0;
}
