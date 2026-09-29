// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: restarting blocking syscalls interrupted by a signal handler. A read
// restarts only if the handler has SA_RESTART, while poll and socket calls with
// a timeout (SO_RCVTIMEO) fail with EINTR regardless. See `man 7 signal`.

#include "helpers.h"

#include <signal.h>
#include <sys/un.h>

// The handler writes a byte here, so a restarted read completes.
static int wake_fd = -1;
static volatile sig_atomic_t handler_count;

static void wake_handler(int sig) {
    (void)sig;
    // The syscall wrongly blocked again after the first run.
    if (++handler_count > 1) {
        static const char msg[] = "FAIL: syscall blocked again after its handler ran\n";
        (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
        _exit(3);
    }
    char byte = 'x';
    if (write(wake_fd, &byte, 1) != 1) {
        _exit(2);
    }
    // Rearm, so a syscall wrongly blocking again fails instead of hanging.
    struct itimerval timer = {{0, 0}, {0, 200000}};
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        _exit(2);
    }
}

// Delivers SIGALRM to `wake_handler`, installed with `flags`, while the caller blocks.
static void arm_wake(int fd, int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = wake_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = flags;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");

    wake_fd = fd;
    handler_count = 0;
    struct itimerval timer = {{0, 0}, {0, 200000}};
    TEST_ASSERT(setitimer(ITIMER_REAL, &timer, NULL) == 0, "setitimer failed");
}

// Stops the timer once the blocking call returns, preserving its errno.
static void disarm_wake(void) {
    int saved_errno = errno;
    struct itimerval timer = {{0, 0}, {0, 0}};
    TEST_ASSERT(setitimer(ITIMER_REAL, &timer, NULL) == 0, "setitimer failed");
    errno = saved_errno;
}

static void expect_byte(int fd, const char *op) {
    char byte = 0;
    TEST_ASSERT(read(fd, &byte, 1) == 1, op);
    TEST_ASSERT(byte == 'x', op);
}

static void test_read_restarts_with_sa_restart(void) {
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe failed");
    arm_wake(fds[1], SA_RESTART);

    char byte = 0;
    errno = 0;
    ssize_t n = read(fds[0], &byte, 1);
    disarm_wake();
    TEST_ASSERT(n == 1, "read must restart and return the handler's byte");
    TEST_ASSERT(byte == 'x', "read must return the handler's byte");
    TEST_ASSERT(handler_count == 1, "handler must run exactly once");

    close(fds[0]);
    close(fds[1]);
    printf("read_restarts_with_sa_restart: PASS\n");
}

static void test_read_interrupted_without_sa_restart(void) {
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe failed");
    arm_wake(fds[1], 0);

    char byte = 0;
    errno = 0;
    ssize_t n = read(fds[0], &byte, 1);
    disarm_wake();
    TEST_ASSERT(n == -1 && errno == EINTR, "read must fail with EINTR");
    TEST_ASSERT(handler_count == 1, "handler must run exactly once");
    expect_byte(fds[0], "the handler's byte must remain");

    close(fds[0]);
    close(fds[1]);
    printf("read_interrupted_without_sa_restart: PASS\n");
}

static void test_poll_not_restarted(void) {
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe failed");
    arm_wake(fds[1], SA_RESTART);

    struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
    errno = 0;
    int r = poll(&pfd, 1, -1);
    disarm_wake();
    TEST_ASSERT(r == -1 && errno == EINTR, "poll must fail with EINTR despite SA_RESTART");
    TEST_ASSERT(handler_count == 1, "handler must run exactly once");
    expect_byte(fds[0], "the handler's byte must remain");

    close(fds[0]);
    close(fds[1]);
    printf("poll_not_restarted: PASS\n");
}

static void test_timed_recv_not_restarted(void) {
    int sv[2];
    make_socket_pair(SOCK_STREAM, sv);
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    TEST_ASSERT(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "setsockopt(SO_RCVTIMEO) failed");
    arm_wake(sv[1], SA_RESTART);

    char byte = 0;
    errno = 0;
    ssize_t n = recv(sv[0], &byte, 1, 0);
    disarm_wake();
    TEST_ASSERT(n == -1 && errno == EINTR, "recv with SO_RCVTIMEO must fail with EINTR");
    TEST_ASSERT(handler_count == 1, "handler must run exactly once");
    expect_byte(sv[0], "the handler's byte must remain");

    close_pair(sv);
    printf("timed_recv_not_restarted: PASS\n");
}

static void test_timed_accept_not_restarted(void) {
    const char *path = "/tmp/syscall_restart.sock";
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path);

    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_ASSERT(listener >= 0, "socket failed");
    TEST_ASSERT(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind failed");
    TEST_ASSERT(listen(listener, 1) == 0, "listen failed");
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    TEST_ASSERT(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "setsockopt(SO_RCVTIMEO) failed");
    // The handler's byte is not what accept waits for.
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe failed");
    arm_wake(fds[1], SA_RESTART);

    errno = 0;
    int conn = accept(listener, NULL, NULL);
    disarm_wake();
    TEST_ASSERT(conn == -1 && errno == EINTR, "accept with SO_RCVTIMEO must fail with EINTR");
    TEST_ASSERT(handler_count == 1, "handler must run exactly once");

    close(fds[0]);
    close(fds[1]);
    close(listener);
    unlink(path);
    printf("timed_accept_not_restarted: PASS\n");
}

int main(void) {
    printf("Starting syscall restart tests...\n");

    test_read_restarts_with_sa_restart();
    test_read_interrupted_without_sa_restart();
    test_poll_not_restarted();
    test_timed_recv_not_restarted();
    test_timed_accept_not_restarted();

    printf("All syscall restart tests passed!\n");
    return 0;
}
