// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: SIGINT delivery (self-sent via raise/kill)

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

static volatile sig_atomic_t sigint_count = 0;

static void sigint_handler(int sig) {
    (void)sig;
    sigint_count++;
}

// Test that SIGINT default action terminates via exit_group when no handler
// is installed. We can't test this directly (it would kill us), so instead
// verify that installing SIG_IGN causes SIGINT to be ignored.
int test_sigint_ignore(void) {
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    TEST_ASSERT(sigaction(SIGINT, &sa, NULL) == 0, "sigaction(SIG_IGN) failed");

    // Sending SIGINT should be silently ignored.
    TEST_ASSERT(raise(SIGINT) == 0, "raise(SIGINT) failed");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);

    printf("sigint_ignore: PASS\n");
    return 0;
}

// Test that SIGINT is delivered to a custom handler via raise().
int test_sigint_raise(void) {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    TEST_ASSERT(sigaction(SIGINT, &sa, NULL) == 0, "sigaction failed");

    sigint_count = 0;
    TEST_ASSERT(raise(SIGINT) == 0, "raise(SIGINT) failed");

    TEST_ASSERT(sigint_count == 1, "SIGINT handler should have been called exactly once");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);

    printf("sigint_raise: PASS\n");
    return 0;
}

// Test that SIGINT is delivered via kill(getpid(), SIGINT).
int test_sigint_kill(void) {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    TEST_ASSERT(sigaction(SIGINT, &sa, NULL) == 0, "sigaction failed");

    sigint_count = 0;
    TEST_ASSERT(kill(getpid(), SIGINT) == 0, "kill(getpid(), SIGINT) failed");

    TEST_ASSERT(sigint_count == 1, "SIGINT handler should have been called exactly once");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);

    printf("sigint_kill: PASS\n");
    return 0;
}

// Test that SIGINT can be blocked and then delivered when unblocked.
int test_sigint_block_unblock(void) {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    TEST_ASSERT(sigaction(SIGINT, &sa, NULL) == 0, "sigaction failed");

    sigint_count = 0;

    // Block SIGINT.
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &block_set, &old_set) == 0, "sigprocmask(BLOCK) failed");

    // Send SIGINT while blocked -- should be queued, not delivered.
    TEST_ASSERT(raise(SIGINT) == 0, "raise(SIGINT) failed");
    TEST_ASSERT(sigint_count == 0, "SIGINT should be pending, not delivered");

    // Unblock SIGINT -- should now be delivered.
    TEST_ASSERT(sigprocmask(SIG_SETMASK, &old_set, NULL) == 0, "sigprocmask(RESTORE) failed");
    TEST_ASSERT(sigint_count == 1, "SIGINT should have been delivered after unblocking");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);

    printf("sigint_block_unblock: PASS\n");
    return 0;
}

// Test that multiple SIGINTs are coalesced (standard signals are not queued).
int test_sigint_coalesce(void) {
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    TEST_ASSERT(sigaction(SIGINT, &sa, NULL) == 0, "sigaction failed");

    sigint_count = 0;

    // Block SIGINT.
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &block_set, &old_set) == 0, "sigprocmask(BLOCK) failed");

    // Send multiple SIGINTs while blocked.
    for (int i = 0; i < 5; i++) {
        raise(SIGINT);
    }
    TEST_ASSERT(sigint_count == 0, "SIGINT should not be delivered while blocked");

    // Unblock -- only one delivery expected (standard signal coalescing).
    TEST_ASSERT(sigprocmask(SIG_SETMASK, &old_set, NULL) == 0, "sigprocmask(RESTORE) failed");
    TEST_ASSERT(sigint_count == 1,
                "only one SIGINT should be delivered (standard signal coalescing)");

    // Restore default handler.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);

    printf("sigint_coalesce: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting SIGINT tests...\n");

    if (test_sigint_ignore() != 0) return 1;
    if (test_sigint_raise() != 0) return 1;
    if (test_sigint_kill() != 0) return 1;
    if (test_sigint_block_unblock() != 0) return 1;
    if (test_sigint_coalesce() != 0) return 1;

    printf("All SIGINT tests passed!\n");
    return 0;
}
