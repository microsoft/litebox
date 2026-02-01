// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: getpid, getppid, gettid, getuid, getgid, etc.
// Process/user identity syscalls

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

int test_getpid(void) {
    pid_t pid = getpid();
    TEST_ASSERT(pid > 0, "getpid should return positive value");

    // Call again - should be same
    pid_t pid2 = getpid();
    TEST_ASSERT(pid == pid2, "getpid should be consistent");

    printf("getpid: PASS (pid=%d)\n", pid);
    return 0;
}

int test_getppid(void) {
    pid_t ppid = getppid();
    TEST_ASSERT(ppid >= 0, "getppid should return non-negative");

    printf("getppid: PASS (ppid=%d)\n", ppid);
    return 0;
}

int test_gettid(void) {
    pid_t tid = syscall(SYS_gettid);
    TEST_ASSERT(tid > 0, "gettid should return positive value");

    // In single-threaded process, tid == pid
    pid_t pid = getpid();
    TEST_ASSERT(tid == pid, "in main thread, tid should equal pid");

    printf("gettid: PASS (tid=%d)\n", tid);
    return 0;
}

int test_getuid_getgid(void) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();

    // These should all be non-negative
    TEST_ASSERT(uid >= 0, "getuid should return non-negative");
    TEST_ASSERT(euid >= 0, "geteuid should return non-negative");
    TEST_ASSERT(gid >= 0, "getgid should return non-negative");
    TEST_ASSERT(egid >= 0, "getegid should return non-negative");

    printf("getuid/getgid: PASS (uid=%d, euid=%d, gid=%d, egid=%d)\n",
           uid, euid, gid, egid);
    return 0;
}

int test_getpid_consistency(void) {
    // Verify consistency across multiple calls
    pid_t pids[10];
    for (int i = 0; i < 10; i++) {
        pids[i] = getpid();
    }
    for (int i = 1; i < 10; i++) {
        TEST_ASSERT(pids[i] == pids[0], "getpid should be stable");
    }

    printf("getpid consistency: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting process identity tests...\n");

    if (test_getpid() != 0) return 1;
    if (test_getppid() != 0) return 1;
    if (test_gettid() != 0) return 1;
    if (test_getuid_getgid() != 0) return 1;
    if (test_getpid_consistency() != 0) return 1;

    printf("All process identity tests passed!\n");
    return 0;
}
