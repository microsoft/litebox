// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

static long raw_faccessat(int dirfd, const char *pathname, int mode) {
    return syscall(SYS_faccessat, dirfd, pathname, mode);
}

static void expect_faccessat_ok(int dirfd, const char *pathname, int mode, const char *op) {
    errno = 0;
    TEST_ASSERT(raw_faccessat(dirfd, pathname, mode) == 0, op);
}

static void expect_faccessat_errno(int dirfd, const char *pathname, int mode,
                                   int expected_errno, const char *op) {
    errno = 0;
    long ret = raw_faccessat(dirfd, pathname, mode);
    TEST_ASSERT(ret == -1 && errno == expected_errno, op);
}

static void test_at_fdcwd_success(void) {
    const char *path = "/tmp/lb_faccessat_success";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat_ok(AT_FDCWD, path, F_OK, "faccessat AT_FDCWD F_OK should succeed");
    expect_faccessat_ok(AT_FDCWD, path, R_OK | W_OK,
                        "faccessat AT_FDCWD R_OK|W_OK should succeed");

    struct stat st;
    TEST_ASSERT(stat(path, &st) == 0, "stat should observe file after faccessat");

    unlink(path);
}

static void test_missing_path_enoent(void) {
    const char *path = "/tmp/lb_faccessat_missing";
    unlink(path);

    expect_faccessat_errno(AT_FDCWD, path, F_OK, ENOENT,
                           "faccessat on a missing path should fail with ENOENT");
}

static void test_mode_permission_denied(void) {
    const char *path = "/tmp/lb_faccessat_readonly";
    unlink(path);
    create_test_file(path, 0400);

    expect_faccessat_errno(AT_FDCWD, path, W_OK, EACCES,
                           "faccessat W_OK on read-only file should fail with EACCES");

    errno = 0;
    int fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open should observe that the file still exists");
    close(fd);

    unlink(path);
}

static void test_invalid_mode_einval(void) {
    const char *path = "/tmp/lb_faccessat_invalid_mode";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat_errno(AT_FDCWD, path, R_OK | 8, EINVAL,
                           "faccessat with invalid mode bits should fail with EINVAL");

    unlink(path);
}

int main(void) {
    printf("===== faccessat tests =====\n");
    test_at_fdcwd_success();
    test_missing_path_enoent();
    test_mode_permission_denied();
    test_invalid_mode_einval();
    printf("All faccessat tests passed.\n");
    return 0;
}
