// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#ifndef SYS_faccessat2
#error SYS_faccessat2 is not defined on this build host
#endif

static long raw_faccessat2(int dirfd, const char *pathname, int mode, int flags) {
    return syscall(SYS_faccessat2, dirfd, pathname, mode, flags);
}

static void expect_faccessat2_ok(int dirfd, const char *pathname, int mode, int flags,
                                 const char *op) {
    errno = 0;
    TEST_ASSERT(raw_faccessat2(dirfd, pathname, mode, flags) == 0, op);
}

static void expect_faccessat2_errno(int dirfd, const char *pathname, int mode, int flags,
                                    int expected_errno, const char *op) {
    errno = 0;
    long ret = raw_faccessat2(dirfd, pathname, mode, flags);
    TEST_ASSERT(ret == -1 && errno == expected_errno, op);
}

static void test_at_fdcwd_success(void) {
    const char *path = "/tmp/lb_faccessat2_success";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat2_ok(AT_FDCWD, path, F_OK, 0,
                         "faccessat2 AT_FDCWD F_OK should succeed");
    expect_faccessat2_ok(AT_FDCWD, path, R_OK | W_OK, 0,
                         "faccessat2 AT_FDCWD R_OK|W_OK should succeed");

    struct stat st;
    TEST_ASSERT(stat(path, &st) == 0, "stat should observe file after faccessat2");

    unlink(path);
}

static void test_accepted_flags_regular_file(void) {
    const char *path = "/tmp/lb_faccessat2_flags";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat2_ok(AT_FDCWD, path, F_OK, AT_EACCESS,
                         "faccessat2 AT_EACCESS should succeed for accessible file");

    // TODO: Add symlink follow/no-follow coverage once LiteBox file systems can
    // distinguish stat and lstat semantics for symlink targets.
    expect_faccessat2_ok(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW,
                         "faccessat2 AT_SYMLINK_NOFOLLOW should succeed for regular file");

    unlink(path);
}

static void test_owner_bits_take_precedence(void) {
    const char *other_read_path = "/tmp/lb_faccessat2_other_read";
    const char *owner_read_path = "/tmp/lb_faccessat2_owner_read";
    unlink(other_read_path);
    unlink(owner_read_path);
    create_test_file(other_read_path, 0004);
    create_test_file(owner_read_path, 0400);

    expect_faccessat2_errno(AT_FDCWD, other_read_path, R_OK, 0, EACCES,
                            "owner read should not fall through to other read bit");
    expect_faccessat2_errno(AT_FDCWD, other_read_path, R_OK, AT_EACCESS, EACCES,
                            "AT_EACCESS owner read should not fall through to other read bit");
    expect_faccessat2_ok(AT_FDCWD, owner_read_path, R_OK, AT_EACCESS,
                         "AT_EACCESS owner read bit should allow R_OK");

    unlink(other_read_path);
    unlink(owner_read_path);
}

static void test_empty_path_success(void) {
    const char *path = "/tmp/lb_faccessat2_empty_path";
    unlink(path);
    create_test_file(path, 0400);

    int fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open test file failed");

    expect_faccessat2_ok(fd, "", R_OK, AT_EMPTY_PATH,
                         "faccessat2 AT_EMPTY_PATH R_OK should succeed on fd");
    expect_faccessat2_errno(fd, "", W_OK, AT_EMPTY_PATH, EACCES,
                            "faccessat2 AT_EMPTY_PATH W_OK should fail with EACCES");

    struct stat st;
    TEST_ASSERT(fstat(fd, &st) == 0, "fstat should observe fd after faccessat2");

    close(fd);
    unlink(path);
}

static void test_missing_path_enoent(void) {
    const char *path = "/tmp/lb_faccessat2_missing";
    unlink(path);

    expect_faccessat2_errno(AT_FDCWD, path, F_OK, 0, ENOENT,
                            "faccessat2 on a missing path should fail with ENOENT");
}

static void test_mode_permission_denied(void) {
    const char *path = "/tmp/lb_faccessat2_readonly";
    unlink(path);
    create_test_file(path, 0400);

    expect_faccessat2_errno(AT_FDCWD, path, W_OK, 0, EACCES,
                            "faccessat2 W_OK on read-only file should fail with EACCES");

    errno = 0;
    int fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open should observe that the file still exists");
    close(fd);

    unlink(path);
}

static void test_invalid_mode_einval(void) {
    const char *path = "/tmp/lb_faccessat2_invalid_mode";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat2_errno(AT_FDCWD, path, R_OK | 8, 0, EINVAL,
                            "faccessat2 with invalid mode bits should fail with EINVAL");

    unlink(path);
}

static void test_invalid_flags_einval(void) {
    const char *path = "/tmp/lb_faccessat2_invalid_flags";
    unlink(path);
    create_test_file(path, 0600);

    expect_faccessat2_errno(AT_FDCWD, path, F_OK, 0x40000000, EINVAL,
                            "faccessat2 with invalid flags should fail with EINVAL");

    unlink(path);
}

int main(void) {
    printf("===== faccessat2 tests =====\n");
    test_at_fdcwd_success();
    test_accepted_flags_regular_file();
    test_owner_bits_take_precedence();
    test_empty_path_success();
    test_missing_path_enoent();
    test_mode_permission_denied();
    test_invalid_mode_einval();
    test_invalid_flags_einval();
    printf("All faccessat2 tests passed.\n");
    return 0;
}
