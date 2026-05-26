// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#ifndef SYS_faccessat2
#error SYS_faccessat2 is not defined on this build host
#endif

static long raw_faccessat2(int dirfd, const char *pathname, int mode, int flags) {
    return syscall(SYS_faccessat2, dirfd, pathname, mode, flags);
}

static void test_at_fdcwd_success(void) {
    const char *path = "/tmp/lb_faccessat2_success";
    unlink(path);
    create_test_file(path, 0600);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, F_OK, 0);
    EXPECT(ret == 0, "faccessat2 AT_FDCWD F_OK should succeed");

    errno = 0;
    ret = raw_faccessat2(AT_FDCWD, path, R_OK | W_OK, 0);
    EXPECT(ret == 0, "faccessat2 AT_FDCWD R_OK|W_OK should succeed");

    struct stat st;
    EXPECT(stat(path, &st) == 0, "stat should observe file after faccessat2");

    unlink(path);
}

static void test_supported_flags_regular_file(void) {
    const char *path = "/tmp/lb_faccessat2_flags";
    unlink(path);
    create_test_file(path, 0600);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, F_OK, AT_EACCESS);
    EXPECT(ret == 0, "faccessat2 AT_EACCESS should succeed for accessible file");

    errno = 0;
    ret = raw_faccessat2(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW);
    EXPECT(ret == 0,
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

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, other_read_path, R_OK, 0);
    EXPECT(ret == -1 && errno == EACCES,
           "owner read should not fall through to other read bit");

    errno = 0;
    ret = raw_faccessat2(AT_FDCWD, other_read_path, R_OK, AT_EACCESS);
    EXPECT(ret == -1 && errno == EACCES,
           "AT_EACCESS owner read should not fall through to other read bit");

    errno = 0;
    ret = raw_faccessat2(AT_FDCWD, owner_read_path, R_OK, AT_EACCESS);
    EXPECT(ret == 0, "AT_EACCESS owner read bit should allow R_OK");

    unlink(other_read_path);
    unlink(owner_read_path);
}

static void test_empty_path_success(void) {
    const char *path = "/tmp/lb_faccessat2_empty_path";
    unlink(path);
    create_test_file(path, 0400);

    int fd = open(path, O_RDONLY);
    EXPECT(fd >= 0, "open test file failed");

    errno = 0;
    long ret = raw_faccessat2(fd, "", R_OK, AT_EMPTY_PATH);
    EXPECT(ret == 0, "faccessat2 AT_EMPTY_PATH R_OK should succeed on fd");

    errno = 0;
    ret = raw_faccessat2(fd, "", W_OK, AT_EMPTY_PATH);
    EXPECT(ret == -1 && errno == EACCES,
           "faccessat2 AT_EMPTY_PATH W_OK should fail with EACCES");

    struct stat st;
    EXPECT(fstat(fd, &st) == 0, "fstat should observe fd after faccessat2");

    close(fd);
    unlink(path);
}

static void test_missing_path_enoent(void) {
    const char *path = "/tmp/lb_faccessat2_missing";
    unlink(path);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, F_OK, 0);
    EXPECT(ret == -1 && errno == ENOENT,
           "faccessat2 on a missing path should fail with ENOENT");
}

static void test_mode_permission_denied(void) {
    const char *path = "/tmp/lb_faccessat2_readonly";
    unlink(path);
    create_test_file(path, 0400);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, W_OK, 0);
    EXPECT(ret == -1 && errno == EACCES,
           "faccessat2 W_OK on read-only file should fail with EACCES");

    errno = 0;
    ret = open(path, O_RDONLY);
    EXPECT(ret >= 0, "open should observe that the file still exists");
    close((int)ret);

    unlink(path);
}

static void test_invalid_mode_einval(void) {
    const char *path = "/tmp/lb_faccessat2_invalid_mode";
    unlink(path);
    create_test_file(path, 0600);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, R_OK | 8, 0);
    EXPECT(ret == -1 && errno == EINVAL,
           "faccessat2 with invalid mode bits should fail with EINVAL");

    unlink(path);
}

static void test_invalid_flags_einval(void) {
    const char *path = "/tmp/lb_faccessat2_invalid_flags";
    unlink(path);
    create_test_file(path, 0600);

    errno = 0;
    long ret = raw_faccessat2(AT_FDCWD, path, F_OK, 0x40000000);
    EXPECT(ret == -1 && errno == EINVAL,
           "faccessat2 with invalid flags should fail with EINVAL");

    unlink(path);
}

int main(void) {
    printf("===== faccessat2 tests =====\n");
    test_at_fdcwd_success();
    test_supported_flags_regular_file();
    test_owner_bits_take_precedence();
    test_empty_path_success();
    test_missing_path_enoent();
    test_mode_permission_denied();
    test_invalid_mode_einval();
    test_invalid_flags_einval();
    printf("All faccessat2 tests passed.\n");
    return 0;
}
