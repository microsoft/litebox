// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <fcntl.h>
#include <sys/stat.h>

#ifndef SYS_mkdirat
#error SYS_mkdirat is not defined on this build host
#endif

static long raw_mkdirat(int dirfd, const char *pathname, mode_t mode) {
    return syscall(SYS_mkdirat, dirfd, pathname, mode);
}

static void expect_mkdirat_success(int dirfd, const char *pathname, mode_t mode,
                                   const char *msg) {
    errno = 0;
    long ret = raw_mkdirat(dirfd, pathname, mode);
    TEST_ASSERT(ret == 0, msg);
}

static void expect_mkdirat_errno(int dirfd, const char *pathname, mode_t mode,
                                 int expected_errno, const char *msg) {
    errno = 0;
    long ret = raw_mkdirat(dirfd, pathname, mode);
    TEST_ASSERT(ret == -1, msg);
    TEST_ASSERT(errno == expected_errno, msg);
}

static void expect_directory_mode(const char *path, mode_t mode, const char *msg) {
    struct stat st;

    errno = 0;
    TEST_ASSERT(stat(path, &st) == 0, msg);
    TEST_ASSERT(S_ISDIR(st.st_mode), "stat should observe a directory");
    TEST_ASSERT((st.st_mode & 0777) == mode, msg);
}

static void create_regular_file(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    TEST_ASSERT(fd >= 0, "create test file failed");
    TEST_ASSERT(close(fd) == 0, "close test file failed");
}

static void test_at_fdcwd_relative_success(void) {
    const char *name = "lb_mkdirat_relative";
    const char *path = "/tmp/lb_mkdirat_relative";
    char old_cwd[4096];

    rmdir(path);
    TEST_ASSERT(getcwd(old_cwd, sizeof(old_cwd)) != NULL, "getcwd failed");
    TEST_ASSERT(chdir("/tmp") == 0, "chdir /tmp failed");

    expect_mkdirat_success(AT_FDCWD, name, 0777,
                           "mkdirat AT_FDCWD relative should succeed");
    expect_directory_mode(path, 0755,
                          "stat should observe mkdirat AT_FDCWD relative result");

    TEST_ASSERT(chdir(old_cwd) == 0, "restore cwd failed");
    TEST_ASSERT(rmdir(path) == 0, "cleanup relative directory failed");
}

static void test_absolute_path_ignores_dirfd(void) {
    const char *path = "/tmp/lb_mkdirat_absolute";

    rmdir(path);
    expect_mkdirat_success(-2, path, 0700,
                           "mkdirat absolute path should ignore invalid dirfd");
    expect_directory_mode(path, 0700,
                          "stat should observe mkdirat absolute path result");
    TEST_ASSERT(rmdir(path) == 0, "cleanup absolute directory failed");
}

static void test_existing_path_eexist(void) {
    const char *path = "/tmp/lb_mkdirat_existing";

    rmdir(path);
    TEST_ASSERT(mkdir(path, 0700) == 0, "setup existing directory failed");
    expect_mkdirat_errno(AT_FDCWD, path, 0700, EEXIST,
                         "mkdirat existing path should fail with EEXIST");
    TEST_ASSERT(rmdir(path) == 0, "cleanup existing directory failed");
}

static void test_missing_parent_enoent(void) {
    const char *parent = "/tmp/lb_mkdirat_missing_parent";
    const char *path = "/tmp/lb_mkdirat_missing_parent/child";

    rmdir(path);
    rmdir(parent);
    expect_mkdirat_errno(AT_FDCWD, path, 0700, ENOENT,
                         "mkdirat missing parent should fail with ENOENT");
}

static void test_component_not_directory_enotdir(void) {
    const char *file = "/tmp/lb_mkdirat_file";
    const char *path = "/tmp/lb_mkdirat_file/child";

    unlink(file);
    create_regular_file(file);
    expect_mkdirat_errno(AT_FDCWD, path, 0700, ENOTDIR,
                         "mkdirat through regular file should fail with ENOTDIR");
    TEST_ASSERT(unlink(file) == 0, "cleanup regular file failed");
}

static void test_empty_path_enoent(void) {
    expect_mkdirat_errno(AT_FDCWD, "", 0700, ENOENT,
                         "mkdirat empty path should fail with ENOENT");
}

int main(void) {
    mode_t old_umask = umask(0022);

    printf("===== mkdirat tests =====\n");
    test_at_fdcwd_relative_success();
    test_absolute_path_ignores_dirfd();
    test_existing_path_eexist();
    test_missing_parent_enoent();
    test_component_not_directory_enotdir();
    test_empty_path_enoent();
    umask(old_umask);
    printf("All mkdirat tests passed.\n");
    return 0;
}