// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: statx happy path, AT_EMPTY_PATH on fds, ENOENT/EBADF/EINVAL errno
// branches. Goes through syscall(SYS_statx, ...) to exercise the raw kernel
// surface that LiteBox intercepts (not the libc wrapper, which may massage
// arguments).

#include "helpers.h"

#include <fcntl.h>
#include <linux/stat.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef STATX__RESERVED
#define STATX__RESERVED 0x80000000U
#endif

#define TEST_PATH "/tmp/statx_test_file"
#define TEST_CONTENT "hello statx"
#define TEST_CONTENT_LEN ((size_t)(sizeof(TEST_CONTENT) - 1))

static int raw_statx(int dirfd, const char *pathname, int flags,
                     unsigned int mask, struct statx *buf) {
    return (int)syscall(SYS_statx, dirfd, pathname, flags, mask, buf);
}

static void expect_statx(int dirfd, const char *pathname, int flags,
                         unsigned int mask, struct statx *sx, const char *op) {
    memset(sx, 0, sizeof(*sx));
    errno = 0;
    TEST_ASSERT(raw_statx(dirfd, pathname, flags, mask, sx) == 0, op);
}

static void expect_statx_errno(int dirfd, const char *pathname, int flags,
                               unsigned int mask, int expected_errno,
                               const char *op) {
    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    errno = 0;
    int rc = raw_statx(dirfd, pathname, flags, mask, &sx);
    TEST_ASSERT(rc == -1, op);
    TEST_ASSERT(errno == expected_errno, op);
}

static void seed_test_file(void) {
    int fd = openat(AT_FDCWD, TEST_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    TEST_ASSERT(fd >= 0, "openat create test file");
    ssize_t n = write(fd, TEST_CONTENT, TEST_CONTENT_LEN);
    TEST_ASSERT(n == (ssize_t)TEST_CONTENT_LEN, "write test content");
    TEST_ASSERT(close(fd) == 0, "close test file");
}

static void cleanup_test_file(void) {
    (void)unlink(TEST_PATH);
}

static void test_absolute_happy_path(void) {
    struct statx sx;
    expect_statx(AT_FDCWD, TEST_PATH, 0, STATX_BASIC_STATS, &sx,
                 "statx absolute happy path");
    TEST_ASSERT((sx.stx_mask & STATX_TYPE) != 0, "stx_mask STATX_TYPE set");
    TEST_ASSERT((sx.stx_mask & STATX_SIZE) != 0, "stx_mask STATX_SIZE set");
    TEST_ASSERT((sx.stx_mode & S_IFMT) == S_IFREG, "stx_mode says regular file");
    TEST_ASSERT(sx.stx_size == TEST_CONTENT_LEN, "stx_size matches written length");
}

static void test_at_empty_path_fd(void) {
    int fd = openat(AT_FDCWD, TEST_PATH, O_RDONLY);
    TEST_ASSERT(fd >= 0, "openat for AT_EMPTY_PATH");
    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    int rc = raw_statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx);
    int saved = errno;
    TEST_ASSERT(close(fd) == 0, "close AT_EMPTY_PATH fd");
    errno = saved;
    TEST_ASSERT(rc == 0, "statx AT_EMPTY_PATH on fd");
    TEST_ASSERT((sx.stx_mode & S_IFMT) == S_IFREG, "stx_mode regular via AT_EMPTY_PATH");
    TEST_ASSERT(sx.stx_size == TEST_CONTENT_LEN, "size via AT_EMPTY_PATH on fd");
}

static void test_at_empty_path_cwd(void) {
    // With dirfd==AT_FDCWD and an empty path + AT_EMPTY_PATH, operate on cwd.
    struct statx sx;
    expect_statx(AT_FDCWD, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx,
                 "statx AT_EMPTY_PATH on AT_FDCWD");
    TEST_ASSERT((sx.stx_mode & S_IFMT) == S_IFDIR, "stx_mode says directory for cwd");
}

static void test_enoent(void) {
    expect_statx_errno(AT_FDCWD, "/tmp/statx_does_not_exist_xyzzy", 0,
                       STATX_BASIC_STATS, ENOENT, "statx ENOENT on missing path");
}

static void test_enoent_empty_path_no_flag(void) {
    // Empty pathname without AT_EMPTY_PATH must fail with ENOENT — covers the
    // `FsPath::Cwd | FsPath::Fd(_)` fall-through arm in the shim.
    expect_statx_errno(AT_FDCWD, "", 0, STATX_BASIC_STATS, ENOENT,
                       "statx ENOENT on empty path without AT_EMPTY_PATH");
}

static void test_ebadf(void) {
    // dirfd = -99 with a relative path is invalid; Linux returns EBADF.
    expect_statx_errno(-99, "relpath", 0, STATX_BASIC_STATS, EBADF,
                       "statx EBADF on bad dirfd");
}

static void test_einval_reserved_mask(void) {
    expect_statx_errno(AT_FDCWD, TEST_PATH, 0, STATX__RESERVED, EINVAL,
                       "statx EINVAL on STATX__RESERVED mask bit");
}

static void test_einval_bad_flag(void) {
    // Pick a bit that is not in any documented AT_* / AT_STATX_* flag.
    const int bogus_flag = 0x40000000;
    expect_statx_errno(AT_FDCWD, TEST_PATH, bogus_flag, STATX_BASIC_STATS, EINVAL,
                       "statx EINVAL on bogus flag bit");
}

int main(void) {
    printf("statx tests starting...\n");
    seed_test_file();
    test_absolute_happy_path();
    test_at_empty_path_fd();
    test_at_empty_path_cwd();
    test_enoent();
    test_enoent_empty_path_no_flag();
    test_ebadf();
    test_einval_reserved_mask();
    test_einval_bad_flag();
    cleanup_test_file();
    printf("All statx tests passed.\n");
    return 0;
}
