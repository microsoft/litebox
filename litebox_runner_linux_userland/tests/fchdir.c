// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// `fchdir` and the `*at` syscalls resolve relative paths against an open directory.

#include "helpers.h"

#include <fcntl.h>
#include <sys/stat.h>

#define TEST_DIR "/tmp/lb_fchdir"

static char test_dir_cwd[4096];

static void expect_cwd(const char *expected, const char *msg) {
    char cwd[4096];
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd failed");
    TEST_ASSERT(strcmp(cwd, expected) == 0, msg);
}

static void create_file(int dirfd, const char *name) {
    int fd = openat(dirfd, name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    TEST_ASSERT(fd >= 0, "openat O_CREAT relative to dirfd failed");
    TEST_ASSERT(close(fd) == 0, "close failed");
}

static void test_at_syscalls(int dirfd) {
    struct stat st;
    char buf[64];

    // The CWD is `/`, so only `dirfd` can resolve these paths.
    create_file(dirfd, "file");
    TEST_ASSERT(stat(TEST_DIR "/file", &st) == 0 && S_ISREG(st.st_mode),
                "openat should create the file in dirfd");
    TEST_ASSERT(fstatat(dirfd, "file", &st, 0) == 0 && S_ISREG(st.st_mode),
                "fstatat relative to dirfd failed");
    TEST_ASSERT(faccessat(dirfd, "file", R_OK, 0) == 0,
                "faccessat relative to dirfd failed");
    TEST_ASSERT(fchmodat(dirfd, "file", 0640, 0) == 0,
                "fchmodat relative to dirfd failed");
    TEST_ASSERT(stat(TEST_DIR "/file", &st) == 0 && (st.st_mode & 0777) == 0640,
                "fchmodat should change the file in dirfd");

    TEST_ASSERT(mkdirat(dirfd, "sub", 0700) == 0, "mkdirat relative to dirfd failed");
    TEST_ASSERT(stat(TEST_DIR "/sub", &st) == 0 && S_ISDIR(st.st_mode),
                "mkdirat should create the directory in dirfd");
    TEST_ASSERT(symlinkat("file", dirfd, "sub/../link") == 0,
                "symlinkat relative to dirfd failed");
    ssize_t len = readlinkat(dirfd, "link", buf, sizeof(buf));
    TEST_ASSERT(len == 4 && memcmp(buf, "file", 4) == 0, "readlinkat relative to dirfd failed");
    TEST_ASSERT(renameat(dirfd, "link", dirfd, "sub/link") == 0,
                "renameat relative to dirfd failed");
    TEST_ASSERT(lstat(TEST_DIR "/sub/link", &st) == 0 && S_ISLNK(st.st_mode),
                "renameat should move the link within dirfd");
    TEST_ASSERT(unlinkat(dirfd, "sub/link", 0) == 0, "unlinkat relative to dirfd failed");
    TEST_ASSERT(unlinkat(dirfd, "sub", AT_REMOVEDIR) == 0,
                "unlinkat AT_REMOVEDIR relative to dirfd failed");
    expect_errno(stat(TEST_DIR "/sub", &st), ENOENT, "unlinkat should remove the directory");
}

static void test_at_syscall_errors(int dirfd) {
    struct stat st;
    int file_fd = openat(dirfd, "file", O_RDONLY);
    TEST_ASSERT(file_fd >= 0, "openat file failed");
    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe failed");
    int closed_fd = dup(file_fd);
    TEST_ASSERT(closed_fd >= 0 && close(closed_fd) == 0, "dup and close failed");

    // A relative path needs `dirfd` to be an open directory.
    expect_errno(openat(file_fd, "x", O_RDONLY), ENOTDIR, "openat relative to a file");
    expect_errno(openat(pipe_fds[0], "x", O_RDONLY), ENOTDIR, "openat relative to a pipe");
    expect_errno(openat(closed_fd, "x", O_RDONLY), EBADF, "openat relative to a closed fd");
    expect_errno(openat(-5, "x", O_RDONLY), EBADF, "openat relative to a negative fd");
    expect_errno(fstatat(file_fd, "x", &st, 0), ENOTDIR, "fstatat relative to a file");
    expect_errno(mkdirat(closed_fd, "x", 0700), EBADF, "mkdirat relative to a closed fd");

    // An absolute path ignores `dirfd` entirely.
    TEST_ASSERT(fstatat(file_fd, TEST_DIR "/file", &st, 0) == 0,
                "fstatat with an absolute path should ignore dirfd");

    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(file_fd);
}

static void test_fchdir(int dirfd) {
    int file_fd = openat(dirfd, "file", O_RDONLY);
    TEST_ASSERT(file_fd >= 0, "openat file failed");
    TEST_ASSERT(mkdirat(dirfd, "sub", 0700) == 0, "mkdirat sub failed");
    int sub_fd = openat(dirfd, "sub", O_PATH);
    TEST_ASSERT(sub_fd >= 0, "openat O_PATH sub failed");
    char sub_cwd[4096 + 8];
    snprintf(sub_cwd, sizeof(sub_cwd), "%s/sub", test_dir_cwd);

    TEST_ASSERT(fchdir(dirfd) == 0, "fchdir to directory failed");
    expect_cwd(test_dir_cwd, "fchdir should change to the directory");
    int fd = open("file", O_RDONLY);
    TEST_ASSERT(fd >= 0, "relative open after fchdir failed");
    close(fd);

    TEST_ASSERT(fchdir(sub_fd) == 0, "fchdir to O_PATH directory failed");
    expect_cwd(sub_cwd, "fchdir should change to the O_PATH directory");

    // Failures leave the CWD alone.
    expect_errno(fchdir(file_fd), ENOTDIR, "fchdir to a file");
    expect_errno(fchdir(-1), EBADF, "fchdir to a negative fd");
    close(file_fd);
    expect_errno(fchdir(file_fd), EBADF, "fchdir to a closed fd");
    expect_cwd(sub_cwd, "failed fchdir should leave the CWD alone");

    TEST_ASSERT(chdir("/") == 0, "chdir / failed");
    close(sub_fd);
    TEST_ASSERT(unlinkat(dirfd, "sub", AT_REMOVEDIR) == 0, "cleanup sub failed");
}

// `fchdir` needs search permission on the directory as of the call, not as of the open.
static void test_fchdir_search_permission(int dirfd) {
    const char *path = TEST_DIR "/noexec";
    char cwd[4096];

    // Root can search any directory.
    if (geteuid() == 0) {
        return;
    }
    TEST_ASSERT(mkdirat(dirfd, "noexec", 0700) == 0, "mkdirat noexec failed");
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd failed");
    int flags[] = {O_RDONLY | O_DIRECTORY, O_PATH};
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        TEST_ASSERT(chmod(path, 0700) == 0, "chmod 0700 failed");
        int fd = open(path, flags[i]);
        TEST_ASSERT(fd >= 0, "open noexec failed");
        TEST_ASSERT(chmod(path, 0600) == 0, "chmod 0600 failed");

        errno = 0;
        expect_errno(fchdir(fd), EACCES, "fchdir without search permission");
        expect_cwd(cwd, "failed fchdir should leave the CWD alone");
        close(fd);
    }
    TEST_ASSERT(rmdir(path) == 0, "cleanup noexec failed");
}

int main(void) {
    unlink(TEST_DIR "/file");
    unlink(TEST_DIR "/sub/link");
    rmdir(TEST_DIR "/sub");
    rmdir(TEST_DIR "/noexec");
    rmdir(TEST_DIR);
    TEST_ASSERT(mkdir(TEST_DIR, 0700) == 0, "mkdir test directory failed");

    // The CWD `chdir` reports for the test directory, which `fchdir` must match.
    TEST_ASSERT(chdir(TEST_DIR) == 0, "chdir test directory failed");
    TEST_ASSERT(getcwd(test_dir_cwd, sizeof(test_dir_cwd)) != NULL, "getcwd failed");
    TEST_ASSERT(chdir("/") == 0, "chdir / failed");

    int dirfd = open(TEST_DIR, O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dirfd >= 0, "open test directory failed");

    printf("===== fchdir and dirfd tests =====\n");
    test_at_syscalls(dirfd);
    test_at_syscall_errors(dirfd);
    test_fchdir(dirfd);
    test_fchdir_search_permission(dirfd);

    close(dirfd);
    TEST_ASSERT(unlink(TEST_DIR "/file") == 0, "cleanup file failed");
    TEST_ASSERT(rmdir(TEST_DIR) == 0, "cleanup test directory failed");
    printf("All fchdir and dirfd tests passed.\n");
    return 0;
}
