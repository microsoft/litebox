// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

int main(void) {
    char tmp[] = "/tmp/lb-dirfd-XXXXXX";
    TEST_ASSERT(mkdtemp(tmp) != NULL && chdir(tmp) == 0, "create working directory");
    TEST_ASSERT(mkdir("old", 0700) == 0 && mkdir("old/sub", 0700) == 0, "create subtree");
    int fd = open("old/sub", O_PATH | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open directory");
    create_test_file("old/sub/original", 0600);
    int file = openat(fd, "original", O_RDONLY);
    TEST_ASSERT(file >= 0, "open file through directory fd");

    TEST_ASSERT(rename("old", "new") == 0, "rename ancestor");
    TEST_ASSERT(mkdir("old", 0700) == 0 && mkdir("old/sub", 0700) == 0, "replace subtree");
    struct stat st;
    TEST_ASSERT(fstatat(fd, "original", &st, 0) == 0, "lookup follows renamed ancestor");
    const struct timespec times[2] = {{12345, 0}, {23456, 0}};
    TEST_ASSERT(utimensat(fd, "original", times, 0) == 0, "set times through moved ancestor");
    TEST_ASSERT(stat("new/sub/original", &st) == 0 && st.st_mtime == 23456,
                "timestamps changed on original inode");
    const struct timespec later[2] = {{34567, 0}, {45678, 0}};
    TEST_ASSERT(futimens(file, later) == 0 && stat("new/sub/original", &st) == 0 &&
                st.st_mtime == 45678 && close(file) == 0, "set times on file under renamed parent");
    TEST_ASSERT(mkdirat(fd, "created", 0700) == 0, "create through directory fd");
    TEST_ASSERT(stat("new/sub/created", &st) == 0, "creation lands in original directory");
    expect_errno(stat("old/sub/created", &st), ENOENT, "replacement is untouched");

    int replaced = open("old/sub", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(replaced >= 0, "open rename destination");
    TEST_ASSERT(symlinkat("../marker", fd, "link") == 0, "create relative symlink");
    create_test_file("old/marker", 0600);
    expect_errno(fstatat(fd, "link", &st, 0), ENOENT, "link does not resolve in replacement");
    TEST_ASSERT(rename("new/sub", "old/sub") == 0, "move open directory over replacement");
    TEST_ASSERT(fstatat(fd, "link", &st, 0) == 0, "relative link follows new parent");
    expect_errno(fstatat(replaced, "original", &st, 0), ENOENT, "replaced fd stays detached");
    struct stat expected;
    TEST_ASSERT(fstat(replaced, &expected) == 0 && fstatat(replaced, ".", &st, 0) == 0 &&
                st.st_ino == expected.st_ino, "dot still names the detached directory");
    TEST_ASSERT(stat("old", &expected) == 0 && fstatat(replaced, "..", &st, 0) == 0 &&
                st.st_ino == expected.st_ino, "dot-dot names the detached directory's parent");
    char dents[256];
    expect_errno(syscall(SYS_getdents64, replaced, dents, sizeof(dents)), ENOENT,
                 "cannot enumerate removed directory");
    TEST_ASSERT(close(replaced) == 0, "close detached directory");
    int dest = open("new", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dest >= 0 && renameat(fd, "link", dest, "moved-link") == 0,
                "rename between independent directory fds");
    TEST_ASSERT(unlinkat(dest, "moved-link", 0) == 0 && close(dest) == 0 &&
                unlink("old/marker") == 0, "cleanup link");
    TEST_ASSERT(unlinkat(fd, "original", 0) == 0 && unlinkat(fd, "created", AT_REMOVEDIR) == 0,
                "remove entries through moved directory fd");
    TEST_ASSERT(rmdir("old/sub") == 0 && mkdir("old/sub", 0700) == 0, "replace removed directory");
    expect_errno(mkdirat(fd, "absent", 0700), ENOENT, "cannot create in removed directory");
    TEST_ASSERT(close(fd) == 0 && rmdir("old/sub") == 0 && rmdir("old") == 0 &&
                rmdir("new") == 0 && chdir("/") == 0 && rmdir(tmp) == 0, "cleanup");
    puts("All directory fd rename tests passed.");
    return 0;
}
