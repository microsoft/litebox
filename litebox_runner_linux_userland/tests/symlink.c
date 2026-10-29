// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

int main(void) {
    char path[] = "/tmp/lb_symlink_XXXXXX";
    char absolute[4096], target[64];
    struct stat file_st, link_st;

    TEST_ASSERT(mkdtemp(path) != NULL, "mkdtemp failed");
    TEST_ASSERT(chdir(path) == 0, "chdir tmpdir failed");
    create_test_file("file", 0600);
    TEST_ASSERT(stat("file", &file_st) == 0, "stat target file failed");

    mode_t old_umask = umask(0777);
    TEST_ASSERT(symlink("./file", "relative") == 0, "symlink relative target failed");
    TEST_ASSERT(readlink("relative", target, sizeof(target)) == 6 &&
                    memcmp(target, "./file", 6) == 0,
                "readlink should preserve relative target verbatim");
    TEST_ASSERT(lstat("relative", &link_st) == 0 && S_ISLNK(link_st.st_mode),
                "lstat should describe the symlink");
    TEST_ASSERT(link_st.st_size == 6 && (link_st.st_mode & 0777) == 0777,
                "symlink should store target length and ignore umask");
    TEST_ASSERT(stat("relative", &link_st) == 0 &&
                    link_st.st_dev == file_st.st_dev && link_st.st_ino == file_st.st_ino,
                "stat should follow the symlink to its target");

    snprintf(absolute, sizeof(absolute), "%s/absolute", path);
    TEST_ASSERT(symlinkat(path, -2, absolute) == 0,
                "symlinkat absolute linkpath should ignore invalid dirfd");
    TEST_ASSERT(stat("absolute", &link_st) == 0 && S_ISDIR(link_st.st_mode),
                "absolute target should resolve from the root");

    const char *missing = "missing//target";
    TEST_ASSERT(symlinkat(missing, AT_FDCWD, "dangling") == 0,
                "symlinkat should allow a dangling target");
    TEST_ASSERT(readlink("dangling", target, sizeof(target)) == (ssize_t)strlen(missing) &&
                    memcmp(target, missing, strlen(missing)) == 0,
                "readlink should preserve dangling target verbatim");
    errno = 0;
    TEST_ASSERT(stat("dangling", &link_st) == -1 && errno == ENOENT,
                "stat dangling symlink should fail with ENOENT");
    errno = 0;
    TEST_ASSERT(symlink("replacement", "dangling") == -1 && errno == EEXIST,
                "symlink should not replace a dangling link");
    errno = 0;
    TEST_ASSERT(symlink("", "empty") == -1 && errno == ENOENT,
                "empty target should fail with ENOENT");

    umask(old_umask);
    TEST_ASSERT(unlink("relative") == 0, "unlink relative symlink failed");
    TEST_ASSERT(stat("file", &file_st) == 0, "unlink symlink should preserve its target");
    TEST_ASSERT(unlink("absolute") == 0, "unlink absolute symlink failed");
    TEST_ASSERT(unlink("dangling") == 0, "unlink dangling symlink failed");
    TEST_ASSERT(unlink("file") == 0, "cleanup target file failed");
    TEST_ASSERT(chdir("/") == 0, "leave tmpdir failed");
    TEST_ASSERT(rmdir(path) == 0, "cleanup tmpdir failed");
    puts("All symlink tests passed.");
    return 0;
}
