// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

int main(void) {
    char path[] = "/tmp/lb_chmod_XXXXXX";
    struct stat st;

    TEST_ASSERT(mkdtemp(path) != NULL, "mkdtemp failed");
    mode_t old_umask = umask(0777);
    TEST_ASSERT(chmod(path, 0751) == 0, "chmod tmpdir failed");
    TEST_ASSERT(stat(path, &st) == 0, "stat after chmod failed");
    TEST_ASSERT((st.st_mode & 07777) == 0751,
                "chmod should set permissions without applying umask");

    TEST_ASSERT(syscall(SYS_fchmodat, -2, path, 0710) == 0,
                "fchmodat absolute path should ignore dirfd");
    TEST_ASSERT(stat(path, &st) == 0, "stat after absolute fchmodat failed");
    TEST_ASSERT((st.st_mode & 07777) == 0710,
                "fchmodat should set directory permissions");
    TEST_ASSERT(chdir(path) == 0, "chdir tmpdir failed");
    TEST_ASSERT(fchmodat(AT_FDCWD, ".", 0750, 0) == 0,
                "relative fchmodat should succeed");
    TEST_ASSERT(stat(".", &st) == 0, "stat after relative fchmodat failed");
    TEST_ASSERT((st.st_mode & 07777) == 0750,
                "relative fchmodat should set permissions");

    umask(old_umask);
    create_test_file("file", 0600);
    TEST_ASSERT(chmod("file", 0640) == 0, "chmod regular file failed");
    TEST_ASSERT(stat("file", &st) == 0, "stat after file chmod failed");
    TEST_ASSERT((st.st_mode & 07777) == 0640,
                "chmod should set regular file permissions");
    errno = 0;
    TEST_ASSERT(chmod("missing", 0700) == -1 && errno == ENOENT,
                "chmod missing path should fail with ENOENT");
    errno = 0;
    TEST_ASSERT(fchmodat(AT_FDCWD, "", 0700, 0) == -1 && errno == ENOENT,
                "fchmodat empty path should fail with ENOENT");

    TEST_ASSERT(unlink("file") == 0, "cleanup file failed");
    TEST_ASSERT(chdir("/") == 0, "leave tmpdir failed");
    TEST_ASSERT(rmdir(path) == 0, "cleanup tmpdir failed");
    puts("All chmod tests passed.");
    return 0;
}
