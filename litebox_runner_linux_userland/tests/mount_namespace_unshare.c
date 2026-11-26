// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks what `unshare -m` does: `unshare(CLONE_NEWNS)`, then making every mount private.

#include "helpers.h"
#include <sys/mount.h>

int main(int argc, char **argv) {
    TEST_ASSERT(argc == 2 && (geteuid() == 0) == (strcmp(argv[1], "mount_unshare_root") == 0),
                "expected guest identity");
    if (geteuid() != 0) {
        TEST_ASSERT(unshare(CLONE_NEWNS) == -1 && errno == EPERM,
                    "namespace creation requires guest root");
        TEST_ASSERT(unshare(CLONE_NEWNS | CLONE_FS) == -1 && errno == EPERM,
                    "a mount namespace implies CLONE_FS");
        TEST_ASSERT(mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1 && errno == EPERM,
                    "propagation changes require guest root");
        TEST_ASSERT(mount("none", "/", NULL, MS_REC | MS_PRIVATE, (void *)1) == -1 &&
                        errno == EFAULT,
                    "mount data is read before permission checks");
        puts("mount namespace unshare ok");
        return 0;
    }

    char *tmp = mkdtemp(test_path("mount-unshare-XXXXXX"));
    TEST_ASSERT(tmp != NULL && chdir(tmp) == 0, "enter test directory");
    TEST_ASSERT(mkdir("target", 0700) == 0, "make mountpoint");
    int old = open("target/old", O_CREAT | O_RDWR, 0600);
    TEST_ASSERT(old >= 0, "open file before unshare");
    pid_t child = fork();
    if (child == 0) {
        TEST_ASSERT(unshare(CLONE_NEWNS) == 0, "unshare the mount namespace");
        TEST_ASSERT(mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "make mounts private");
        TEST_ASSERT(mount("none", "/", NULL, MS_PRIVATE | MS_NOSUID, NULL) == -1 && errno == EINVAL,
                    "a propagation change takes no other flags");
        TEST_ASSERT(mount(NULL, "target", "tmpfs", 0, NULL) == 0, "mount privately");
        TEST_ASSERT(access("target/old", F_OK) == -1 && errno == ENOENT, "cover old file");
        TEST_ASSERT(pwrite(old, "x", 1, 0) == 1, "write covered file opened before unshare");
        create_test_file("target/new", 0600);
        _exit(0);
    }
    int status;
    TEST_ASSERT(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0, "child completed");
    TEST_ASSERT(access("target/new", F_OK) == -1 && errno == ENOENT, "child mount is private");
    char byte = 0;
    TEST_ASSERT(pread(old, &byte, 1, 0) == 1 && byte == 'x', "file contents are shared");
    TEST_ASSERT(close(old) == 0, "close original file");
    puts("mount namespace unshare ok");
    return 0;
}
