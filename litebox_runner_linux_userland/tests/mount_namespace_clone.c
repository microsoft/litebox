// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <linux/sched.h>
#include <sys/mount.h>

static void wait_ok(pid_t pid) {
    int status;
    TEST_ASSERT(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0, "child completed");
}

int main(int argc, char **argv) {
    TEST_ASSERT(argc == 2 && (geteuid() == 0) == (strcmp(argv[1], "mount_ns_root") == 0),
                "expected guest identity");
    TEST_ASSERT(syscall(SYS_clone, CLONE_NEWNS | CLONE_FS | SIGCHLD, 0, 0, 0, 0) == -1 &&
                    errno == EINVAL, "a private mount namespace cannot share FS context");
    if (geteuid() != 0) {
        TEST_ASSERT(syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0) == -1 &&
                        errno == EPERM, "namespace creation requires guest root");
        puts("mount namespace clone ok");
        return 0;
    }

    char tmp[] = "/tmp/mount-clone-XXXXXX";
    TEST_ASSERT(mkdtemp(tmp) != NULL && chdir(tmp) == 0, "enter test directory");
    TEST_ASSERT(mkdir("target", 0700) == 0, "make mountpoint");
    int old = open("target/old", O_CREAT | O_RDWR, 0600);
    TEST_ASSERT(old >= 0, "open file before clone");

    for (int use_clone3 = 0; use_clone3 <= 1; ++use_clone3) {
        struct clone_args args = {.flags = CLONE_NEWNS, .exit_signal = SIGCHLD};
        pid_t child = use_clone3 ? syscall(SYS_clone3, &args, sizeof(args))
                                 : syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
        if (child == 0) {
            TEST_ASSERT(access("target/old", F_OK) == 0, "copy includes original directory");
            TEST_ASSERT(mount(NULL, "target", "tmpfs", 0, NULL) == 0, "mount privately");
            TEST_ASSERT(access("target/old", F_OK) == -1 && errno == ENOENT, "cover old file");
            TEST_ASSERT(pwrite(old, "x", 1, use_clone3) == 1, "write inherited covered file");
            TEST_ASSERT(mkdir("target/nested", 0700) == 0, "make nested mountpoint");
            pid_t grandchild = fork();
            if (grandchild == 0) {
                TEST_ASSERT(mount(NULL, "target/nested", "tmpfs", 0, NULL) == 0, "mount in ordinary fork");
                create_test_file("target/nested/new", 0600);
                _exit(0);
            }
            wait_ok(grandchild);
            TEST_ASSERT(access("target/nested/new", F_OK) == 0, "ordinary fork shares mount view");
            _exit(0);
        }
        wait_ok(child);
        TEST_ASSERT(access("target/nested", F_OK) == -1 && errno == ENOENT, "child mount is private");
        TEST_ASSERT(access("target/old", F_OK) == 0, "parent directory is not covered");
        char byte = 0;
        TEST_ASSERT(pread(old, &byte, 1, use_clone3) == 1 && byte == 'x', "file contents are shared");
    }
    TEST_ASSERT(close(old) == 0, "close original file");
    puts("mount namespace clone ok");
    return 0;
}
