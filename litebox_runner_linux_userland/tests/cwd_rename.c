// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <pthread.h>
#include <sys/un.h>

static void *enter_parent(void *unused) {
    (void)unused;
    TEST_ASSERT(chdir("..") == 0, "thread leaves removed cwd via parent");
    return NULL;
}

// Usage: cwd_rename [base-directory [no-symlinks]]. The working directory is created under
// `base-directory` (default `test_dir()`); `no-symlinks` skips the steps that create symlinks, for
// filesystems that cannot create them.
int main(int argc, char **argv) {
    char tmp[4096];
    int symlinks = enter_test_dir(argc, argv, "lb-cwd", tmp, sizeof(tmp));
    int root = open(".", O_PATH | O_DIRECTORY);
    TEST_ASSERT(root >= 0 && mkdir("a", 0700) == 0 && mkdir("a/sub", 0700) == 0, "setup");
    int sub = open("a/sub", O_PATH | O_DIRECTORY);
    TEST_ASSERT(sub >= 0 && chdir("a/sub") == 0, "enter subdirectory");
    TEST_ASSERT(renameat(root, "a", root, "b") == 0 && mkdirat(root, "a", 0700) == 0 &&
                mkdirat(root, "a/sub", 0700) == 0, "replace ancestor");
    char cwd[4096], expect[4096];
    snprintf(expect, sizeof(expect), "%s/b/sub", tmp);
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, expect), "getcwd after rename");
    struct stat cwd_st, sub_st;
    TEST_ASSERT(fstat(sub, &sub_st) == 0 && fstatat(AT_FDCWD, "", &cwd_st, AT_EMPTY_PATH) == 0 &&
                cwd_st.st_ino == sub_st.st_ino, "empty path names the renamed cwd");
    TEST_ASSERT(syscall(SYS_faccessat2, AT_FDCWD, "", X_OK, AT_EMPTY_PATH) == 0,
                "empty path access checks the renamed cwd");
    const struct timespec times[2] = {{1000, 0}, {2000, 0}};
    TEST_ASSERT(syscall(SYS_utimensat, AT_FDCWD, "", times, AT_EMPTY_PATH) == 0 &&
                fstat(sub, &sub_st) == 0 && sub_st.st_mtime == 2000,
                "empty path sets times on the renamed cwd");
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = "rel.sock"};
    TEST_ASSERT(server >= 0 && bind(server, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
                listen(server, 1) == 0, "bind a relative socket name");
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    int length = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/b/sub/rel.sock", tmp);
    TEST_ASSERT(length >= 0 && (size_t)length < sizeof(addr.sun_path), "socket path too long");
    TEST_ASSERT(client >= 0 && connect(client, (struct sockaddr *)&addr, sizeof(addr)) == 0,
                "relative socket name follows the renamed cwd");
    TEST_ASSERT(close(client) == 0 && close(server) == 0 &&
                unlinkat(root, "b/sub/rel.sock", 0) == 0, "remove socket");
    TEST_ASSERT(mkdir("created", 0700) == 0 && unlinkat(root, "b/sub/created", AT_REMOVEDIR) == 0,
                "relative creation targets original cwd");
    if (symlinks) {
        TEST_ASSERT(symlink("../..", "up") == 0 && chdir("up") == 0,
                    "follow relative symlink from renamed cwd");
        TEST_ASSERT(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, tmp),
                    "symlink reaches real ancestor");
        TEST_ASSERT(unlinkat(root, "b/sub/up", 0) == 0, "remove relative symlink");
    }
    TEST_ASSERT(fchdir(root) == 0 && fchdir(sub) == 0, "enter renamed fd");
    TEST_ASSERT(unlinkat(root, "b/sub", AT_REMOVEDIR) == 0, "remove cwd");
    char link[64], target[4096];
    TEST_ASSERT(fchdir(root) == 0 && fchdir(sub) == 0 && close(sub) == 0, "enter removed fd");
    expect_errno(syscall(SYS_getcwd, cwd, sizeof(cwd)), ENOENT, "removed cwd has no name");
    struct stat st;
    TEST_ASSERT(stat(".", &st) == 0, "removed cwd still denotes a directory");
    pthread_t thread;
    TEST_ASSERT(pthread_create(&thread, NULL, enter_parent, NULL) == 0 &&
                pthread_join(thread, NULL) == 0, "thread shares cwd with caller");
    snprintf(expect, sizeof(expect), "%s/b", tmp);
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, expect), "parent of removed cwd");
    TEST_ASSERT(unlinkat(root, "b", AT_REMOVEDIR) == 0 && chdir("..") == 0 &&
                getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, tmp), "leave removed parent");
    TEST_ASSERT(fchdir(root) == 0 && close(root) == 0 && rmdir("a/sub") == 0 &&
                rmdir("a") == 0 && chdir("/") == 0 && rmdir(tmp) == 0, "cleanup");
    char *dir = realpath(test_dir(), NULL);
    int top = dir ? open(dir, O_PATH | O_DIRECTORY) : -1;
    TEST_ASSERT(top >= 0, "open directory for its fd link");
    snprintf(link, sizeof(link), "proc/self/fd/%d", top);
    ssize_t target_length = readlink(link, target, sizeof(target) - 1);
    TEST_ASSERT(target_length == (ssize_t)strlen(dir) && !memcmp(target, dir, strlen(dir)),
                "relative fd link from root");
    free(dir);
    struct stat link_st, top_st;
    TEST_ASSERT(stat(link, &link_st) == 0 && fstat(top, &top_st) == 0 &&
                link_st.st_ino == top_st.st_ino && close(top) == 0, "relative fd stat from root");
    puts("All cwd rename tests passed.");
    return 0;
}
