// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <pthread.h>

static void *enter_parent(void *unused) {
    (void)unused;
    TEST_ASSERT(chdir("..") == 0, "thread leaves removed cwd via parent");
    return NULL;
}

int main(void) {
    char tmp[] = "/tmp/lb-cwd-XXXXXX";
    TEST_ASSERT(mkdtemp(tmp) && chdir(tmp) == 0, "enter temporary directory");
    int root = open(".", O_PATH | O_DIRECTORY);
    TEST_ASSERT(root >= 0 && mkdir("a", 0700) == 0 && mkdir("a/sub", 0700) == 0, "setup");
    int sub = open("a/sub", O_PATH | O_DIRECTORY);
    TEST_ASSERT(sub >= 0 && chdir("a/sub") == 0, "enter subdirectory");
    TEST_ASSERT(renameat(root, "a", root, "b") == 0 && mkdirat(root, "a", 0700) == 0 &&
                mkdirat(root, "a/sub", 0700) == 0, "replace ancestor");
    char cwd[4096], expect[4096];
    snprintf(expect, sizeof(expect), "%s/b/sub", tmp);
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, expect), "getcwd after rename");
    TEST_ASSERT(mkdir("created", 0700) == 0 && unlinkat(root, "b/sub/created", AT_REMOVEDIR) == 0,
                "relative creation targets original cwd");
    TEST_ASSERT(symlink("../..", "up") == 0 && chdir("up") == 0,
                "follow relative symlink from renamed cwd");
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, tmp), "symlink reaches real ancestor");
    TEST_ASSERT(unlinkat(root, "b/sub/up", 0) == 0, "remove relative symlink");
    TEST_ASSERT(fchdir(root) == 0 && fchdir(sub) == 0, "enter renamed fd");
    TEST_ASSERT(unlinkat(root, "b/sub", AT_REMOVEDIR) == 0, "remove cwd");
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
    puts("All cwd rename tests passed.");
    return 0;
}
