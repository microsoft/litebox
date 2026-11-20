// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <sys/un.h>

// Paths reach the filesystem as spelled: trailing slashes are enforced, and `..` applies after
// following a symlink, for both cwd- and dirfd-relative names and Unix socket addresses.
// Usage: exact_paths [base-directory], like `enter_test_dir`; needs symlinks.
int main(int argc, char **argv) {
    char tmp[4096];
    enter_test_dir(argc, argv, "lb-exact", tmp, sizeof(tmp));
    int dir = open(".", O_PATH | O_DIRECTORY);
    TEST_ASSERT(dir >= 0 && mkdir("d", 0700) == 0 && mkdir("d/sub", 0700) == 0, "setup");
    expect_errno(open("new/", O_CREAT | O_WRONLY, 0600), EISDIR, "cwd O_CREAT trailing slash");
    expect_errno(openat(dir, "new/", O_CREAT | O_WRONLY, 0600), EISDIR, "dirfd O_CREAT slash");
    struct stat st;
    expect_errno(stat("new", &st), ENOENT, "nothing created");
    expect_errno(symlink("t", "l/"), ENOENT, "symlink trailing slash missing");
    TEST_ASSERT(symlink("d/sub", "link") == 0, "link");
    expect_errno(symlinkat("t", dir, "link/"), EEXIST, "symlink trailing slash existing");
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX, .sun_path = "link/../s.sock"};
    TEST_ASSERT(bind(s, (struct sockaddr *)&a, sizeof(a)) == 0, "bind via link/..");
    TEST_ASSERT(stat("d/s.sock", &st) == 0, "socket lands in link target's parent");
    expect_errno(stat("s.sock", &st), ENOENT, "not lexically normalized");
    TEST_ASSERT(close(s) == 0 && unlink("d/s.sock") == 0 && unlink("link") == 0 &&
                rmdir("d/sub") == 0 && rmdir("d") == 0 && chdir("/") == 0 && rmdir(tmp) == 0,
                "cleanup");
    puts("All exact path tests passed.");
    return 0;
}
