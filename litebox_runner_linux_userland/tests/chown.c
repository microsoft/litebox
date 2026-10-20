// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

int main(void) {
    char path[] = "/tmp/lb_chown_XXXXXX";
    struct stat before, after;

    TEST_ASSERT(mkdtemp(path) != NULL, "mkdtemp failed");
    TEST_ASSERT(stat(path, &before) == 0, "stat tmpdir failed");
    TEST_ASSERT(chown(path, (uid_t)-1, getegid()) == 0,
                "chown(tmpdir, -1, egid) should succeed");
    TEST_ASSERT(stat(path, &after) == 0, "stat after chown failed");
    TEST_ASSERT(after.st_uid == before.st_uid && after.st_gid == getegid(),
                "chown should preserve uid and set gid");

    TEST_ASSERT(syscall(SYS_fchownat, -2, path, geteuid(), (gid_t)-1, 0) == 0,
                "fchownat absolute path should ignore dirfd");
    TEST_ASSERT(chdir(path) == 0, "chdir tmpdir failed");
    TEST_ASSERT(fchownat(AT_FDCWD, ".", (uid_t)-1, (gid_t)-1, 0) == 0,
                "relative fchownat should preserve ownership");
    TEST_ASSERT(stat(".", &after) == 0, "stat after fchownat failed");
    TEST_ASSERT(after.st_uid == geteuid() && after.st_gid == getegid(),
                "fchownat should preserve uid and gid");

    errno = 0;
    TEST_ASSERT(chown("missing", (uid_t)-1, getegid()) == -1 && errno == ENOENT,
                "chown missing path should fail with ENOENT");
    TEST_ASSERT(chdir("/") == 0, "leave tmpdir failed");
    TEST_ASSERT(rmdir(path) == 0, "cleanup tmpdir failed");
    puts("All chown tests passed.");
    return 0;
}
