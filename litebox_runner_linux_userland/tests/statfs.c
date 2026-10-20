// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <sys/vfs.h>

int main(void) {
    char path[] = "/tmp/lb_statfs_XXXXXX";
    struct statfs st;

    TEST_ASSERT(mkdtemp(path) != NULL, "mkdtemp failed");
    TEST_ASSERT(statfs(path, &st) == 0, "statfs tmpdir failed");
    TEST_ASSERT(st.f_bsize > 0 && st.f_blocks > 0 && st.f_namelen > 0,
                "statfs should report plausible sizes");

    int fd = open(path, O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open tmpdir failed");
    TEST_ASSERT(fstatfs(fd, &st) == 0, "fstatfs tmpdir failed");
    TEST_ASSERT(close(fd) == 0, "close failed");

    errno = 0;
    TEST_ASSERT(statfs("/tmp/lb_statfs_missing", &st) == -1 && errno == ENOENT,
                "statfs missing path should fail with ENOENT");
    errno = 0;
    TEST_ASSERT(fstatfs(fd, &st) == -1 && errno == EBADF,
                "fstatfs closed fd should fail with EBADF");

    TEST_ASSERT(rmdir(path) == 0, "cleanup tmpdir failed");
    puts("All statfs tests passed.");
    return 0;
}
