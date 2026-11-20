// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

// Once removed, a held directory must not bring back its removed entries, even where (as for
// LiteBox's read-only lower layer) they still exist beneath the removal.
// Usage: held_lower_dir directory, which holds only the regular file `entry`.
int main(int argc, char **argv) {
    TEST_ASSERT(argc == 2, "usage: held_lower_dir directory");
    int fd = open(argv[1], O_PATH | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open directory");
    struct stat st;
    TEST_ASSERT(fstatat(fd, "entry", &st, 0) == 0 && S_ISREG(st.st_mode), "entry exists");
    TEST_ASSERT(unlinkat(fd, "entry", 0) == 0, "unlink entry through the fd");
    expect_errno(fstatat(fd, "entry", &st, 0), ENOENT, "unlinked entry is gone");
    TEST_ASSERT(rmdir(argv[1]) == 0, "remove directory");
    expect_errno(fstatat(fd, "entry", &st, 0), ENOENT, "removed directory stays empty");
    TEST_ASSERT(fstatat(fd, ".", &st, 0) == 0 && S_ISDIR(st.st_mode), "held directory is live");
    expect_errno(openat(fd, "new", O_CREAT | O_WRONLY, 0600), ENOENT, "no creation in it");
    TEST_ASSERT(close(fd) == 0, "close directory");
    puts("held lower directory ok");
    return 0;
}
