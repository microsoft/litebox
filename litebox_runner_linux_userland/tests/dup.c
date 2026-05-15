// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: fd-duplication errno behavior around RLIMIT_NOFILE.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg)                                                \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d: %s)\n",       \
                    __func__, __LINE__, msg, errno, strerror(errno));         \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static int set_nofile_soft_limit(rlim_t soft_limit) {
    struct rlimit old_limit;
    TEST_ASSERT(getrlimit(RLIMIT_NOFILE, &old_limit) == 0, "getrlimit failed");
    TEST_ASSERT(old_limit.rlim_max == RLIM_INFINITY || old_limit.rlim_max >= soft_limit,
                "hard RLIMIT_NOFILE is too low for test");

    struct rlimit new_limit = old_limit;
    new_limit.rlim_cur = soft_limit;
    TEST_ASSERT(setrlimit(RLIMIT_NOFILE, &new_limit) == 0, "setrlimit failed");
    return 0;
}

int main(void) {
    const rlim_t soft_limit = 16;
    if (set_nofile_soft_limit(soft_limit) != 0) {
        return 1;
    }

    int valid_fd = open("/dev/null", O_RDONLY);
    TEST_ASSERT(valid_fd >= 0, "open /dev/null failed");
    int over_limit_fd = (int)soft_limit + 1;

    errno = 0;
    int ret = fcntl(valid_fd, F_DUPFD, (int)soft_limit);
    TEST_ASSERT(ret == -1 && errno == EINVAL,
                "valid fd with min_fd >= RLIMIT_NOFILE should fail with EINVAL");

    errno = 0;
    ret = dup2(valid_fd, over_limit_fd);
    TEST_ASSERT(ret == -1 && errno == EBADF,
                "dup2 with target fd > RLIMIT_NOFILE should fail with EBADF");

    errno = 0;
    ret = dup3(valid_fd, over_limit_fd, O_CLOEXEC);
    TEST_ASSERT(ret == -1 && errno == EBADF,
                "dup3 with target fd > RLIMIT_NOFILE should fail with EBADF");

    int bad_fd = valid_fd;
    TEST_ASSERT(close(valid_fd) == 0, "close valid_fd failed");

    errno = 0;
    ret = fcntl(bad_fd, F_DUPFD, (int)soft_limit);
    TEST_ASSERT(ret == -1 && errno == EBADF,
                "bad fd with min_fd >= RLIMIT_NOFILE should fail with EBADF");

    errno = 0;
    ret = dup2(bad_fd, over_limit_fd);
    TEST_ASSERT(ret == -1 && errno == EBADF,
                "dup2 with bad fd and target fd > RLIMIT_NOFILE should fail with EBADF");

    errno = 0;
    ret = dup3(bad_fd, over_limit_fd, O_CLOEXEC);
    TEST_ASSERT(ret == -1 && errno == EBADF,
                "dup3 with bad fd and target fd > RLIMIT_NOFILE should fail with EBADF");

    printf("fd duplication RLIMIT_NOFILE errno ordering: PASS\n");
    return 0;
}
