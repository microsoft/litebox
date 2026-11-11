// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <linux/stat.h>
#include <sys/mman.h>
#include <utime.h>

static void expect_times(const char *path, int nofollow,
                         const struct timespec expected[2]) {
    struct stat st;
    int result = nofollow ? lstat(path, &st) : stat(path, &st);
    TEST_ASSERT(result == 0, "read timestamps");
    TEST_ASSERT(st.st_atim.tv_sec == expected[0].tv_sec &&
                st.st_atim.tv_nsec == expected[0].tv_nsec, "access time matches");
    TEST_ASSERT(st.st_mtim.tv_sec == expected[1].tv_sec &&
                st.st_mtim.tv_nsec == expected[1].tv_nsec, "modify time matches");
}

int main(int argc, char **argv) {
    char temporary[] = "/tmp/lb_utimensat_XXXXXX";
    const char *directory = argc > 1 ? argv[1] : mkdtemp(temporary);
    // Only a host-backed directory has a clock; in-memory files ignore NOW.
    int now_updates = argc > 1;
    TEST_ASSERT(directory != NULL && chdir(directory) == 0, "enter test directory");
    int fd = open("file", O_CREAT | O_EXCL | O_RDWR, 0600);
    TEST_ASSERT(fd >= 0, "create file");

    struct timespec times[2] = {{123456789, 123456789}, {-1, 987654321}};
    TEST_ASSERT(utimensat(AT_FDCWD, "file", times, 0) == 0, "explicit utimensat");
    expect_times("file", 0, times);
    struct stat st;
    TEST_ASSERT(fstat(fd, &st) == 0 && st.st_mtim.tv_sec == -1 &&
                st.st_mtim.tv_nsec == 987654321, "fstat signed timestamp");
    struct statx sx;
    TEST_ASSERT(syscall(SYS_statx, AT_FDCWD, "file", 0, STATX_BASIC_STATS, &sx) == 0,
                "statx timestamp readback");
    TEST_ASSERT((sx.stx_mask & (STATX_ATIME | STATX_MTIME | STATX_CTIME)) ==
                (STATX_ATIME | STATX_MTIME | STATX_CTIME), "statx advertises timestamps");
    TEST_ASSERT(sx.stx_mtime.tv_sec == -1 && sx.stx_mtime.tv_nsec == 987654321,
                "statx signed timestamp");

    struct timespec update[2] = {{-99, UTIME_OMIT}, {-99, UTIME_NOW}};
    struct timespec before;
    TEST_ASSERT(clock_gettime(CLOCK_REALTIME, &before) == 0, "clock before NOW");
    TEST_ASSERT(utimensat(AT_FDCWD, "file", update, 0) == 0, "NOW and OMIT");
    TEST_ASSERT(fstat(fd, &st) == 0 && st.st_atim.tv_sec == times[0].tv_sec &&
                st.st_atim.tv_nsec == times[0].tv_nsec, "OMIT preserves access time");
    TEST_ASSERT(!now_updates || st.st_mtim.tv_sec >= before.tv_sec, "NOW updates modify time");
    TEST_ASSERT(utimensat(AT_FDCWD, "file", NULL, 0) == 0, "NULL times touch");
    TEST_ASSERT(fstat(fd, &st) == 0 && (!now_updates || (st.st_atim.tv_sec >= before.tv_sec &&
                st.st_mtim.tv_sec >= before.tv_sec)), "NULL times updates both fields");

    times[0] = (struct timespec){100, 111};
    times[1] = (struct timespec){200, 222};
    TEST_ASSERT(futimens(fd, times) == 0, "futimens NULL pathname");
    expect_times("file", 0, times);
    TEST_ASSERT(futimens(fd, NULL) == 0, "futimens NULL times");
    int path_fd = open("file", O_PATH);
    TEST_ASSERT(path_fd >= 0, "open path-only descriptor");
    TEST_ASSERT(syscall(SYS_utimensat, path_fd, "", times, AT_EMPTY_PATH) == 0,
                "AT_EMPTY_PATH accepts path-only descriptors");
    TEST_ASSERT(close(path_fd) == 0, "close path-only descriptor");
    int dir_fd = open(".", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dir_fd >= 0, "open directory descriptor");
    struct timespec relative[2] = {{150, 155}, {250, 255}};
    TEST_ASSERT(utimensat(dir_fd, "file", relative, 0) == 0, "dirfd-relative utimensat");
    expect_times("file", 0, relative);
    TEST_ASSERT(close(dir_fd) == 0, "close directory descriptor");
    TEST_ASSERT(utimensat(AT_FDCWD, "file", times, 0) == 0, "restore times");
    if (argc == 1) {
        TEST_ASSERT(symlink("file", "link") == 0, "create symlink");
    }
    struct timespec link_times[2] = {{300, 333}, {400, 444}};
    TEST_ASSERT(utimensat(AT_FDCWD, "link", link_times, AT_SYMLINK_NOFOLLOW) == 0,
                "set symlink times without following");
    expect_times("link", 1, link_times);
    expect_times("file", 0, times);
    TEST_ASSERT(utimensat(AT_FDCWD, "link", link_times, 0) == 0, "follow symlink");
    expect_times("file", 0, link_times);

    struct timespec omit[2] = {{-1, UTIME_OMIT}, {-1, UTIME_OMIT}};
    TEST_ASSERT(syscall(SYS_utimensat, -1, (void *)1, omit, 0) == 0,
                "both OMIT skips path and descriptor lookup");
    errno = 0;
    TEST_ASSERT(syscall(SYS_utimensat, -1, NULL, times, 0) == -1 && errno == EBADF,
                "invalid fd");
    errno = 0;
    TEST_ASSERT(syscall(SYS_utimensat, fd, NULL, times, AT_SYMLINK_NOFOLLOW) == -1 &&
                errno == EINVAL, "NULL path rejects flags");
    errno = 0;
    TEST_ASSERT(syscall(SYS_utimensat, AT_FDCWD, "file", (void *)1, 0) == -1 &&
                errno == EFAULT, "bad times pointer");
    errno = 0;
    TEST_ASSERT(syscall(SYS_utimensat, AT_FDCWD, (void *)1, times, 0) == -1 &&
                errno == EFAULT, "bad pathname pointer");
    long page_size = sysconf(_SC_PAGESIZE);
    TEST_ASSERT(page_size > 0, "read page size");
    char *pages = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(pages != MAP_FAILED, "map partial times buffer");
    TEST_ASSERT(mprotect(pages + page_size, (size_t)page_size, PROT_NONE) == 0,
                "protect second times entry");
    struct timespec *partial = (struct timespec *)(pages + page_size) - 1;
    *partial = (struct timespec){1, 1000000000};
    errno = 0;
    TEST_ASSERT(syscall(SYS_utimensat, AT_FDCWD, "file", partial, 0) == -1 && errno == EFAULT,
                "copy both times before checking nanoseconds");
#ifdef SYS_futimesat
    struct timeval *partial_micros = (struct timeval *)(pages + page_size) - 1;
    *partial_micros = (struct timeval){1, 1000000};
    errno = 0;
    TEST_ASSERT(syscall(SYS_futimesat, AT_FDCWD, "file", partial_micros) == -1 && errno == EFAULT,
                "copy both legacy times before checking microseconds");
#endif
    TEST_ASSERT(munmap(pages, (size_t)page_size * 2) == 0, "unmap times buffer");
    update[0] = (struct timespec){1, 1000000000};
    errno = 0;
    TEST_ASSERT(utimensat(AT_FDCWD, "file", update, 0) == -1 && errno == EINVAL,
                "invalid nanoseconds");
    errno = 0;
    TEST_ASSERT(utimensat(AT_FDCWD, "file", times, 0x40000000) == -1 && errno == EINVAL,
                "invalid flags");

#ifdef SYS_utime
    struct utimbuf seconds = {500, 600};
    TEST_ASSERT(syscall(SYS_utime, "file", &seconds) == 0, "legacy utime");
    times[0] = (struct timespec){500, 0};
    times[1] = (struct timespec){600, 0};
    expect_times("file", 0, times);
#endif
#ifdef SYS_utimes
    struct timeval micros[2] = {{700, 123456}, {800, 654321}};
    TEST_ASSERT(syscall(SYS_utimes, "file", micros) == 0, "legacy utimes");
    times[0] = (struct timespec){700, 123456000};
    times[1] = (struct timespec){800, 654321000};
    expect_times("file", 0, times);
    TEST_ASSERT(syscall(SYS_futimesat, fd, NULL, micros) == 0, "legacy futimesat fd");
    micros[0].tv_usec = 1000000;
    errno = 0;
    TEST_ASSERT(syscall(SYS_futimesat, AT_FDCWD, "file", micros) == -1 && errno == EINVAL,
                "invalid microseconds");
#endif

    // A future atime (after mtime and ctime) survives host relatime updates on reads, so the
    // host-side check still sees it if something on the host reads the file afterwards.
    times[0] = (struct timespec){4000000000, 123456789};
    times[1] = (struct timespec){987654321, 987654321};
    TEST_ASSERT(futimens(fd, times) == 0, "final host-visible timestamps");
    expect_times("file", 0, times);
    TEST_ASSERT(close(fd) == 0, "close file");
    if (argc == 1) {
        TEST_ASSERT(unlink("link") == 0 && unlink("file") == 0, "cleanup files");
        TEST_ASSERT(chdir("/") == 0 && rmdir(directory) == 0, "cleanup directory");
    }
    puts("utimensat ok");
    return 0;
}
