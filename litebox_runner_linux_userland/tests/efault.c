// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define INVALID ((void *)0x10000)

static void expect_efault(ssize_t r, const char *operation) {
    if (r >= 0) {
        fprintf(stderr, "%s with an invalid address succeeded unexpectedly\n", operation);
        abort();
    }
    if (errno != EFAULT) {
        perror(operation);
        abort();
    }
}

static int lowest_free_fd(void) {
    int fd = dup(STDOUT_FILENO);
    if (fd < 0 || close(fd) != 0) {
        perror("dup");
        abort();
    }
    return fd;
}

// Like Linux, a descriptor pair that cannot be stored is not installed.
static void expect_pair_efault(int fds[2]) {
    int lowest = lowest_free_fd();
    expect_efault(pipe(fds), "pipe");
    if (lowest_free_fd() != lowest) {
        fprintf(stderr, "pipe leaked a descriptor\n");
        abort();
    }
    expect_efault(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), "socketpair");
    if (lowest_free_fd() != lowest) {
        fprintf(stderr, "socketpair leaked a descriptor\n");
        abort();
    }
}

static void test_descriptor_pairs(void) {
    expect_pair_efault(INVALID);

    // Only the second descriptor's slot faults.
    long page = sysconf(_SC_PAGESIZE);
    char *pages = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED || mprotect(pages + page, page, PROT_NONE) != 0) {
        perror("mmap");
        abort();
    }
    expect_pair_efault((int *)(pages + page) - 1);
    munmap(pages, 2 * page);
}

int main() {
    expect_efault(write(STDOUT_FILENO, INVALID, 1), "write to stdout");
    test_descriptor_pairs();

    const char *path = "/tmp/test_efault.bin";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    if (write(fd, "abcd", 4) != 4) {
        perror("write");
        return 1;
    }
    expect_efault(write(fd, INVALID, 4), "file write");
    expect_efault(pread(fd, INVALID, 4, 0), "file pread");
    struct stat status;
    if (fstat(fd, &status) != 0 || status.st_size != 4) {
        fprintf(stderr, "a faulting write changed the file\n");
        return 1;
    }
    char contents[4];
    if (pread(fd, contents, sizeof(contents), 0) != 4 || contents[0] != 'a' ||
        contents[3] != 'd') {
        fprintf(stderr, "the file lost its contents\n");
        return 1;
    }
    close(fd);
    unlink(path);
    return 0;
}
