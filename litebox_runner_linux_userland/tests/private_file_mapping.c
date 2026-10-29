// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that MAP_PRIVATE file mappings behave as on Linux, which only mapping the file's pages
// copy-on-write, rather than copying the file, achieves: pages not yet written see later writes
// to the file, accessing past the end of the file raises SIGBUS, and MADV_DONTNEED shows the
// file again. Writes stay private to the mapping, and to each process after fork, which still
// share the pages neither wrote.
//
// Run with this program's own path as the argument, to check the same for a file of the initial
// file system, which never changes.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH "/tmp/private-file-mapping"

static int failures;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("FAIL line %d: %s (errno=%d)\n", __LINE__, #cond, errno);           \
            failures++;                                                                \
        }                                                                              \
    } while (0)

static sigjmp_buf fault_jump;
static volatile sig_atomic_t fault_signal;

static void on_fault(int signal) {
    fault_signal = signal;
    siglongjmp(fault_jump, 1);
}

// Returns whether reading `address` raises SIGBUS.
static int raises_bus(const char *address) {
    fault_signal = 0;
    if (sigsetjmp(fault_jump, 1) == 0) {
        (void)*(volatile const char *)address;
        return 0;
    }
    return fault_signal == SIGBUS;
}

static char read_byte(int fd, off_t offset) {
    char byte = 0;
    CHECK(pread(fd, &byte, 1, offset) == 1);
    return byte;
}

// Checks a file of the initial file system, which a private mapping maps without copying.
static void check_initial_file(const char *path, long page) {
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    off_t size = lseek(fd, 0, SEEK_END);
    CHECK(size > 0);
    long pages = (size + page - 1) / page;
    char *first = mmap(NULL, (pages + 1) * page, PROT_READ, MAP_PRIVATE, fd, 0);
    char *second = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(first != MAP_FAILED && second != MAP_FAILED);
    if (first == MAP_FAILED || second == MAP_FAILED) {
        close(fd);
        return;
    }
    CHECK(memcmp(first, "\177ELF", 4) == 0);
    // A file open only for reading may still be written through a private mapping.
    CHECK(mprotect(first, page, PROT_READ | PROT_WRITE) == 0);
    first[0] = 'X';
    CHECK(second[0] == '\177');
    CHECK(read_byte(fd, 0) == '\177');
    CHECK(madvise(first, page, MADV_DONTNEED) == 0);
    CHECK(first[0] == '\177');
    // The page past the end of the file is not part of it.
    CHECK(raises_bus(first + pages * page));
    munmap(first, (pages + 1) * page);
    munmap(second, page);
    close(fd);
}

int main(int argc, char **argv) {
    long page = sysconf(_SC_PAGESIZE);
    struct sigaction action = {0};
    action.sa_handler = on_fault;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGBUS, &action, NULL) == 0);
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);

    int fd = open(PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    char contents[2 * 4096];
    memset(contents, 'a', sizeof(contents));
    CHECK(page == 4096);
    CHECK(write(fd, contents, sizeof(contents)) == (ssize_t)sizeof(contents));

    // Three pages of a two-page file.
    char *mapping = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    char *other = mmap(NULL, 2 * page, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(mapping != MAP_FAILED && other != MAP_FAILED);
    if (mapping == MAP_FAILED || other == MAP_FAILED) {
        printf("private-file failures=%d\n", failures);
        return 1;
    }
    CHECK(mapping[0] == 'a' && mapping[page] == 'a');

    // A private write is the mapping's own.
    mapping[0] = 'P';
    CHECK(other[0] == 'a');
    CHECK(read_byte(fd, 0) == 'a');

    // Writes to the file show in the pages no mapping wrote, but not in written ones.
    CHECK(pwrite(fd, "W", 1, page) == 1);
    CHECK(pwrite(fd, "W", 1, 1) == 1);
    CHECK(mapping[page] == 'W' && other[page] == 'W');
    CHECK(mapping[1] == 'a' && other[1] == 'W');

    // Accessing past the end of the file raises SIGBUS.
    CHECK(raises_bus(mapping + 2 * page));

    // A forked child starts with the parent's private pages, and each process's writes stay its
    // own, while both keep seeing the file in the pages neither wrote.
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        int ok = mapping[0] == 'P' && mapping[page] == 'W';
        mapping[0] = 'C';
        ok = ok && pwrite(fd, "F", 1, page + 1) == 1;
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(mapping[0] == 'P');
    CHECK(mapping[page + 1] == 'F');

    // MADV_DONTNEED drops the written copies, so the file shows again.
    CHECK(madvise(mapping, page, MADV_DONTNEED) == 0);
    CHECK(mapping[0] == 'a' && mapping[1] == 'W');

    munmap(mapping, 3 * page);
    munmap(other, 2 * page);
    close(fd);
    unlink(PATH);

    if (argc > 1) {
        check_initial_file(argv[1], page);
    }
    printf("private-file failures=%d\n", failures);
    return failures != 0;
}
