// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that MAP_SHARED file mappings share pages: between mappings in one process, with
// read/write/ftruncate on the file, with a forked child, and with an unrelated process started
// through execve. Run with this program's own path as the argument to include the exec check;
// it reruns itself with "child" to act as that process.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH "/tmp/shared-file-mapping"
#define INCREMENTS 100000

struct shared {
    uint64_t counter;
    char parent[32];
    char child[32];
    char exec_child[32];
};

static int failures;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("FAIL line %d: %s (errno=%d)\n", __LINE__, #cond, errno);           \
            failures++;                                                                \
        }                                                                              \
    } while (0)

static void add(struct shared *shared) {
    for (int i = 0; i < INCREMENTS; i++) {
        __atomic_fetch_add(&shared->counter, 1, __ATOMIC_SEQ_CST);
    }
}

static int exec_child(void) {
    int fd = open(PATH, O_RDWR);
    if (fd < 0) {
        return 2;
    }
    struct shared *shared =
        mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared == MAP_FAILED) {
        return 3;
    }
    if (strcmp(shared->parent, "from-parent") != 0) {
        return 4;
    }
    strcpy(shared->exec_child, "from-exec-child");
    add(shared);
    return 0;
}

static sigjmp_buf bus_jump;

static void on_bus(int signal) {
    (void)signal;
    siglongjmp(bus_jump, 1);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 2 && strcmp(argv[1], "child") == 0) {
        return exec_child();
    }
    const char *self = argc >= 2 ? argv[1] : NULL;
    long page = sysconf(_SC_PAGESIZE);

    unlink(PATH);
    int fd = open(PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, 2 * page) == 0);
    struct shared *shared = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(shared != MAP_FAILED);
    if (shared == MAP_FAILED) {
        printf("shared-file failures=%d\n", failures);
        return 1;
    }
    char *bytes = (char *)shared;

    // Stores through the mapping are what reads see, and writes are what the mapping sees.
    strcpy(shared->parent, "from-parent");
    char buffer[32] = {0};
    CHECK(pread(fd, buffer, 12, offsetof(struct shared, parent)) == 12);
    CHECK(strcmp(buffer, "from-parent") == 0);
    CHECK(pwrite(fd, "written", 8, page) == 8);
    CHECK(memcmp(bytes + page, "written", 8) == 0);

    // Another mapping of the file shares the same pages.
    int read_only = open(PATH, O_RDONLY);
    CHECK(read_only >= 0);
    struct shared *reader = mmap(NULL, page, PROT_READ, MAP_SHARED, read_only, 0);
    CHECK(reader != MAP_FAILED);
    shared->counter = 123;
    CHECK(reader->counter == 123);
    CHECK(strcmp(reader->parent, "from-parent") == 0);

    // A file open only for reading can be mapped neither writable nor made writable later.
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, read_only, 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    errno = 0;
    CHECK(mprotect(reader, page, PROT_READ | PROT_WRITE) == -1);
    CHECK(errno == EACCES);

    // Stores to a private mapping of the file stay private.
    char *private = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(private != MAP_FAILED);
    CHECK(strcmp(private + offsetof(struct shared, parent), "from-parent") == 0);
    private[offsetof(struct shared, child)] = 'X';
    CHECK(shared->child[0] == 0);
    CHECK(munmap(private, page) == 0);

    CHECK(msync(shared, 2 * page, MS_SYNC) == 0);
    errno = 0;
    CHECK(msync(shared, page, MS_SYNC | MS_ASYNC) == -1);
    CHECK(errno == EINVAL);

    // A forked child shares the pages.
    shared->counter = 0;
    pid_t pid = fork();
    if (pid == 0) {
        strcpy(shared->child, "from-child");
        add(shared);
        // A mapping the child creates shares the pages too.
        struct shared *again =
            mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (again == MAP_FAILED || strcmp(again->parent, "from-parent") != 0) {
            _exit(1);
        }
        strcpy(again->child + 11, "+");
        _exit(0);
    }
    CHECK(pid > 0);
    add(shared);
    int status = -1;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(strcmp(shared->child, "from-child") == 0);
    CHECK(strcmp(shared->child + 11, "+") == 0);
    CHECK(shared->counter == 2 * INCREMENTS);

    // So does an unrelated process that maps the file itself.
    if (self != NULL) {
        pid = fork();
        if (pid == 0) {
            execl(self, self, "child", (char *)NULL);
            _exit(127);
        }
        CHECK(pid > 0);
        status = -1;
        CHECK(waitpid(pid, &status, 0) == pid);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(strcmp(shared->exec_child, "from-exec-child") == 0);
        CHECK(shared->counter == 3 * INCREMENTS);
    }

    // Truncation discards the pages past the new end, and growing the file again exposes
    // zeros.
    CHECK(ftruncate(fd, page) == 0);
    CHECK(ftruncate(fd, 2 * page) == 0);
    CHECK(bytes[page] == 0);
    CHECK(pwrite(fd, "again", 6, page) == 6);
    CHECK(strcmp(bytes + page, "again") == 0);

    // Accessing a mapped page past the end of the file raises SIGBUS.
    CHECK(ftruncate(fd, page) == 0);
    struct sigaction action = {0};
    action.sa_handler = on_bus;
    CHECK(sigaction(SIGBUS, &action, NULL) == 0);
    volatile int bus = 0;
    if (sigsetjmp(bus_jump, 1) == 0) {
        (void)*(volatile char *)(bytes + page);
    } else {
        bus = 1;
    }
    CHECK(bus == 1);

    CHECK(munmap(reader, page) == 0);
    CHECK(munmap(shared, 2 * page) == 0);
    close(read_only);
    close(fd);
    unlink(PATH);
    printf("shared-file failures=%d\n", failures);
    return failures != 0;
}
