// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that MAP_SHARED file mappings share pages: between mappings in one process, with
// read/write/ftruncate on the file, with a forked child, and with an unrelated process started
// through execve, including futex wakes across those processes, and between a writable mapping
// and an executable one. Run with this program's own path as the argument to include the exec
// check; it reruns itself with "child" to act as that process.

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
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// The files the test uses, named after the main process so that runs on one host do not share
// them.
static char PATH[64];
static char SHORT_PATH[64];
static char CODE_PATH[64];

static void name_files(pid_t main_process) {
    int id = (int)main_process;
    snprintf(PATH, sizeof(PATH), "/tmp/shared-file-mapping-%d", id);
    snprintf(SHORT_PATH, sizeof(SHORT_PATH), "/tmp/shared-file-mapping-%d-short", id);
    snprintf(CODE_PATH, sizeof(CODE_PATH), "/tmp/shared-file-mapping-%d-code", id);
}
#define INCREMENTS 100000
// Where in the file's second page the exec child signals that it is done.
#define SECOND_PAGE_DONE_OFFSET 64

struct shared {
    uint64_t counter;
    char parent[32];
    char child[32];
    char exec_child[32];
    uint32_t child_done;
};

static int failures;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            printf("FAIL line %d: %s (errno=%d)\n", __LINE__, #cond, errno);           \
            failures++;                                                                \
        }                                                                              \
    } while (0)

static void add_increments(struct shared *shared) {
    for (int i = 0; i < INCREMENTS; i++) {
        __atomic_fetch_add(&shared->counter, 1, __ATOMIC_SEQ_CST);
    }
}

// Wakes the process waiting for `word` until a wake reaches it, which proves the wait and the
// wake name the same futex, then sets `word` and wakes it again. Gives up reaching it after
// about a minute, which the waiter then reports.
static void signal_done(uint32_t *word) {
    struct timespec pause = {0, 1000 * 1000};
    for (int i = 0; i < 60000 && syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0) < 1;
         i++) {
        nanosleep(&pause, NULL);
    }
    __atomic_store_n(word, 1, __ATOMIC_SEQ_CST);
    syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0);
}

// Waits, for up to about two minutes, for `child`, running `signal_done` on `word`, to set it,
// then reaps `child`, returning whether it set `word`, a wake from it ended a wait, and it
// exited successfully. Stops waiting early if `child` exits without setting `word`.
static int woken_when_done(uint32_t *word, pid_t child) {
    struct timespec timeout = {5, 0};
    int woken = 0;
    int status = -1;
    int reaped = 0;
    for (int waits = 0; __atomic_load_n(word, __ATOMIC_SEQ_CST) == 0 && waits < 24; waits++) {
        long result = syscall(SYS_futex, word, FUTEX_WAIT, 0, &timeout, NULL, 0);
        if (result == 0) {
            woken = 1;
        } else if (errno == ETIMEDOUT && waitpid(child, &status, WNOHANG) == child) {
            reaped = 1;
            break;
        }
    }
    int done = woken && __atomic_load_n(word, __ATOMIC_SEQ_CST) == 1;
    if (!reaped && waitpid(child, &status, 0) != child) {
        return 0;
    }
    return done && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int exec_child(void) {
    long page = sysconf(_SC_PAGESIZE);
    int fd = open(PATH, O_RDWR);
    if (fd < 0) {
        return 2;
    }
    struct shared *shared =
        mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    // The second page alone, so that futex words in it are keyed by their offset in the file.
    char *second_page = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page);
    if (shared == MAP_FAILED || second_page == MAP_FAILED) {
        return 3;
    }
    if (strcmp(shared->parent, "from-parent") != 0) {
        return 4;
    }
    strcpy(shared->exec_child, "from-exec-child");
    add_increments(shared);
    signal_done((uint32_t *)(second_page + SECOND_PAGE_DONE_OFFSET));
    return 0;
}

static sigjmp_buf fault_jump;
// Whether `fault_jump` guards the access in progress.
static volatile sig_atomic_t fault_armed;
static volatile sig_atomic_t fault_signal;
static volatile sig_atomic_t fault_code;
static void *volatile fault_address;

static void on_fault(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (!fault_armed) {
        // An unexpected fault: let it repeat with the default action, which ends the test.
        struct sigaction action = {0};
        action.sa_handler = SIG_DFL;
        sigaction(signal, &action, NULL);
        return;
    }
    fault_armed = 0;
    fault_signal = signal;
    fault_code = info->si_code;
    fault_address = info->si_addr;
    siglongjmp(fault_jump, 1);
}

// Accesses `address`, writing it if `write` is set, returning the signal that raised, or 0.
static int access_signal(char *address, int write) {
    fault_signal = 0;
    if (sigsetjmp(fault_jump, 1) == 0) {
        fault_armed = 1;
        if (write) {
            *(volatile char *)address = 1;
        } else {
            (void)*(volatile const char *)address;
        }
        fault_armed = 0;
        return 0;
    }
    return fault_signal;
}

// Returns whether accessing `address`, past the end of a mapped file, raises SIGBUS as Linux
// does for such an access.
static int raises_bus(char *address, int write) {
    return access_signal(address, write) == SIGBUS && fault_code == BUS_ADRERR &&
           fault_address == address;
}

// Writes a function returning `value` at `code`.
static void write_return(char *code, int value) {
#if defined(__x86_64__)
    code[0] = (char)0xb8; // mov eax, imm32
    memcpy(code + 1, &value, 4);
    code[5] = (char)0xc3; // ret
#elif defined(__aarch64__)
    uint32_t instructions[2] = {0x52800000u | ((uint32_t)value << 5), 0xd65f03c0u};
    memcpy(code, instructions, sizeof(instructions));
#else
#error "unsupported architecture"
#endif
}

// Calls the function at `code`, returning the signal that raised, or 0 after storing its result
// in `result`.
static int call_catching_signal(char *code, int *result) {
    fault_signal = 0;
    if (sigsetjmp(fault_jump, 1) == 0) {
        fault_armed = 1;
        // Cleaning the cache accesses `code` too, which faults the same way past the end of the
        // file.
#if defined(__aarch64__)
        __builtin___clear_cache(code, code + 8);
#endif
        *result = ((int (*)(void))code)();
        fault_armed = 0;
        return 0;
    }
    return fault_signal;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 2 && strcmp(argv[1], "child") == 0) {
        // The main process forked this one before it ran this program.
        name_files(getppid());
        return exec_child();
    }
    name_files(getpid());
    const char *self = argc >= 2 ? argv[1] : NULL;
    long page = sysconf(_SC_PAGESIZE);
    // Ends the test, as failed, if anything hangs.
    alarm(600);

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

    // A mapping from a nonzero offset shares the pages at that offset.
    char *second_page = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page);
    CHECK(second_page != MAP_FAILED);
    CHECK(strcmp(second_page, "written") == 0);
    second_page[8] = 'Y';
    CHECK(bytes[page + 8] == 'Y');
    CHECK(munmap(second_page, page) == 0);

    // A mapping of a file open for writing may be made writable later.
    char *upgraded = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, page);
    CHECK(upgraded != MAP_FAILED);
    CHECK(mprotect(upgraded, page, PROT_READ | PROT_WRITE) == 0);
    upgraded[32] = 'U';
    char upgraded_byte = 0;
    CHECK(pread(fd, &upgraded_byte, 1, page + 32) == 1 && upgraded_byte == 'U');
    CHECK(munmap(upgraded, page) == 0);

    // A fixed mapping replaces what was there, but not when asked not to.
    char *anonymous =
        mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(anonymous != MAP_FAILED);
    anonymous[page] = 'A';
    struct shared *fixed = mmap(anonymous, page, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_FIXED, fd, 0);
    CHECK(fixed == (struct shared *)anonymous);
    CHECK(fixed->counter == 123);
    CHECK(anonymous[page] == 'A');
    errno = 0;
    CHECK(mmap(anonymous + page, page, PROT_READ, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0) ==
          MAP_FAILED);
    CHECK(errno == EEXIST);
    CHECK(anonymous[page] == 'A');
    CHECK(munmap(anonymous, 2 * page) == 0);

    // A file open only for writing cannot be mapped at all.
    int write_only = open(PATH, O_WRONLY);
    CHECK(write_only >= 0);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, write_only, 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    close(write_only);

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
    errno = 0;
    CHECK(msync(shared, page, 8) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(msync(bytes + 1, page, MS_SYNC) == -1);
    CHECK(errno == EINVAL);
    char *unmapped = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(unmapped != MAP_FAILED);
    CHECK(munmap(unmapped, page) == 0);
    errno = 0;
    CHECK(msync(unmapped, page, MS_SYNC) == -1);
    CHECK(errno == ENOMEM);

    // Freeing applies only to anonymous memory; the file keeps its contents.
    errno = 0;
    CHECK(madvise(shared, page, MADV_FREE) == -1);
    CHECK(errno == EINVAL);
    CHECK(madvise(shared, page, MADV_DONTNEED) == 0);
    CHECK(strcmp(shared->parent, "from-parent") == 0);

    // A forked child shares the pages.
    shared->counter = 0;
    pid_t pid = fork();
    if (pid == 0) {
        strcpy(shared->child, "from-child");
        add_increments(shared);
        // A mapping the child creates shares the pages too.
        struct shared *again =
            mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (again == MAP_FAILED || strcmp(again->parent, "from-parent") != 0) {
            _exit(1);
        }
        strcpy(again->child + 11, "+");
        signal_done(&shared->child_done);
        _exit(0);
    }
    CHECK(pid > 0);
    add_increments(shared);
    CHECK(pid > 0 && woken_when_done(&shared->child_done, pid));
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
        CHECK(pid > 0 &&
              woken_when_done((uint32_t *)(bytes + page + SECOND_PAGE_DONE_OFFSET), pid));
        CHECK(strcmp(shared->exec_child, "from-exec-child") == 0);
        CHECK(shared->counter == 3 * INCREMENTS);
    }

    struct sigaction action = {0};
    action.sa_sigaction = on_fault;
    action.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGBUS, &action, NULL) == 0);
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);

    // Writing a mapping of a file open only for reading faults like any read-only memory.
    CHECK(access_signal((char *)reader, 1) == SIGSEGV);

    // Truncation discards the pages past the new end, and growing the file again exposes
    // zeros. Accessing a mapped page past the end of the file raises SIGBUS.
    CHECK(ftruncate(fd, page) == 0);
    CHECK(ftruncate(fd, 2 * page) == 0);
    CHECK(bytes[page] == 0);
    CHECK(pwrite(fd, "again", 6, page) == 6);
    CHECK(strcmp(bytes + page, "again") == 0);
    CHECK(ftruncate(fd, page) == 0);
    struct stat file_status;
    CHECK(fstat(fd, &file_status) == 0 && file_status.st_size == page);
    char past_end_byte = 0;
    CHECK(pread(fd, &past_end_byte, 1, page) == 0);
    CHECK(raises_bus(bytes + page, 0));
    CHECK(raises_bus(bytes + page, 1));
    // A system call given such memory fails instead.
    int pipe_fds[2];
    CHECK(pipe(pipe_fds) == 0);
    errno = 0;
    CHECK(write(pipe_fds[1], bytes + page, 1) == -1);
    CHECK(errno == EFAULT);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    // Truncating on open discards the mapped pages too.
    CHECK(close(open(PATH, O_RDWR | O_TRUNC)) == 0);
    CHECK(fstat(fd, &file_status) == 0 && file_status.st_size == 0);
    CHECK(ftruncate(fd, 2 * page) == 0);
    CHECK(shared->counter == 0 && bytes[page] == 0);

    // A mapping that extends past the end of its file raises SIGBUS there too.
    int short_fd = open(SHORT_PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(short_fd >= 0);
    CHECK(ftruncate(short_fd, page / 2) == 0);
    char *past_end = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, short_fd, 0);
    CHECK(past_end != MAP_FAILED);
    if (past_end != MAP_FAILED) {
        // The rest of the last page is accessible and zero, as on Linux.
        past_end[0] = 'x';
        CHECK(past_end[page - 1] == 0);
        CHECK(access_signal(past_end + page / 2, 0) == 0);
        CHECK(raises_bus(past_end + page, 0));
        CHECK(munmap(past_end, 2 * page) == 0);
    }
    close(short_fd);
    unlink(SHORT_PATH);

    // An executable shared mapping runs what another mapping of the file stores, as code
    // generators that map one file twice, writable and executable, rely on.
    int code_fd = open(CODE_PATH, O_RDWR | O_CREAT | O_TRUNC, 0700);
    CHECK(code_fd >= 0);
    CHECK(ftruncate(code_fd, page) == 0);
    char *writer = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, code_fd, 0);
    char *runner = mmap(NULL, 2 * page, PROT_READ | PROT_EXEC, MAP_SHARED, code_fd, 0);
    CHECK(writer != MAP_FAILED && runner != MAP_FAILED);
    if (writer != MAP_FAILED && runner != MAP_FAILED) {
        int result = 0;
        write_return(writer, 42);
        CHECK(call_catching_signal(runner, &result) == 0 && result == 42);
        write_return(writer, 43);
        CHECK(call_catching_signal(runner, &result) == 0 && result == 43);
        // Running a mapping that is not executable raises SIGSEGV, and running one past the end
        // of the file raises SIGBUS.
        CHECK(call_catching_signal(writer, &result) == SIGSEGV);
        CHECK(call_catching_signal(runner + page, &result) == SIGBUS);
        CHECK(fault_code == BUS_ADRERR && fault_address == runner + page);
    }
    if (writer != MAP_FAILED) {
        CHECK(munmap(writer, page) == 0);
    }
    if (runner != MAP_FAILED) {
        CHECK(munmap(runner, 2 * page) == 0);
    }
    close(code_fd);
    unlink(CODE_PATH);
    action.sa_handler = SIG_DFL;
    action.sa_flags = 0;
    CHECK(sigaction(SIGBUS, &action, NULL) == 0);
    CHECK(sigaction(SIGSEGV, &action, NULL) == 0);

    CHECK(munmap(reader, page) == 0);
    CHECK(munmap(shared, 2 * page) == 0);
    close(read_only);
    close(fd);
    unlink(PATH);
    printf("shared-file failures=%d\n", failures);
    return failures != 0;
}
