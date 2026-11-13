// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include "helpers.h"

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

// The files the test uses, in `TMPDIR` or else /tmp, named after the main process so that runs
// on one host do not share them.
static char PATH[4096];
static char SHORT_PATH[4096];
static char CODE_PATH[4096];

static void name_files(pid_t main_process) {
    const char *directory = getenv("TMPDIR");
    if (directory == NULL || directory[0] == 0) {
        directory = "/tmp";
    }
    int id = (int)main_process;
    snprintf(PATH, sizeof(PATH), "%s/shared-file-mapping-%d", directory, id);
    snprintf(SHORT_PATH, sizeof(SHORT_PATH), "%s/shared-file-mapping-%d-short", directory, id);
    snprintf(CODE_PATH, sizeof(CODE_PATH), "%s/shared-file-mapping-%d-code", directory, id);
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
// wake name the same futex, then sets `word` and wakes it again. Returns whether a wake reached
// the waiter, which it gives up on after about a minute.
static int signal_done(uint32_t *word) {
    int reached = 0;
    for (int i = 0; i < 60000 && !reached; i++) {
        reached = syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0) >= 1;
        if (!reached) {
            sleep_ms(1);
        }
    }
    __atomic_store_n(word, 1, __ATOMIC_SEQ_CST);
    syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0);
    return reached;
}

// The children running, which the watchdog kills so that none outlives the test holding its
// output open.
static volatile pid_t live_children[2];

static void track_child(pid_t child, int live) {
    for (size_t i = 0; i < sizeof(live_children) / sizeof(live_children[0]); i++) {
        if (live ? live_children[i] == 0 : live_children[i] == child) {
            live_children[i] = live ? child : 0;
            return;
        }
    }
}

static void on_watchdog(int signal) {
    (void)signal;
    static const char message[] = "FAIL: timed out\n";
    (void)!write(STDOUT_FILENO, message, sizeof(message) - 1);
    for (size_t i = 0; i < sizeof(live_children) / sizeof(live_children[0]); i++) {
        if (live_children[i] > 0) {
            kill(live_children[i], SIGKILL);
        }
    }
    unlink(PATH);
    _exit(1);
}

// Waits, for up to about a minute, for `child`, running `signal_done` on `word`, to set it,
// then reaps `child`, killing it first if it has not set `word`. Returns whether it set `word`,
// a wake from it ended a wait, and it exited successfully, and reports why not otherwise. Stops
// waiting early if `child` exits without setting `word`, or if waiting fails unexpectedly.
static int reap_child_after_done_wake(uint32_t *word, pid_t child) {
    struct timespec timeout = {5, 0};
    int woken = 0;
    int status = -1;
    int reaped = 0;
    int wait_error = 0;
    for (int waits = 0; __atomic_load_n(word, __ATOMIC_SEQ_CST) == 0 && waits < 12; waits++) {
        long result = syscall(SYS_futex, word, FUTEX_WAIT, 0, &timeout, NULL, 0);
        if (result == 0) {
            woken = 1;
        } else if (errno == ETIMEDOUT) {
            if (waitpid(child, &status, WNOHANG) == child) {
                reaped = 1;
                break;
            }
        } else if (errno != EAGAIN && errno != EINTR) {
            wait_error = errno;
            break;
        }
    }
    int done = woken && __atomic_load_n(word, __ATOMIC_SEQ_CST) == 1;
    if (!reaped) {
        if (!done) {
            kill(child, SIGKILL);
        }
        if (waitpid(child, &status, 0) != child) {
            printf("child %d could not be reaped (errno=%d)\n", (int)child, errno);
            return 0;
        }
    }
    track_child(child, 0);
    int succeeded = done && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!succeeded) {
        printf("child %d: woken=%d done=%d status=%#x wait_errno=%d\n", (int)child, woken, done,
               status, wait_error);
    }
    return succeeded;
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
    return signal_done((uint32_t *)(second_page + SECOND_PAGE_DONE_OFFSET)) ? 0 : 5;
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

// Runs `action` on `argument`, returning the signal that raised, or 0.
static int catch_signal(void (*action)(void *), void *argument) {
    fault_signal = 0;
    if (sigsetjmp(fault_jump, 1) == 0) {
        fault_armed = 1;
        action(argument);
        fault_armed = 0;
        return 0;
    }
    return fault_signal;
}

static void read_byte(void *address) { (void)*(volatile const char *)address; }

static void write_byte(void *address) { *(volatile char *)address = 1; }

// Accesses `address`, writing it if `write` is set, returning the signal that raised, or 0.
static int access_signal(char *address, int write) {
    return catch_signal(write ? write_byte : read_byte, address);
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

static void sync_code(char *code) {
#if defined(__aarch64__)
    __builtin___clear_cache(code, code + 8);
#else
    (void)code;
#endif
}

struct call {
    char *code;
    int result;
};

static void call_code(void *argument) {
    struct call *call = argument;
    call->result = ((int (*)(void))call->code)();
}

// Calls the function at `code`, returning the signal that raised, or 0 after storing its result
// in `result`.
static int call_catching_signal(char *code, int *result) {
    struct call call = {code, 0};
    int signal = catch_signal(call_code, &call);
    if (signal == 0) {
        *result = call.result;
    }
    return signal;
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
    // Ends the test, as failed, if anything hangs, well before the harness gives up on it.
    signal(SIGALRM, on_watchdog);
    alarm(240);

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
    // A replacement the file's access mode refuses leaves what was there.
    errno = 0;
    CHECK(mmap(anonymous + page, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, read_only,
               0) == MAP_FAILED);
    CHECK(errno == EACCES);
    CHECK(anonymous[page] == 'A');
    CHECK(munmap(anonymous, 2 * page) == 0);

    // An offset past the largest file Linux allows, `MAX_LFS_FILESIZE`.
    off_t beyond_limit = (off_t)(INT64_MAX & ~(int64_t)(page - 1));

    // A file open only for writing cannot be mapped at all.
    int write_only = open(PATH, O_WRONLY);
    CHECK(write_only >= 0);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, write_only, 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    close(write_only);

    // A directory has no contents to map, and is never open for writing.
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 0);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, directory, 0) == MAP_FAILED);
    CHECK(errno == ENODEV);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, directory, 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    // Only regular files have a size limit.
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, directory, beyond_limit) == MAP_FAILED);
    CHECK(errno == ENODEV);
    close(directory);

    // Linux checks other descriptors' access modes before finding they cannot be mapped.
    int pipe_ends[2];
    CHECK(pipe(pipe_ends) == 0);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, pipe_ends[0], 0) == MAP_FAILED);
    CHECK(errno == ENODEV);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, pipe_ends[0], 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, pipe_ends[1], 0) == MAP_FAILED);
    CHECK(errno == EACCES);
    close(pipe_ends[0]);
    close(pipe_ends[1]);

    // A descriptor opened only for its path cannot be mapped at all.
    int path_only = open(PATH, O_PATH);
    CHECK(path_only >= 0);
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, path_only, 0) == MAP_FAILED);
    CHECK(errno == EBADF);
    // Linux mmap(2): O_PATH is not a valid mapping descriptor, regardless of requested access.
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, path_only, 0) == MAP_FAILED);
    CHECK(errno == EBADF);
    // Linux refuses the descriptor before checking the size limit.
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, path_only, beyond_limit) == MAP_FAILED);
    CHECK(errno == EBADF);
    close(path_only);

    // A mapping cannot extend past the largest file Linux allows.
    errno = 0;
    CHECK(mmap(NULL, page, PROT_READ, MAP_SHARED, fd, beyond_limit) == MAP_FAILED);
    CHECK(errno == EOVERFLOW);

    // This program's file, open only for reading, maps readable but can never be made writable.
    // LiteBox's read-only image cannot share its pages, so there this maps a copy instead, which
    // stays mapped for the fork below.
    char *image = MAP_FAILED;
    if (self != NULL) {
        int program = open(self, O_RDONLY);
        CHECK(program >= 0);
        image = mmap(NULL, page, PROT_READ, MAP_SHARED, program, 0);
        CHECK(image != MAP_FAILED);
        close(program);
        if (image != MAP_FAILED) {
            CHECK(memcmp(image, "\x7f" "ELF", 4) == 0);
            errno = 0;
            CHECK(mprotect(image, page, PROT_READ | PROT_WRITE) == -1);
            CHECK(errno == EACCES);
            // Its pages are the file's, which freeing cannot discard and discarding keeps.
            errno = 0;
            CHECK(madvise(image, page, MADV_FREE) == -1);
            CHECK(errno == EINVAL);
            CHECK(madvise(image, page, MADV_DONTNEED) == 0);
            CHECK(memcmp(image, "\x7f" "ELF", 4) == 0);
        }
    }

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
    CHECK(msync(shared, 0, MS_SYNC) == 0);
    errno = 0;
    CHECK(msync(shared, page, MS_SYNC | MS_ASYNC) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(msync(shared, page, 8) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(msync(bytes + 1, page, MS_SYNC) == -1);
    CHECK(errno == EINVAL);
    // Linux rounds the length up modulo the address space, so this one wraps to zero.
    CHECK(msync(shared, SIZE_MAX, MS_SYNC) == 0);
    // A range with any unmapped page fails.
    char *unmapped = mmap(NULL, 2 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(unmapped != MAP_FAILED);
    CHECK(munmap(unmapped + page, page) == 0);
    errno = 0;
    CHECK(msync(unmapped, 2 * page, MS_SYNC) == -1);
    CHECK(errno == ENOMEM);
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
    if (pid > 0) {
        track_child(pid, 1);
    }
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
        // The program's mapping stays readable, and never writable, in the child too.
        if (image != MAP_FAILED &&
            (memcmp(image, "\x7f" "ELF", 4) != 0 ||
             mprotect(image, page, PROT_READ | PROT_WRITE) != -1 || errno != EACCES)) {
            _exit(3);
        }
        _exit(signal_done(&shared->child_done) ? 0 : 4);
    }
    CHECK(pid > 0);
    add_increments(shared);
    CHECK(pid > 0 && reap_child_after_done_wake(&shared->child_done, pid));
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
        if (pid > 0) {
            track_child(pid, 1);
        }
        CHECK(pid > 0 && reap_child_after_done_wake(
                             (uint32_t *)(bytes + page + SECOND_PAGE_DONE_OFFSET), pid));
        CHECK(strcmp(shared->exec_child, "from-exec-child") == 0);
        CHECK(shared->counter == 3 * INCREMENTS);
    }
    if (image != MAP_FAILED) {
        CHECK(munmap(image, page) == 0);
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
    unlink(SHORT_PATH);
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

    // An executable shared mapping runs what another mapping of the file stores, as code
    // generators that map one file twice, writable and executable, rely on.
    int code_fd = open(CODE_PATH, O_RDWR | O_CREAT | O_TRUNC, 0700);
    CHECK(code_fd >= 0);
    unlink(CODE_PATH);
    CHECK(ftruncate(code_fd, page) == 0);
    char *writer = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, code_fd, 0);
    char *runner = mmap(NULL, 2 * page, PROT_READ, MAP_SHARED, code_fd, 0);
    CHECK(writer != MAP_FAILED && runner != MAP_FAILED);
    if (writer != MAP_FAILED && runner != MAP_FAILED) {
        // Linux permits executable protection even on pages beyond the file's end.
        CHECK(mprotect(runner, 2 * page, PROT_READ | PROT_EXEC) == 0);
        int result = 0;
        write_return(writer, 42);
        sync_code(runner);
        CHECK(call_catching_signal(runner, &result) == 0 && result == 42);
        write_return(writer, 43);
        sync_code(runner);
        CHECK(call_catching_signal(runner, &result) == 0 && result == 43);
        // Running a mapping that is not executable raises SIGSEGV, and running one past the end
        // of the file raises SIGBUS.
        CHECK(call_catching_signal(writer, &result) == SIGSEGV);
        CHECK(call_catching_signal(runner + page, &result) == SIGBUS);
        CHECK(fault_code == BUS_ADRERR && fault_address == runner + page);
        CHECK(ftruncate(code_fd, 0) == 0);
        CHECK(mprotect(runner, 2 * page, PROT_READ) == 0);
        CHECK(mprotect(runner, 2 * page, PROT_READ | PROT_EXEC) == 0);
        CHECK(call_catching_signal(runner, &result) == SIGBUS);
        CHECK(fault_code == BUS_ADRERR && fault_address == runner);
    }
    if (writer != MAP_FAILED) {
        CHECK(munmap(writer, page) == 0);
    }
    if (runner != MAP_FAILED) {
        CHECK(munmap(runner, 2 * page) == 0);
    }
    close(code_fd);
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
