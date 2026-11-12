// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "helpers.h"

static void check_self(void) {
    char expected[32];
    char target[32];
    int size = snprintf(expected, sizeof(expected), "%d", getpid());
    assert(readlink("/proc/self", target, sizeof(target)) == size);
    assert(memcmp(expected, target, size) == 0);
    struct stat link, directory;
    assert(lstat("/proc/self", &link) == 0 && S_ISLNK(link.st_mode));
    assert(link.st_size == 0);
    assert(stat("/proc/self", &directory) == 0 && S_ISDIR(directory.st_mode));
    int fd = open("/proc/self", O_RDONLY | O_DIRECTORY);
    assert(fd >= 0);
    struct stat opened;
    assert(fstat(fd, &opened) == 0 && opened.st_ino == directory.st_ino);
    assert(close(fd) == 0);
    assert(open("/proc/self", O_WRONLY) == -1 && errno == EISDIR);
    assert(mkdir("/proc/self/fd", 0700) == -1 && errno == EEXIST);
    assert(symlink("/elsewhere", "/proc/self/fd") == -1 && errno == EEXIST);
    DIR *root = opendir("/proc");
    assert(root != NULL);
    int found_self = 0, found_pid = 0;
    struct dirent *entry;
    while ((entry = readdir(root)) != NULL) {
        found_self |= strcmp(entry->d_name, "self") == 0;
        found_pid |= strcmp(entry->d_name, expected) == 0;
    }
    assert(found_self && found_pid);
    assert(closedir(root) == 0);
}

static ino_t check_image(void) {
    struct stat target, link, opened;
    assert(lstat("/proc/self/exe", &link) == 0 && S_ISLNK(link.st_mode));
    assert(stat("/proc/self/exe", &target) == 0 && S_ISREG(target.st_mode));
    int fd = open("/proc/self/exe", O_RDONLY);
    assert(fd >= 0);
    assert(fstat(fd, &opened) == 0 && opened.st_ino == target.st_ino);
    char magic[4];
    assert(read(fd, magic, sizeof(magic)) == sizeof(magic));
    assert(memcmp(magic, "\177ELF", sizeof(magic)) == 0);
    assert(close(fd) == 0);
    char numeric[64];
    snprintf(numeric, sizeof(numeric), "/proc/%d/exe", getpid());
    assert(stat(numeric, &opened) == 0 && opened.st_ino == target.st_ino);
    char display[4096], own_display[4096];
    ssize_t length = readlink(numeric, display, sizeof(display));
    assert(length > 0);
    assert(readlink("/proc/self/exe", own_display, sizeof(own_display)) == length);
    assert(memcmp(display, own_display, length) == 0);
    fd = open("/proc/self/exe", O_PATH | O_NOFOLLOW);
    assert(fd >= 0);
    assert(fstat(fd, &opened) == 0 && S_ISLNK(opened.st_mode));
    assert(opened.st_ino == link.st_ino);
    assert(close(fd) == 0);
    assert(open("/proc/self/exe", O_WRONLY) == -1 && errno == ETXTBSY);
    assert(open("/proc/self/exe", O_RDONLY | O_TRUNC) == -1 && errno == ETXTBSY);
    // Reopening a descriptor of the image is refused the same way.
    fd = open("/proc/self/exe", O_RDONLY);
    assert(fd >= 0);
    snprintf(numeric, sizeof(numeric), "/proc/self/fd/%d", fd);
    assert(open(numeric, O_RDWR) == -1 && errno == ETXTBSY);
    assert(close(fd) == 0);
    assert(stat("/proc/self/exe/child", &opened) == -1 && errno == ENOTDIR);
    assert(chdir("/proc/self/exe") == -1 && errno == ENOTDIR);
    return target.st_ino;
}

// Checks that `/proc/self/cwd` is a link naming, and leading to, the working directory.
static void check_cwd(void) {
    char cwd[4096], target[4096];
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    ssize_t length = readlink("/proc/self/cwd", target, sizeof(target));
    assert(length == (ssize_t)strlen(cwd));
    assert(memcmp(cwd, target, length) == 0);
    struct stat link, followed, directory;
    assert(lstat("/proc/self/cwd", &link) == 0 && S_ISLNK(link.st_mode));
    assert(stat("/proc/self/cwd", &followed) == 0 && S_ISDIR(followed.st_mode));
    assert(stat(cwd, &directory) == 0 && followed.st_ino == directory.st_ino);
}

// Checks that a 20-character `/proc/self/limits` value column holds `expected`.
static void check_limit_value(const char *column, rlim_t expected) {
    char value[21];
    memcpy(value, column, 20);
    value[20] = '\0';
    for (int i = 19; i >= 0 && value[i] == ' '; i--) {
        value[i] = '\0';
    }
    if (expected == RLIM_INFINITY) {
        assert(strcmp(value, "unlimited") == 0);
    } else {
        char *end;
        assert(strtoull(value, &end, 10) == expected && *end == '\0' && end != value);
    }
}

// Checks that `/proc/self/limits` reports every limit as `getrlimit` does.
static void check_limits(void) {
    struct stat status;
    assert(stat("/proc/self/limits", &status) == 0 && S_ISREG(status.st_mode));
    assert((status.st_mode & 07777) == 0444 && status.st_size == 0);
    assert(open("/proc/self/limits", O_WRONLY) == -1 && errno == EACCES);
    char text[4096];
    int fd = open("/proc/self/limits", O_RDONLY);
    assert(fd >= 0);
    ssize_t total = 0, count;
    while ((count = read(fd, text + total, sizeof(text) - 1 - total)) > 0) {
        total += count;
    }
    assert(count == 0 && lseek(fd, 0, SEEK_CUR) == total);
    // Like any seq_file, the text can be sought anywhere from its start, but not from its end.
    assert(lseek(fd, 0, SEEK_END) == -1 && errno == EINVAL);
    char byte;
    assert(lseek(fd, 5, SEEK_SET) == 5 && read(fd, &byte, 1) == 1 && byte == text[5]);
    assert(lseek(fd, total + 100, SEEK_SET) == total + 100 && read(fd, &byte, 1) == 0);
    assert(close(fd) == 0);
    assert(readlink("/proc/self/limits", &byte, 1) == -1 && errno == EINVAL);
    text[total] = '\0';
    const char *line = strchr(text, '\n');
    assert(line != NULL);
    line++;
    for (int resource = 0; resource <= RLIMIT_RTTIME; resource++) {
        const char *end = strchr(line, '\n');
        assert(end != NULL && end - line >= 67);
        struct rlimit limit;
        assert(getrlimit(resource, &limit) == 0);
        check_limit_value(line + 26, limit.rlim_cur);
        check_limit_value(line + 47, limit.rlim_max);
        line = end + 1;
    }
    assert(*line == '\0');
}

static void check_limits_reposition(void) {
    struct rlimit original, changed;
    assert(getrlimit(RLIMIT_CORE, &original) == 0 && original.rlim_max >= 1);
    changed = original;
    changed.rlim_cur = original.rlim_cur == 0 ? 1 : 0;
    char before[4096], after[4096], expected[4096];
    int fd = open("/proc/self/limits", O_RDONLY);
    assert(fd >= 0 && read(fd, before, 3) == 3);
    assert(setrlimit(RLIMIT_CORE, &changed) == 0);
    size_t total = 3;
    ssize_t count;
    while ((count = read(fd, before + total, 3)) > 0) {
        total += count;
        assert(total + 3 < sizeof(before));
    }
    assert(count == 0);
    before[total] = '\0';
    const char *core = strstr(before, "Max core file size");
    assert(core != NULL);
    check_limit_value(core + 26, original.rlim_cur);
    int fresh = open("/proc/self/limits", O_RDONLY);
    assert(fresh >= 0);
    ssize_t length = read(fresh, expected, sizeof(expected));
    assert(length > 1 && close(fresh) == 0);
    total = 1;
    while ((count = pread(fd, after + total, 3, total)) > 0) {
        total += count;
        assert(total + 3 < sizeof(after));
    }
    // Native Linux: a discontinuous pread regenerates the limits sequence.
    assert(count == 0 && total == (size_t)length);
    assert(memcmp(after + 1, expected + 1, total - 1) == 0);
    assert(close(fd) == 0 && setrlimit(RLIMIT_CORE, &original) == 0);
}

static void check_mutations(void) {
    // Verified through the native syscall surface, not the backend's generic read-only errors.
    assert(mkdir("/proc/litebox-missing-directory", 0700) == -1 && errno == ENOENT);
    assert(unlink("/proc/self") == -1 && errno == EACCES);
    assert(chmod("/proc/self", 0700) == -1 && errno == EPERM);
    assert(symlink("/elsewhere", "/proc/litebox-missing-link") == -1 && errno == ENOENT);
    struct stat status;
    assert(stat("/proc/self/fd", &status) == 0);
    assert((status.st_mode & 07777) == 0500);
}

static void check_directory_copy_fault(void) {
    long page = sysconf(_SC_PAGESIZE);
    assert(page > 24);
    char *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapping != MAP_FAILED);
    assert(mprotect(mapping + page, page, PROT_NONE) == 0);
    int fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    assert(fd >= 0);
    struct dirent64 *first = (struct dirent64 *)(mapping + page - 24);
    // Native Linux reports the complete prefix and retries the entry whose copy faulted.
    ssize_t copied = getdents64(fd, first, 48);
    if (copied != 24) {
        fprintf(stderr, "partial getdents64: got %zd, errno %d\n", copied, errno);
    }
    assert(copied == 24 && strcmp(first->d_name, ".") == 0);
    char buffer[32];
    assert(getdents64(fd, buffer, 24) == 24);
    assert(strcmp(((struct dirent64 *)buffer)->d_name, "..") == 0);
    assert(close(fd) == 0 && munmap(mapping, 2 * page) == 0);
}

// Returns the value of `/proc/self/status`'s field `key`, which must be present, in `value`.
static void status_field(const char *key, char *value, size_t size) {
    char text[4096];
    int fd = open("/proc/self/status", O_RDONLY);
    assert(fd >= 0);
    ssize_t total = 0, count;
    while ((count = read(fd, text + total, sizeof(text) - 1 - total)) > 0) {
        total += count;
    }
    assert(count == 0 && close(fd) == 0);
    text[total] = '\0';
    size_t key_length = strlen(key);
    for (char *line = text; *line != '\0';) {
        char *end = strchr(line, '\n');
        assert(end != NULL);
        if (strncmp(line, key, key_length) == 0 && line[key_length] == ':' &&
            line[key_length + 1] == '\t') {
            size_t length = end - (line + key_length + 2);
            assert(length < size);
            memcpy(value, line + key_length + 2, length);
            value[length] = '\0';
            return;
        }
        line = end + 1;
    }
    assert(!"missing status field");
}

static void check_status_field(const char *key, const char *expected) {
    char value[256];
    status_field(key, value, sizeof(value));
    if (strcmp(value, expected) != 0) {
        fprintf(stderr, "status %s: %s != %s\n", key, value, expected);
        assert(!"unexpected status field");
    }
}

// Checks that `/proc/self/status` reports this process as it sees itself, with `threads` threads.
static void check_status(int threads) {
    struct stat status;
    assert(stat("/proc/self/status", &status) == 0 && S_ISREG(status.st_mode));
    assert((status.st_mode & 07777) == 0444 && status.st_size == 0);
    char expected[256], name[16] = {0};
    assert(prctl(PR_GET_NAME, name) == 0);
    check_status_field("Name", name);
    mode_t mask = umask(0);
    umask(mask);
    snprintf(expected, sizeof(expected), "%04o", mask);
    check_status_field("Umask", expected);
    snprintf(expected, sizeof(expected), "%d", getpid());
    check_status_field("Tgid", expected);
    check_status_field("Pid", expected);
    snprintf(expected, sizeof(expected), "%d", getppid());
    check_status_field("PPid", expected);
    check_status_field("TracerPid", "0");
    snprintf(expected, sizeof(expected), "%u\t%u\t%u\t%u", getuid(), geteuid(), geteuid(),
             geteuid());
    check_status_field("Uid", expected);
    snprintf(expected, sizeof(expected), "%u\t%u\t%u\t%u", getgid(), getegid(), getegid(),
             getegid());
    check_status_field("Gid", expected);
    snprintf(expected, sizeof(expected), "%d", threads);
    check_status_field("Threads", expected);
}

// Waits until `/proc/self/status` reports `threads` threads. A joined thread may still count
// briefly, since Linux wakes the joiner before the thread finishes exiting.
static void wait_for_threads(int threads) {
    char expected[16], value[256];
    snprintf(expected, sizeof(expected), "%d", threads);
    struct timespec start, now;
    assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    for (;;) {
        status_field("Threads", value, sizeof(value));
        if (strcmp(value, expected) == 0) {
            return;
        }
        assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        if (now.tv_sec - start.tv_sec > 30) {
            fprintf(stderr, "status Threads: %s != %s\n", value, expected);
            assert(!"thread count did not settle");
        }
        sched_yield();
    }
}

static pthread_barrier_t worker_started, worker_checked;

static void *worker(void *argument) {
    (void)argument;
    // Renaming another thread leaves the process's name, its leader's, alone.
    assert(prctl(PR_SET_NAME, "worker") == 0);
    pthread_barrier_wait(&worker_started);
    pthread_barrier_wait(&worker_checked);
    return NULL;
}

static void check_status_changes(void) {
    check_status(1);
    char original[16] = {0};
    assert(prctl(PR_GET_NAME, original) == 0);
    // Like Linux, `Name` escapes newlines and backslashes.
    assert(prctl(PR_SET_NAME, "line\nslash\\") == 0);
    check_status_field("Name", "line\\nslash\\\\");
    assert(prctl(PR_SET_NAME, "renamed") == 0);
    check_status_field("Name", "renamed");
    mode_t mask = umask(027);
    check_status_field("Umask", "0027");
    // A vfork child has its own umask, so changing it leaves the parent's alone.
    pid_t child = vfork();
    assert(child >= 0);
    if (child == 0) {
        umask(077);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status));
    check_status_field("Umask", "0027");
    umask(mask);

    pthread_t thread;
    assert(pthread_barrier_init(&worker_started, NULL, 2) == 0);
    assert(pthread_barrier_init(&worker_checked, NULL, 2) == 0);
    assert(pthread_create(&thread, NULL, worker, NULL) == 0);
    pthread_barrier_wait(&worker_started);
    check_status(2);
    check_status_field("Name", "renamed");
    pthread_barrier_wait(&worker_checked);
    assert(pthread_join(thread, NULL) == 0);
    wait_for_threads(1);
    check_status(1);
    assert(prctl(PR_SET_NAME, original) == 0);
    check_status(1);
}

// Checks that listing `/proc/self/fd` one entry per call lists `file`, and that seeking to an
// entry's `d_off` resumes after that entry.
static void check_descriptor_listing(int file) {
    char buffer[sizeof(struct dirent64) + 8], name[16];
    int path_only = open("/proc/self/fd", O_PATH | O_DIRECTORY);
    assert(path_only >= 0);
    assert(getdents64(path_only, buffer, sizeof(buffer)) == -1 && errno == EBADF);
    assert(lseek(path_only, 0, SEEK_SET) == -1 && errno == EBADF);
    assert(close(path_only) == 0);
    int directory = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    assert(directory >= 0);
    assert(getdents64(directory, buffer, 8) == -1 && errno == EINVAL);
    snprintf(name, sizeof(name), "%d", file);
    off_t after_file = -1, previous = -1;
    int entries = 0;
    ssize_t count;
    // A short buffer holds one entry per call.
    while ((count = getdents64(directory, buffer, 32)) > 0) {
        struct dirent64 *entry = (struct dirent64 *)buffer;
        assert(entry->d_reclen == count && entry->d_off > previous);
        previous = entry->d_off;
        entries++;
        if (strcmp(entry->d_name, name) == 0) {
            after_file = entry->d_off;
        }
    }
    assert(count == 0 && entries >= 5 && after_file >= 0);
    assert(lseek(directory, after_file, SEEK_SET) == after_file);
    while ((count = getdents64(directory, buffer, 32)) > 0) {
        struct dirent64 *entry = (struct dirent64 *)buffer;
        assert(strcmp(entry->d_name, name) != 0 && strcmp(entry->d_name, ".") != 0);
    }
    assert(count == 0 && close(directory) == 0);
}

// Checks that `/proc/self/fd/<n>` names, reaches, and reopens this process's descriptor `n`.
static void check_descriptors(void) {
    const char *name = "/tmp/procfs-descriptor";
    char path[64], other[64], target[4096], data[4];
    int file = open(name, O_RDWR | O_CREAT | O_TRUNC, 0600);
    assert(file >= 0 && write(file, "abcdef", 6) == 6);
    snprintf(path, sizeof(path), "/proc/self/fd/%d", file);
    ssize_t length = readlink(path, target, sizeof(target));
    assert(length == (ssize_t)strlen(name) && memcmp(target, name, length) == 0);
    struct stat link, followed, opened;
    assert(lstat(path, &link) == 0 && S_ISLNK(link.st_mode));
    assert((link.st_mode & 07777) == 0700 && link.st_size == 64);
    assert(stat(path, &followed) == 0 && fstat(file, &opened) == 0);
    assert(S_ISREG(followed.st_mode) && followed.st_ino == opened.st_ino);
    assert(access(path, R_OK | W_OK) == 0);

    // Opening the link opens the file anew, with an offset of its own.
    int reopened = open(path, O_RDONLY);
    assert(reopened >= 0 && read(reopened, data, 3) == 3 && memcmp(data, "abc", 3) == 0);
    assert(lseek(file, 0, SEEK_CUR) == 6 && close(reopened) == 0);
    snprintf(other, sizeof(other), "/proc/%d/fd/%d", getpid(), file);
    assert(stat(other, &followed) == 0 && followed.st_ino == opened.st_ino);
    assert(symlink(path, "/tmp/procfs-fd-link") == 0);
    reopened = open("/tmp/procfs-fd-link", O_RDONLY);
    assert(reopened >= 0 && read(reopened, data, 2) == 2 && memcmp(data, "ab", 2) == 0);
    assert(close(reopened) == 0 && unlink("/tmp/procfs-fd-link") == 0);
    // Native Linux reopens the retained object even when its old name leads back to this link.
    const char *looped = "/tmp/procfs-looped";
    int loop_fd = open(looped, O_RDWR | O_CREAT | O_TRUNC, 0600);
    assert(loop_fd >= 0 && write(loop_fd, "old", 3) == 3 && unlink(looped) == 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", loop_fd);
    assert(symlink(other, looped) == 0);
    reopened = open(other, O_RDONLY);
    assert(reopened >= 0 && read(reopened, data, 3) == 3 && memcmp(data, "old", 3) == 0);
    assert(close(reopened) == 0);
    assert(unlink(looped) == 0 && close(loop_fd) == 0);
    // `/dev/fd` leads to the same descriptors.
    length = readlink("/dev/fd", target, sizeof(target));
    assert(length == 13 && memcmp(target, "/proc/self/fd", 13) == 0);
    snprintf(other, sizeof(other), "/dev/fd/%d", file);
    reopened = open(other, O_RDONLY);
    assert(reopened >= 0 && read(reopened, data, 3) == 3 && memcmp(data, "abc", 3) == 0);
    assert(close(reopened) == 0);
    // Changing to a descriptor's link changes to its directory, and only a directory's.
    char original[4096], cwd[4096];
    assert(getcwd(original, sizeof(original)) != NULL);
    int directory = open("/tmp", O_RDONLY | O_DIRECTORY);
    assert(directory >= 0);
    snprintf(other, sizeof(other), "/dev/fd/%d", directory);
    assert(chdir(other) == 0 && getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/tmp") == 0);
    assert(chdir(original) == 0 && close(directory) == 0);
    assert(chdir(path) == -1 && errno == ENOTDIR);
    int read_only = open(name, O_RDONLY);
    assert(read_only >= 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", read_only);
    assert(lstat(other, &link) == 0 && (link.st_mode & 07777) == 0500);
    assert(close(read_only) == 0);

    // A pipe end reopens the pipe itself, in whichever direction is requested; a socket cannot
    // be reopened.
    int pipe_fds[2];
    assert(pipe(pipe_fds) == 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", pipe_fds[0]);
    length = readlink(other, target, sizeof(target));
    assert(length > 6 && memcmp(target, "pipe:[", 6) == 0);
    assert(stat(other, &followed) == 0 && S_ISFIFO(followed.st_mode));
    int reader = open(other, O_RDONLY);
    assert(reader >= 0 && write(pipe_fds[1], "x", 1) == 1);
    assert(read(reader, data, 1) == 1 && data[0] == 'x');
    int nonblocking = open(other, O_RDONLY | O_NONBLOCK);
    assert(nonblocking >= 0 && (fcntl(nonblocking, F_GETFL) & O_NONBLOCK) != 0);
    assert((fcntl(pipe_fds[0], F_GETFL) & O_NONBLOCK) == 0);
    assert(read(nonblocking, data, 1) == -1 && errno == EAGAIN);
    assert(fcntl(nonblocking, F_SETFL, O_APPEND | O_NONBLOCK) == 0);
    assert((fcntl(pipe_fds[0], F_GETFL) & O_APPEND) == 0);
    int opposite = open(other, O_WRONLY | O_NONBLOCK);
    assert(opposite >= 0 && write(opposite, "z", 1) == 1);
    assert(read(nonblocking, data, 1) == 1 && data[0] == 'z');
    assert(close(opposite) == 0 && close(nonblocking) == 0);
    // The link to the write end has only write access, which a nofollow check sees.
    assert(lstat(other, &link) == 0 && (link.st_mode & 07777) == 0500);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", pipe_fds[1]);
    assert(lstat(other, &link) == 0 && (link.st_mode & 07777) == 0300);
    assert(faccessat(AT_FDCWD, other, W_OK, AT_SYMLINK_NOFOLLOW) == 0);
    assert(faccessat(AT_FDCWD, other, R_OK, AT_SYMLINK_NOFOLLOW) == -1 && errno == EACCES);
    assert(access(other, W_OK) == 0);
    int writer = open(other, O_WRONLY);
    assert(writer >= 0 && write(writer, "y", 1) == 1);
    assert(read(reader, data, 1) == 1 && data[0] == 'y');
    int both = open(other, O_RDWR | O_NONBLOCK);
    assert(both >= 0 && write(both, "b", 1) == 1);
    assert(read(both, data, 1) == 1 && data[0] == 'b');
    assert(close(both) == 0);
    // Opening a link without following it, or exclusively creating it, fails.
    assert(open(other, O_WRONLY | O_NOFOLLOW) == -1 && errno == ELOOP);
    assert(open(other, O_WRONLY | O_CREAT | O_EXCL, 0600) == -1 && errno == EEXIST);
    assert(close(writer) == 0 && close(reader) == 0);
    assert(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", sockets[0]);
    assert(open(other, O_RDWR) == -1 && errno == ENXIO);
    assert(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    // Nor can an anonymous inode, whose root-owned mode refuses others first.
    int event = eventfd(0, 0);
    assert(event >= 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", event);
    assert(open(other, O_RDWR) == -1 && errno == (geteuid() == 0 ? ENXIO : EACCES));
    assert(close(event) == 0);

    // Only an `O_PATH` open may name a link itself, through its descriptor too.
    assert(symlink("procfs-descriptor", "/tmp/procfs-symlink") == 0);
    int link_fd = open("/tmp/procfs-symlink", O_PATH | O_NOFOLLOW);
    assert(link_fd >= 0);
    snprintf(other, sizeof(other), "/proc/self/fd/%d", link_fd);
    assert(open(other, O_RDONLY) == -1 && errno == ELOOP);
    assert(open(other, O_RDONLY | O_TRUNC) == -1 && errno == ELOOP);
    assert(open(other, O_WRONLY) == -1 && errno == ELOOP);
    assert(close(link_fd) == 0 && unlink("/tmp/procfs-symlink") == 0);

    // The directory lists the open descriptors, and closed or malformed names name nothing.
    int listed_file = 0, listed_stdin = 0;
    DIR *descriptors = opendir("/proc/self/fd");
    assert(descriptors != NULL);
    struct dirent *entry;
    char number[16];
    snprintf(number, sizeof(number), "%d", file);
    while ((entry = readdir(descriptors)) != NULL) {
        listed_file |= strcmp(entry->d_name, number) == 0 && entry->d_type == DT_LNK;
        listed_stdin |= strcmp(entry->d_name, "0") == 0;
    }
    assert(listed_file && listed_stdin && closedir(descriptors) == 0);
    check_descriptor_listing(file);
    assert(close(file) == 0 && unlink(name) == 0);
    assert(stat(path, &followed) == -1 && errno == ENOENT);
    assert(readlink(path, target, sizeof(target)) == -1 && errno == ENOENT);
    assert(open(path, O_RDONLY) == -1 && errno == ENOENT);
    const char *malformed[] = {"00", "03", "+3", "-1", "x", "2147483648"};
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
        snprintf(other, sizeof(other), "/proc/self/fd/%s", malformed[i]);
        assert(stat(other, &followed) == -1 && errno == ENOENT);
    }
}

// Checks that a child execs in its parent's process directory, which only the parent can see on
// LiteBox, both in place and from a `vfork` child, which LiteBox starts in a new runner.
static void check_exec_in_parent_directory(void) {
    char original[4096];
    assert(getcwd(original, sizeof(original)) != NULL && chdir("/proc/self") == 0);
    for (int use_vfork = 0; use_vfork < 2; use_vfork++) {
        pid_t child = use_vfork ? vfork() : fork();
        assert(child >= 0);
        if (child == 0) {
            execl("/proc/self/exe", "/proc/self/exe", "parent-cwd", NULL);
            _exit(127);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    assert(chdir(original) == 0);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "parent-cwd") == 0) {
        check_self();
        return 0;
    }
    check_self();
    check_cwd();
    check_limits();
    check_limits_reposition();
    check_mutations();
    check_directory_copy_fault();
    check_status(1);
    ino_t image = check_image();
    struct stat named;
    assert(stat(argv[0], &named) == 0 && named.st_ino == image);
    if (argc > 1 && strcmp(argv[1], "image") == 0) {
        int held = open("/proc/self/exe", O_RDONLY);
        assert(held >= 0);
        assert(rename("/tmp/procfs-image", "/tmp/renamed-image") == 0);
        char display[128];
        ssize_t length = readlink("/proc/self/exe", display, sizeof(display));
        const char *renamed = "/tmp/renamed-image";
        assert(length == (ssize_t)strlen(renamed) && memcmp(display, renamed, length) == 0);
        int replacement = open("/tmp/procfs-image", O_WRONLY | O_CREAT | O_EXCL, 0755);
        char invalid[128] = {0};
        assert(replacement >= 0);
        assert(write(replacement, invalid, sizeof(invalid)) == sizeof(invalid));
        assert(close(replacement) == 0);
        assert(unlink("/tmp/renamed-image") == 0);
        length = readlink("/proc/self/exe", display, sizeof(display));
        const char *deleted = "/tmp/renamed-image (deleted)";
        assert(length == (ssize_t)strlen(deleted) && memcmp(display, deleted, length) == 0);
        assert(stat("/tmp/procfs-image", &named) == 0 && named.st_ino != image);
        assert(check_image() == image);
        execl("/tmp/procfs-image", "/tmp/procfs-image", NULL);
        assert(errno == ENOEXEC);
        assert(check_image() == image);
        char magic[4];
        assert(read(held, magic, sizeof(magic)) == sizeof(magic));
        assert(memcmp(magic, "\177ELF", sizeof(magic)) == 0);
        assert(close(held) == 0);
        execl("/proc/self/exe", "/proc/self/exe", "retained", NULL);
        assert(!"retained executable exec failed");
    }
    if (argc > 1) {
        puts("procfs: OK");
        return 0;
    }
    char original[4096];
    assert(getcwd(original, sizeof(original)) != NULL);
    assert(chdir("/tmp") == 0);
    check_cwd();
    int root = open("/", O_RDONLY | O_DIRECTORY);
    assert(root >= 0);
    assert(fchdir(root) == 0 && close(root) == 0);
    check_cwd();
    // A vfork child has its own working directory, so changing it leaves the parent's alone.
    pid_t child = vfork();
    assert(child >= 0);
    if (child == 0) {
        _exit(chdir("/tmp") == 0 ? 0 : 1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char cwd[4096];
    assert(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/") == 0);
    check_cwd();

    check_status_changes();
    check_descriptors();
    check_exec_in_parent_directory();

    struct rlimit core = {.rlim_cur = 1234, .rlim_max = 5678};
    assert(setrlimit(RLIMIT_CORE, &core) == 0);
    check_limits();

    assert(chdir("/tmp") == 0);
    copy_to_new_file("/proc/self/exe", "/tmp/procfs-image", 0755);
    struct stat through_link, copied;
    assert(stat("/proc/self/cwd/procfs-image", &through_link) == 0);
    assert(stat("/tmp/procfs-image", &copied) == 0 && through_link.st_ino == copied.st_ino);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        check_self();
        // The child starts in its parent's working directory, which exec keeps.
        assert(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/tmp") == 0);
        check_cwd();
        assert(chdir("/") == 0);
        check_cwd();
        struct rlimit inherited;
        assert(getrlimit(RLIMIT_CORE, &inherited) == 0 && inherited.rlim_max == 5678);
        check_limits();
        check_status(1);
        assert(check_image() == image);
        execl("/tmp/procfs-image", "/tmp/procfs-image", "image", NULL);
        assert(!"child exec failed");
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, "/tmp") == 0);
    check_cwd();
    assert(chdir(original) == 0);
    check_cwd();
    assert(check_image() == image);
    execl(argv[0], argv[0], "exec", NULL);
    assert(!"exec failed");
}
