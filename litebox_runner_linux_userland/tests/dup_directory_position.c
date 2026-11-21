// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <stdint.h>

#ifndef SYS_getdents64
#error SYS_getdents64 is not defined on this build host
#endif

#define TEST_DIR_NAME "lb_dup_directory_position"
#define GETDENTS_BUFFER_SIZE 48
#define MAX_CHUNK_ENTRIES 2
#define NAME_CAPACITY 32

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
} __attribute__((packed));

struct name_chunk {
    char names[MAX_CHUNK_ENTRIES][NAME_CAPACITY];
    size_t count;
    int64_t next_offset;
};

// Returns an empty chunk at end of directory.
static struct name_chunk read_names_or_eof(int fd) {
    char buffer[GETDENTS_BUFFER_SIZE];
    long bytes_read = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
    TEST_ASSERT(bytes_read >= 0 && bytes_read <= (long)sizeof(buffer),
                "getdents64 failed");

    struct name_chunk chunk = {0};
    size_t offset = 0;
    while (offset < (size_t)bytes_read) {
        struct linux_dirent64 *entry =
            (struct linux_dirent64 *)(buffer + offset);
        TEST_ASSERT(entry->d_reclen >= sizeof(*entry) + 1,
                    "invalid directory entry length");
        TEST_ASSERT(entry->d_reclen % 8 == 0, "record is not 8-byte aligned");
        TEST_ASSERT(offset + entry->d_reclen <= (size_t)bytes_read,
                    "directory entry exceeds returned data");
        TEST_ASSERT(chunk.count < MAX_CHUNK_ENTRIES,
                    "unexpected number of directory entries");

        size_t name_capacity = entry->d_reclen - sizeof(*entry);
        const char *name_end = memchr(entry->d_name, '\0', name_capacity);
        TEST_ASSERT(name_end != NULL, "directory entry name is not terminated");
        size_t name_length = (size_t)(name_end - entry->d_name);
        TEST_ASSERT(name_length < NAME_CAPACITY, "directory entry name is too long");
        memcpy(chunk.names[chunk.count], entry->d_name, name_length);
        chunk.names[chunk.count][name_length] = '\0';
        chunk.count++;
        chunk.next_offset = entry->d_off;
        offset += entry->d_reclen;
    }
    TEST_ASSERT(offset == (size_t)bytes_read, "invalid directory entry data");
    return chunk;
}

static struct name_chunk read_names(int fd) {
    struct name_chunk chunk = read_names_or_eof(fd);
    TEST_ASSERT(chunk.count > 0, "unexpected end of directory");
    return chunk;
}

static int chunks_are_disjoint(const struct name_chunk *left,
                               const struct name_chunk *right) {
    for (size_t i = 0; i < left->count; i++) {
        for (size_t j = 0; j < right->count; j++) {
            if (strcmp(left->names[i], right->names[j]) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

static int chunks_have_same_names(const struct name_chunk *left,
                                  const struct name_chunk *right) {
    if (left->count != right->count) {
        return 0;
    }
    for (size_t i = 0; i < left->count; i++) {
        int found = 0;
        for (size_t j = 0; j < right->count; j++) {
            if (strcmp(left->names[i], right->names[j]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return 0;
        }
    }
    return 1;
}

static void create_entries(void) {
    TEST_ASSERT(mkdir(test_path(TEST_DIR_NAME), 0700) == 0, "create test directory failed");
    create_test_file(test_path(TEST_DIR_NAME "/a"), 0600);
    create_test_file(test_path(TEST_DIR_NAME "/b"), 0600);
    create_test_file(test_path(TEST_DIR_NAME "/c"), 0600);
    create_test_file(test_path(TEST_DIR_NAME "/directory-entry"), 0600);
}

#define ENTRY_COUNT 6

static const char *const entry_names[ENTRY_COUNT] = {".", "..", "a", "b", "c",
                                                     "directory-entry"};

// Directory order is filesystem-defined, so only check that each entry is seen exactly once.
static void mark_seen(int seen[ENTRY_COUNT], const struct name_chunk *chunk) {
    for (size_t i = 0; i < chunk->count; i++) {
        int found = 0;
        for (size_t j = 0; j < ENTRY_COUNT; j++) {
            if (strcmp(chunk->names[i], entry_names[j]) == 0) {
                TEST_ASSERT(!seen[j], "directory entry returned twice");
                seen[j] = 1;
                found = 1;
            }
        }
        TEST_ASSERT(found, "unexpected directory entry");
    }
}

static size_t seen_count(const int seen[ENTRY_COUNT]) {
    size_t count = 0;
    for (size_t i = 0; i < ENTRY_COUNT; i++) {
        count += seen[i];
    }
    return count;
}

static int is_dot(const char *name) {
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static void remove_entry(const char *entry) {
    char name[sizeof(TEST_DIR_NAME) + NAME_CAPACITY];
    snprintf(name, sizeof(name), TEST_DIR_NAME "/%s", entry);
    TEST_ASSERT(unlink(test_path(name)) == 0, "remove entry failed");
}

// Removing names between reads must neither skip nor repeat any name that was not removed.
static void check_delete(int dir_fd, const struct name_chunk *replay) {
    int seen[ENTRY_COUNT] = {0};
    mark_seen(seen, replay);
    int removed[ENTRY_COUNT] = {0};
    for (size_t i = 2; i < ENTRY_COUNT; i++) {
        if (seen[i]) {
            remove_entry(entry_names[i]);
            removed[i] = 1;
        }
    }
    // Also remove one unread name; POSIX leaves whether it is still returned unspecified.
    for (size_t i = 2; i < ENTRY_COUNT; i++) {
        if (!seen[i]) {
            remove_entry(entry_names[i]);
            removed[i] = 1;
            break;
        }
    }

    for (;;) {
        struct name_chunk chunk = read_names_or_eof(dir_fd);
        if (chunk.count == 0) {
            break;
        }
        mark_seen(seen, &chunk);
    }
    for (size_t i = 0; i < ENTRY_COUNT; i++) {
        TEST_ASSERT(seen[i] || removed[i], "remaining directory entry was skipped");
    }
}

// Reads the next chunk through `fd`, which a forked or executed child inherited, and sends it to
// the parent through `pipe_fd`.
static void report_child_chunk(int fd, int64_t expected_offset, int pipe_fd) {
    TEST_ASSERT(lseek(fd, 0, SEEK_CUR) == expected_offset,
                "child did not inherit the directory position");
    struct name_chunk after = read_names(fd);
    TEST_ASSERT(lseek(fd, 0, SEEK_CUR) == after.next_offset,
                "d_off does not name the position after the record");
    TEST_ASSERT(write(pipe_fd, &after, sizeof(after)) == sizeof(after),
                "send child entries failed");
    _exit(0);
}

// Checks a child's reads through its inherited descriptor; the child execs `self` if non-NULL.
static void check_child(int dir_fd, int dup_fd, const struct name_chunk *replay,
                        const char *self) {
    int seen[ENTRY_COUNT] = {0};
    mark_seen(seen, replay);
    struct name_chunk before = read_names(dir_fd);
    mark_seen(seen, &before);
    // Only already-returned names are removed: POSIX leaves it unspecified whether unread
    // removed names are returned, but every untouched name must still appear exactly once.
    for (size_t i = 0; i < before.count; i++) {
        if (!is_dot(before.names[i])) {
            remove_entry(before.names[i]);
        }
    }

    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe failed");
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork with a positioned directory failed");
    if (child == 0) {
        if (self != NULL) {
            char fd_arg[16], offset_arg[32], pipe_arg[16];
            snprintf(fd_arg, sizeof(fd_arg), "%d", dup_fd);
            snprintf(offset_arg, sizeof(offset_arg), "%lld", (long long)before.next_offset);
            snprintf(pipe_arg, sizeof(pipe_arg), "%d", pipe_fds[1]);
            char *child_argv[] = {(char *)self, "exec-child", fd_arg, offset_arg, pipe_arg,
                                  NULL};
            execv(self, child_argv);
            _exit(111);
        }
        report_child_chunk(dup_fd, before.next_offset, pipe_fds[1]);
    }
    TEST_ASSERT(close(pipe_fds[1]) == 0, "close pipe writer failed");
    int status;
    TEST_ASSERT(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                    WEXITSTATUS(status) == 0,
                "child failed to resume the directory listing");
    struct name_chunk after;
    TEST_ASSERT(read(pipe_fds[0], &after, sizeof(after)) == sizeof(after),
                "receive child entries failed");
    TEST_ASSERT(close(pipe_fds[0]) == 0, "close pipe reader failed");
    TEST_ASSERT(lseek(dir_fd, 0, SEEK_CUR) == after.next_offset,
                "parent did not observe the child's directory reads");
    mark_seen(seen, &after);

    while (seen_count(seen) < ENTRY_COUNT) {
        struct name_chunk tail = read_names(dir_fd);
        mark_seen(seen, &tail);
    }
    TEST_ASSERT(syscall(SYS_getdents64, dir_fd, NULL, 0) == 0,
                "expected EOF after all records were read");
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "exec-child") == 0) {
        report_child_chunk(atoi(argv[2]), strtoll(argv[3], NULL, 10), atoi(argv[4]));
    }
    create_entries();

    int dir_fd = open(test_path(TEST_DIR_NAME), O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dir_fd >= 0, "open test directory failed");
    int dup_fd = dup(dir_fd);
    TEST_ASSERT(dup_fd >= 0, "duplicate directory descriptor failed");

    char too_small[23];
    TEST_ASSERT(syscall(SYS_getdents64, dir_fd, too_small, sizeof(too_small)) == -1 &&
                    errno == EINVAL,
                "getdents64 accepted a buffer smaller than one aligned record");
    // Linux leaves the position after a rejected short buffer filesystem-defined (ext4 moves it).
    TEST_ASSERT(lseek(dir_fd, 0, SEEK_SET) == 0, "rewind directory failed");
    struct name_chunk first = read_names(dir_fd);
    off_t position_after_first = lseek(dir_fd, 0, SEEK_CUR);
    TEST_ASSERT(position_after_first >= 0, "read original directory position failed");
    TEST_ASSERT(lseek(dup_fd, 0, SEEK_CUR) == position_after_first,
                "duplicate should observe original directory position");
    struct name_chunk second = read_names(dup_fd);
    TEST_ASSERT(chunks_are_disjoint(&first, &second),
                "duplicate repeated the original directory entries");
    off_t position_after_second = lseek(dup_fd, 0, SEEK_CUR);
    TEST_ASSERT(position_after_second >= 0, "read duplicate directory position failed");
    TEST_ASSERT(lseek(dir_fd, 0, SEEK_CUR) == position_after_second,
                "original should observe duplicate directory position");

    TEST_ASSERT(lseek(dup_fd, 0, SEEK_SET) == 0,
                "reset duplicate directory position failed");
    TEST_ASSERT(lseek(dir_fd, 0, SEEK_CUR) == 0,
                "original should observe reset directory position");
    struct name_chunk replay = read_names(dir_fd);
    TEST_ASSERT(chunks_have_same_names(&first, &replay),
                "reset directory position should replay the first entries");

    if (argc > 1 && strcmp(argv[1], "fork") == 0) {
        check_child(dir_fd, dup_fd, &replay, NULL);
    } else if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        check_child(dir_fd, dup_fd, &replay, argv[0]);
    } else {
        check_delete(dir_fd, &replay);
    }
    TEST_ASSERT(close(dup_fd) == 0, "close duplicate failed");
    TEST_ASSERT(close(dir_fd) == 0, "close directory failed");
    for (size_t i = 2; i < ENTRY_COUNT; i++) {
        char name[sizeof(TEST_DIR_NAME) + NAME_CAPACITY];
        snprintf(name, sizeof(name), TEST_DIR_NAME "/%s", entry_names[i]);
        TEST_ASSERT(unlink(test_path(name)) == 0 || errno == ENOENT, "remove test file failed");
    }
    TEST_ASSERT(rmdir(test_path(TEST_DIR_NAME)) == 0, "remove test directory failed");
    printf("duplicated directory descriptors share position: PASS\n");
    return 0;
}