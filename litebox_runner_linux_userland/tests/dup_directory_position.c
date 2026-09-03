// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <stdint.h>

#ifndef SYS_getdents64
#error SYS_getdents64 is not defined on this build host
#endif

#define TEST_DIR "/tmp/lb_dup_directory_position"
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
};

static struct name_chunk read_names(int fd) {
    char buffer[GETDENTS_BUFFER_SIZE];
    long bytes_read = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
    TEST_ASSERT(bytes_read > 0 && bytes_read <= (long)sizeof(buffer),
                "getdents64 failed");

    struct name_chunk chunk = {0};
    size_t offset = 0;
    while (offset < (size_t)bytes_read) {
        struct linux_dirent64 *entry =
            (struct linux_dirent64 *)(buffer + offset);
        TEST_ASSERT(entry->d_reclen >= sizeof(*entry) + 1,
                    "invalid directory entry length");
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
        offset += entry->d_reclen;
    }
    TEST_ASSERT(offset == (size_t)bytes_read, "invalid directory entry data");
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
    TEST_ASSERT(mkdir(TEST_DIR, 0700) == 0, "create test directory failed");
    create_test_file(TEST_DIR "/a", 0600);
    create_test_file(TEST_DIR "/b", 0600);
    create_test_file(TEST_DIR "/c", 0600);
    create_test_file(TEST_DIR "/d", 0600);
}

static void cleanup(void) {
    TEST_ASSERT(unlink(TEST_DIR "/a") == 0, "remove a failed");
    TEST_ASSERT(unlink(TEST_DIR "/b") == 0, "remove b failed");
    TEST_ASSERT(unlink(TEST_DIR "/c") == 0, "remove c failed");
    TEST_ASSERT(unlink(TEST_DIR "/d") == 0, "remove d failed");
    TEST_ASSERT(rmdir(TEST_DIR) == 0, "remove test directory failed");
}

int main(void) {
    create_entries();

    int dir_fd = open(TEST_DIR, O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dir_fd >= 0, "open test directory failed");
    int dup_fd = dup(dir_fd);
    TEST_ASSERT(dup_fd >= 0, "duplicate directory descriptor failed");

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

    TEST_ASSERT(close(dup_fd) == 0, "close duplicate failed");
    TEST_ASSERT(close(dir_fd) == 0, "close directory failed");
    cleanup();
    printf("duplicated directory descriptors share position: PASS\n");
    return 0;
}