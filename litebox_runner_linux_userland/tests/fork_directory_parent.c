// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that a forked child shares its parent's directory position: the child continues where the
// parent stopped, and the parent continues where the child stopped.

#include "helpers.h"

#include <dirent.h>

#define TEST_DIR "/tmp/lb_fork_directory"
#define NAME_CAPACITY 32
#define ENTRY_COUNT 6
#define CHILD_READS 2

static const char *const EXPECTED[ENTRY_COUNT] = {".", "..", "a", "b", "c", "d"};

// Reads the next entry's name, returning 0 at the end of the directory. The buffer holds one
// entry with a short name but not two.
static int read_one(int fd, char name[NAME_CAPACITY]) {
    char buffer[40];
    ssize_t bytes_read = getdents64(fd, buffer, sizeof(buffer));
    TEST_ASSERT(bytes_read >= 0, "getdents64 failed");
    if (bytes_read == 0) {
        return 0;
    }
    struct dirent64 *entry = (struct dirent64 *)buffer;
    TEST_ASSERT(entry->d_reclen == bytes_read, "expected exactly one directory entry");
    TEST_ASSERT(strlen(entry->d_name) < NAME_CAPACITY, "directory entry name is too long");
    strcpy(name, entry->d_name);
    return 1;
}

int main(void) {
    TEST_ASSERT(mkdir(TEST_DIR, 0700) == 0, "create test directory failed");
    for (size_t i = 2; i < ENTRY_COUNT; i++) {
        char path[64];
        snprintf(path, sizeof(path), TEST_DIR "/%s", EXPECTED[i]);
        create_test_file(path, 0600);
    }

    int dir_fd = open(TEST_DIR, O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dir_fd >= 0, "open test directory failed");
    char seen[ENTRY_COUNT][NAME_CAPACITY];
    size_t count = 0;
    TEST_ASSERT(read_one(dir_fd, seen[count]), "parent read no entry");
    count++;

    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe failed");
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork failed");
    if (child == 0) {
        close(pipe_fds[0]);
        char names[CHILD_READS][NAME_CAPACITY] = {0};
        for (size_t i = 0; i < CHILD_READS; i++) {
            TEST_ASSERT(read_one(dir_fd, names[i]), "child read no entry");
        }
        off_t position = lseek(dir_fd, 0, SEEK_CUR);
        TEST_ASSERT(position >= 0, "child directory position failed");
        TEST_ASSERT(write(pipe_fds[1], &position, sizeof(position)) == sizeof(position),
                    "child position write failed");
        TEST_ASSERT(write(pipe_fds[1], names, sizeof(names)) == sizeof(names),
                    "child names write failed");
        _exit(0);
    }
    close(pipe_fds[1]);

    off_t child_position;
    read_exact_bytes(pipe_fds[0], &child_position, sizeof(child_position));
    read_exact_bytes(pipe_fds[0], seen[count], CHILD_READS * NAME_CAPACITY);
    count += CHILD_READS;
    int status;
    TEST_ASSERT(waitpid(child, &status, 0) == child, "waitpid failed");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child failed");
    TEST_ASSERT(lseek(dir_fd, 0, SEEK_CUR) == child_position,
                "parent should observe the child's directory position");

    while (count < ENTRY_COUNT && read_one(dir_fd, seen[count])) {
        count++;
    }
    char extra[NAME_CAPACITY];
    TEST_ASSERT(count == ENTRY_COUNT && !read_one(dir_fd, extra),
                "parent and child should together read each entry once");
    for (size_t i = 0; i < ENTRY_COUNT; i++) {
        size_t matches = 0;
        for (size_t j = 0; j < ENTRY_COUNT; j++) {
            matches += strcmp(EXPECTED[i], seen[j]) == 0;
        }
        TEST_ASSERT(matches == 1, "an entry was skipped or repeated");
    }

    TEST_ASSERT(close(dir_fd) == 0, "close directory failed");
    for (size_t i = 2; i < ENTRY_COUNT; i++) {
        char path[64];
        snprintf(path, sizeof(path), TEST_DIR "/%s", EXPECTED[i]);
        TEST_ASSERT(unlink(path) == 0, "remove test file failed");
    }
    TEST_ASSERT(rmdir(TEST_DIR) == 0, "remove test directory failed");
    printf("fork-directory shared=1\n");
    return 0;
}
