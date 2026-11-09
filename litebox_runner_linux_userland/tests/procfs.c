// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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

int main(int argc, char **argv) {
    check_self();
    if (argc > 1) {
        puts("procfs: OK");
        return 0;
    }
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        check_self();
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    execl(argv[0], argv[0], "exec", NULL);
    assert(!"exec failed");
}
