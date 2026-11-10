// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
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
    assert(open("/proc/self/exe", O_WRONLY) == -1 && errno == EROFS);
    assert(open("/proc/self/exe", O_RDONLY | O_TRUNC) == -1 && errno == EROFS);
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

static void copy_image(void) {
    int input = open("/proc/self/exe", O_RDONLY);
    int output = open("/tmp/procfs-image", O_WRONLY | O_CREAT | O_EXCL, 0755);
    assert(input >= 0 && output >= 0);
    char buffer[8192];
    ssize_t length;
    while ((length = read(input, buffer, sizeof(buffer))) > 0) {
        ssize_t written = 0;
        while (written < length) {
            ssize_t count = write(output, buffer + written, length - written);
            assert(count > 0);
            written += count;
        }
    }
    assert(length == 0);
    assert(close(input) == 0 && close(output) == 0);
}

int main(int argc, char **argv) {
    check_self();
    check_cwd();
    ino_t image = check_image();
    struct stat named;
    assert(stat(argv[0], &named) == 0 && named.st_ino == image);
    if (argc > 1 && strcmp(argv[1], "image") == 0) {
        int held = open("/proc/self/exe", O_RDONLY);
        assert(held >= 0);
        assert(rename("/tmp/procfs-image", "/tmp/renamed-image") == 0);
        int replacement = open("/tmp/procfs-image", O_WRONLY | O_CREAT | O_EXCL, 0755);
        char invalid[128] = {0};
        assert(replacement >= 0);
        assert(write(replacement, invalid, sizeof(invalid)) == sizeof(invalid));
        assert(close(replacement) == 0);
        assert(unlink("/tmp/renamed-image") == 0);
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

    assert(chdir("/tmp") == 0);
    copy_image();
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
