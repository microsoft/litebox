// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <dirent.h>
#include <sys/mount.h>

int main(void) {
    char temporary[] = "/tmp/lb_mount_XXXXXX";
    char *directory = mkdtemp(temporary);
    TEST_ASSERT(directory != NULL && chdir(directory) == 0, "enter mount test directory");
    TEST_ASSERT(mkdir("target", 0700) == 0, "create mountpoint");
    int old = open("target/old", O_CREAT | O_RDWR, 0600);
    TEST_ASSERT(old >= 0 && write(old, "old", 3) == 3, "populate covered directory");
    struct stat before, after;
    TEST_ASSERT(stat("target", &before) == 0, "stat before mount");

    if (geteuid() != 0) {
        errno = 0;
        TEST_ASSERT(mount(NULL, "/tmp", "tmpfs", 0, NULL) == -1 && errno == EPERM,
                    "reject foreign-owned mountpoint");
    }
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "proc", 0, NULL) == -1 && errno == ENODEV,
                "reject unsupported filesystem");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "tmpfs", MS_BIND, NULL) == -1 && errno == EINVAL,
                "reject bind mounts");
    errno = 0;
    TEST_ASSERT(mount(NULL, "missing", "tmpfs", 0, NULL) == -1 && errno == ENOENT,
                "require existing mountpoint");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target/old", "tmpfs", 0, NULL) == -1 && errno == ENOTDIR,
                "require directory mountpoint");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "tmpfs", MS_NOEXEC, NULL) == -1 && errno == EINVAL,
                "reject unenforced noexec restriction");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "tmpfs", 0, "mode=0700") == -1 && errno == EINVAL,
                "reject unsupported mount options");
    errno = 0;
    TEST_ASSERT(syscall(SYS_mount, NULL, "target", "tmpfs", 0, (void *)1) == -1 && errno == EFAULT,
                "validate optional data pointer");
    errno = 0;
    TEST_ASSERT(mount(NULL, NULL, "tmpfs", 0, NULL) == -1 && errno == EFAULT,
                "validate target pointer");
    TEST_ASSERT(symlink("target", "link") == 0, "create mountpoint symlink");
    TEST_ASSERT(syscall(SYS_mount, NULL, "link", "tmpfs", 0, NULL) == 0,
                "mount tmpfs through relative symlink");
    TEST_ASSERT(stat("target", &after) == 0 && before.st_dev != after.st_dev,
                "mounted filesystem has distinct device");
    TEST_ASSERT((after.st_mode & 07777) == 01777, "tmpfs default root mode");
    TEST_ASSERT(after.st_uid == geteuid() && after.st_gid == getegid(), "tmpfs belongs to mounter");
    errno = 0;
    TEST_ASSERT(stat("target/old", &after) == -1 && errno == ENOENT, "mount covers old files");
    char buffer[4] = {0};
    TEST_ASSERT(pread(old, buffer, 3, 0) == 3 && memcmp(buffer, "old", 3) == 0,
                "open file survives mount");
    TEST_ASSERT(close(old) == 0, "close covered file");

    int fd = open("target/new", O_CREAT | O_EXCL | O_RDWR, 0600);
    TEST_ASSERT(fd >= 0 && write(fd, "new", 3) == 3, "write mounted file");
    memset(buffer, 0, sizeof(buffer));
    TEST_ASSERT(pread(fd, buffer, 3, 0) == 3 && memcmp(buffer, "new", 3) == 0,
                "read mounted file");
    TEST_ASSERT(close(fd) == 0, "close mounted file");
    DIR *dir = opendir("target");
    TEST_ASSERT(dir != NULL, "open mounted directory");
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        found |= strcmp(entry->d_name, "new") == 0;
        TEST_ASSERT(strcmp(entry->d_name, "old") != 0, "listing hides covered files");
    }
    TEST_ASSERT(found && closedir(dir) == 0, "listing includes mounted file");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "tmpfs", 0, NULL) == -1 && errno == EBUSY,
                "reject mount stacking");
    errno = 0;
    TEST_ASSERT(rmdir("target") == -1 && errno == EROFS, "mountpoint cannot be removed");
    TEST_ASSERT(unlink("target/new") == 0, "unlink mounted file");
    puts("mount tmpfs ok");
    return 0;
}
