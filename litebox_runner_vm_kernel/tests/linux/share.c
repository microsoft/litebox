// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A host directory over virtio-9p, read-only at /mnt/host (see
// dev_tools/run_linux_on_vm_userland.sh): reads the host's greeting.txt; its
// symlink link.txt and greeting.txt through it; greeting.txt through the
// symlink self (to .) within the path; and the symlink abs.txt, to
// /mnt/host/greeting.txt, and greeting.txt through it, as its absolute target
// resolves from the guest's root, not the share's. Lists the directory;
// writing, creating, and removing fail with EROFS, but, as on a Linux
// read-only mount, creating an existing name fails with EEXIST first, and
// opening an existing file read-only with O_CREAT succeeds.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *what) {
    perror(what);
    return 1;
}

// Whether `result` is a failure with `expected`.
static int fails_with(int result, int expected, const char *what) {
    if (result >= 0 || errno != expected) {
        fprintf(stderr, "%s: not errno %d (result %d, errno %d)\n", what, expected, result,
                errno);
        return 0;
    }
    return 1;
}

static int read_only(int result, const char *what) { return fails_with(result, EROFS, what); }

// Copies the file at `path` to stdout.
static int cat(const char *path) {
    char buf[256];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return fail(path);
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    if (n < 0) return fail(path);
    close(fd);
    return 0;
}

// Prints the target of the share's symlink `name`.
static int print_link(const char *name) {
    char path[256], target[256];
    snprintf(path, sizeof path, "/mnt/host/%s", name);
    ssize_t length = readlink(path, target, sizeof target - 1);
    if (length < 0) return fail(path);
    target[length] = '\0';
    printf("%s -> %s\n", name, target);
    return 0;
}

int main(void) {
    if (cat("/mnt/host/greeting.txt") != 0 || print_link("link.txt") != 0 ||
        cat("/mnt/host/link.txt") != 0 || cat("/mnt/host/self/greeting.txt") != 0 ||
        print_link("abs.txt") != 0 || cat("/mnt/host/abs.txt") != 0)
        return 1;

    DIR *dir = opendir("/mnt/host");
    if (dir == NULL) return fail("opendir");
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) found |= strcmp(entry->d_name, "greeting.txt") == 0;
    closedir(dir);
    if (!found) {
        fprintf(stderr, "greeting.txt not listed\n");
        return 1;
    }

    if (!read_only(open("/mnt/host/greeting.txt", O_WRONLY), "open for writing") ||
        !read_only(open("/mnt/host/new.txt", O_WRONLY | O_CREAT, 0644), "create") ||
        !read_only(mkdir("/mnt/host/dir", 0755), "mkdir") ||
        !read_only(unlink("/mnt/host/greeting.txt"), "unlink") ||
        // The 9P backend itself would panic the kernel on this one.
        !read_only(open("/mnt/host", O_WRONLY), "open the directory for writing") ||
        !fails_with(mkdir("/mnt/host/greeting.txt", 0755), EEXIST, "mkdir an existing name") ||
        !fails_with(symlink("x", "/mnt/host/link.txt"), EEXIST, "symlink an existing name") ||
        !fails_with(open("/mnt/host/greeting.txt", O_RDONLY | O_CREAT | O_EXCL, 0644), EEXIST,
                    "create an existing file exclusively"))
        return 1;
    int fd = open("/mnt/host/greeting.txt", O_RDONLY | O_CREAT, 0644);
    if (fd < 0) return fail("open an existing file read-only with O_CREAT");
    close(fd);
    printf("read-only\n");
    return 0;
}
