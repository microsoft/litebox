// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A host directory over virtio-9p, read-only at /mnt/host (see
// dev_tools/run_linux_on_vm_userland.sh): reads the host's greeting.txt and
// lists the directory; writing, creating, and removing fail with EROFS.

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

static int read_only(int result, const char *what) {
    if (result >= 0 || errno != EROFS) {
        fprintf(stderr, "%s: not EROFS (result %d, errno %d)\n", what, result, errno);
        return 0;
    }
    return 1;
}

int main(void) {
    char buf[256];
    int fd = open("/mnt/host/greeting.txt", O_RDONLY);
    if (fd < 0) return fail("open greeting.txt");
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    if (n < 0) return fail("read greeting.txt");
    close(fd);

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
        !read_only(open("/mnt/host", O_WRONLY), "open the directory for writing"))
        return 1;
    printf("read-only\n");
    return 0;
}
