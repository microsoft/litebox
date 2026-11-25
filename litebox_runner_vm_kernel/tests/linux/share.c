// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The host directory read-only at /mnt/host, over virtio-fs (the virtiofs
// test). Reads files, through symlinks too (abs.txt's absolute target
// resolves from the guest's root, not the share's) and from a directory's
// descriptor (dir/sub's `../marker` is dir's), and big.bin, larger than a
// request carries;
// lists many/, more than a FUSE_READDIR reply (64 KiB) holds, and stats 200 of
// its files, more than a batch of FUSE forgets. Also checks a modification
// time and that the FIFO is hidden, as special files are.
// Writing, creating, and removing fail with EROFS, but, as on a Linux
// read-only mount, creating an existing name fails with EEXIST first, and
// opening an existing file read-only with O_CREAT succeeds.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

// Copies the file at `path`, from the directory `dir`, to stdout.
static int cat_at(int dir, const char *path) {
    char buf[256];
    int fd = openat(dir, path, O_RDONLY);
    if (fd < 0) return fail(path);
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) fwrite(buf, 1, n, stdout);
    if (n < 0) return fail(path);
    close(fd);
    return 0;
}

static int cat(const char *path) { return cat_at(AT_FDCWD, path); }

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

// Whether the `length` bytes in `buf` are those at `offset` of big.bin.
static int big_bytes(const unsigned char *buf, size_t length, off_t offset) {
    for (size_t i = 0; i < length; i++) {
        if (buf[i] != (unsigned char)((offset + i) % 251)) {
            fprintf(stderr, "big.bin: byte %lld is %u\n", (long long)(offset + i), buf[i]);
            return 0;
        }
    }
    return 1;
}

// Reads big.bin in reads larger than a request carries, then its end at an
// offset; prints its size.
static int read_big(void) {
    // More than the 1 MiB a virtio-fs request carries, and not a whole
    // number of pages.
    size_t chunk = (1 << 20) + 4099;
    unsigned char *buf = malloc(chunk);
    if (buf == NULL) return fail("malloc");
    int fd = open("/mnt/host/big.bin", O_RDONLY);
    if (fd < 0) return fail("big.bin");
    struct stat st;
    if (fstat(fd, &st) != 0) return fail("fstat big.bin");
    off_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf, chunk)) > 0) {
        if (!big_bytes(buf, n, total)) return 1;
        total += n;
    }
    if (n < 0) return fail("read big.bin");
    if (total != st.st_size || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "big.bin: read %lld bytes, stat says %lld\n", (long long)total,
                (long long)st.st_size);
        return 1;
    }
    if (lseek(fd, 0, SEEK_END) != total) return fail("lseek big.bin");
    n = pread(fd, buf, 100, total - 100);
    if (n != 100) return fail("pread big.bin");
    if (!big_bytes(buf, n, total - 100)) return 1;
    close(fd);
    free(buf);
    printf("big.bin: %lld bytes\n", (long long)total);
    return 0;
}

// Counts the entries of the directory `path`, but `.` and `..`, and whether
// it has `name`; -1 on errors.
static int count_entries(const char *path, const char *name, int *found) {
    DIR *dir = opendir(path);
    if (dir == NULL) {
        fail(path);
        return -1;
    }
    int count = 0;
    struct dirent *entry;
    // readdir's end leaves errno as it was; its errors set it.
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        count++;
        *found |= strcmp(entry->d_name, name) == 0;
    }
    if (errno != 0) {
        fail(path);
        closedir(dir);
        return -1;
    }
    closedir(dir);
    return count;
}

int main(void) {
    int sub = open("/mnt/host/dir/sub", O_RDONLY | O_DIRECTORY);
    if (sub < 0) return fail("dir/sub");
    if (cat("/mnt/host/greeting.txt") != 0 || print_link("link.txt") != 0 ||
        cat("/mnt/host/link.txt") != 0 || cat("/mnt/host/self/greeting.txt") != 0 ||
        print_link("abs.txt") != 0 || cat("/mnt/host/abs.txt") != 0 ||
        cat("/mnt/host/dir/sub/deep.txt") != 0 || cat_at(sub, "../marker") != 0 ||
        read_big() != 0)
        return 1;

    struct stat st;
    if (stat("/mnt/host/dir/sub", &st) != 0) return fail("stat dir/sub");
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "dir/sub is not a directory\n");
        return 1;
    }
    if (lstat("/mnt/host/link.txt", &st) != 0) return fail("lstat link.txt");
    if (!S_ISLNK(st.st_mode)) {
        fprintf(stderr, "link.txt is not a symlink\n");
        return 1;
    }
    if (stat("/mnt/host/link.txt", &st) != 0) return fail("stat link.txt");
    if (!S_ISREG(st.st_mode) || st.st_size != 20) {
        fprintf(stderr, "link.txt does not lead to a 20-byte file (size %lld)\n",
                (long long)st.st_size);
        return 1;
    }
    if (st.st_mtime != 1700000000) {
        fprintf(stderr, "greeting.txt: mtime %lld\n", (long long)st.st_mtime);
        return 1;
    }
    printf("mtime 1700000000\n");
    int listed = 0;
    if (count_entries("/mnt/host", "fifo", &listed) < 0) return 1;
    if (listed || !fails_with(stat("/mnt/host/fifo", &st), EINVAL, "stat the FIFO")) {
        fprintf(stderr, "the FIFO is not hidden\n");
        return 1;
    }
    printf("fifo hidden\n");
    int found = 0;
    if (count_entries("/mnt/host", "greeting.txt", &found) < 0) return 1;
    if (!found) {
        fprintf(stderr, "greeting.txt not listed\n");
        return 1;
    }
    found = 0;
    int many = count_entries("/mnt/host/many", "f2999", &found);
    if (many != 3000 || !found) {
        fprintf(stderr, "many: %d entries, f2999 %s\n", many, found ? "listed" : "not listed");
        return 1;
    }
    printf("many: %d entries\n", many);
    for (int i = 0; i < 200; i++) {
        char path[64];
        snprintf(path, sizeof path, "/mnt/host/many/f%04d", i);
        if (stat(path, &st) != 0) return fail(path);
        if (!S_ISREG(st.st_mode)) {
            fprintf(stderr, "%s is not a regular file\n", path);
            return 1;
        }
    }

    if (!read_only(open("/mnt/host/greeting.txt", O_WRONLY), "open for writing") ||
        !read_only(open("/mnt/host/new.txt", O_WRONLY | O_CREAT, 0644), "create") ||
        !read_only(mkdir("/mnt/host/dir2", 0755), "mkdir") ||
        !read_only(unlink("/mnt/host/greeting.txt"), "unlink") ||
        !read_only(rename("/mnt/host/greeting.txt", "/mnt/host/moved.txt"), "rename") ||
        !read_only(symlink("x", "/mnt/host/newlink"), "symlink") ||
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
