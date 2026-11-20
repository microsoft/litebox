// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <dirent.h>
#include <sys/mount.h>

static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

// A mount over an ancestor of the cwd and of held directories leaves them on the covered
// directories. Runs in the working directory `directory`.
static void test_mount_over_held_ancestor(const char *directory) {
    TEST_ASSERT(mkdir("shadow", 0700) == 0 && mkdir("shadow/sub", 0700) == 0,
                "create covered tree");
    struct stat shadow, sub, root, st;
    TEST_ASSERT(stat("shadow", &shadow) == 0 && stat("shadow/sub", &sub) == 0,
                "stat covered tree");
    int covered = open("shadow", O_PATH | O_DIRECTORY);
    int fd = open("shadow/sub", O_PATH | O_DIRECTORY);
    TEST_ASSERT(covered >= 0 && fd >= 0 && chdir("shadow/sub") == 0, "hold covered tree");
    char path[4096], cwd[4096];
    snprintf(path, sizeof(path), "%s/shadow", directory);
    TEST_ASSERT(mount(NULL, path, "tmpfs", 0, NULL) == 0, "mount over held ancestor");
    TEST_ASSERT(stat(path, &root) == 0 && root.st_dev != shadow.st_dev,
                "mountpoint path names the mount");
    snprintf(path, sizeof(path), "%s/shadow/sub", directory);
    // Linux: d_path() of the cwd, which stays (outer mount, covered sub), names the covered path.
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) != NULL && strcmp(cwd, path) == 0,
                "getcwd names the covered cwd");
    TEST_ASSERT(stat(".", &st) == 0 && same_file(&st, &sub), "dot is the covered cwd");
    TEST_ASSERT(fstatat(fd, ".", &st, 0) == 0 && same_file(&st, &sub),
                "dot is the covered held directory");
    TEST_ASSERT(fstatat(covered, ".", &st, 0) == 0 && same_file(&st, &shadow),
                "held mountpoint stays on the covered directory");
    TEST_ASSERT(fstatat(covered, "sub", &st, 0) == 0 && same_file(&st, &sub),
                "held mountpoint still reaches covered entries");
    // Linux: handle_dots() passes the parent to step_into(), which crosses mounts on it, so
    // `..` from below a covered directory lands on the covering mount's root.
    int up = openat(fd, "..", O_PATH | O_DIRECTORY);
    TEST_ASSERT(up >= 0 && fstat(up, &st) == 0 && same_file(&st, &root) && close(up) == 0,
                "dot-dot from held directory crosses into the covering mount");
    TEST_ASSERT(stat("..", &st) == 0 && same_file(&st, &root),
                "dot-dot from cwd crosses into the covering mount");
    expect_errno(stat("../sub", &st), ENOENT, "covered entries are hidden past dot-dot");
    TEST_ASSERT(close(fd) == 0 && close(covered) == 0 && chdir(directory) == 0,
                "leave covered tree");
}

// `..` from a mount root leaves the mount, and a lookup from a directory held since before a
// mount crosses into it. Expects `target` to be mounted. Runs in the working directory
// `directory`.
static void test_mount_boundaries(const char *directory) {
    struct stat outer, root, covered, st;
    TEST_ASSERT(stat(".", &outer) == 0 && stat("target", &root) == 0, "stat mount and parent");
    int mount_root = open("target", O_PATH | O_DIRECTORY);
    TEST_ASSERT(mount_root >= 0 && fstat(mount_root, &st) == 0 && same_file(&st, &root),
                "open mount root");
    // Linux: follow_dotdot() steps from a mount root to its mountpoint, then to its parent.
    int up = openat(mount_root, "..", O_PATH | O_DIRECTORY);
    TEST_ASSERT(up >= 0 && fstat(up, &st) == 0 && same_file(&st, &outer) && close(up) == 0,
                "dot-dot from mount root reaches outer directory");
    TEST_ASSERT(fstatat(mount_root, "../target", &st, 0) == 0 && same_file(&st, &root) &&
                close(mount_root) == 0, "dot-dot then mountpoint re-enters the mount");

    TEST_ASSERT(mkdir("held", 0700) == 0 && mkdir("held/t", 0700) == 0, "create held tree");
    int held = open("held", O_PATH | O_DIRECTORY);
    int below = open("held/t", O_PATH | O_DIRECTORY);
    TEST_ASSERT(held >= 0 && below >= 0 && stat("held/t", &covered) == 0, "hold tree");
    // The held directory moves first, so the mount is found from where it is, not from the name
    // it was opened by.
    TEST_ASSERT(rename("held", "moved") == 0, "move held tree");
    char path[4096];
    snprintf(path, sizeof(path), "%s/moved/t", directory);
    TEST_ASSERT(mount(NULL, path, "tmpfs", 0, NULL) == 0, "mount below held directory");
    TEST_ASSERT(stat("moved/t", &root) == 0 && root.st_dev != covered.st_dev,
                "mountpoint path names the mount");
    // Linux: walking `t` from the held directory crosses the mount added since it was opened.
    int file = openat(held, "t/x", O_CREAT | O_EXCL | O_WRONLY, 0600);
    TEST_ASSERT(file >= 0 && fstat(file, &st) == 0 && st.st_dev == root.st_dev &&
                close(file) == 0, "creation through held directory lands in the mount");
    TEST_ASSERT(stat("moved/t/x", &st) == 0 && st.st_dev == root.st_dev,
                "created file is visible in the mount");
    expect_errno(fstatat(below, "x", &st, 0), ENOENT, "covered directory is untouched");
    TEST_ASSERT(unlinkat(held, "t/x", 0) == 0 && close(below) == 0 && close(held) == 0,
                "cleanup held tree");
}

int main(void) {
    char *directory = mkdtemp(test_path("lb_mount_XXXXXX"));
    TEST_ASSERT(directory != NULL && chdir(directory) == 0, "enter mount test directory");
    TEST_ASSERT(mkdir("target", 0700) == 0, "create mountpoint");
    int old = open("target/old", O_CREAT | O_RDWR, 0600);
    TEST_ASSERT(old >= 0 && write(old, "old", 3) == 3, "populate covered directory");
    struct stat before, after;
    TEST_ASSERT(stat("target", &before) == 0, "stat before mount");

    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "lb_nonexistent_fs", 0, NULL) == -1 && errno == ENODEV,
                "reject unknown filesystem");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target", "tmpfs", MS_BIND, NULL) == -1 && errno == EINVAL,
                "require source for bind mount");
    errno = 0;
    TEST_ASSERT(mount(NULL, "missing", "tmpfs", 0, NULL) == -1 && errno == ENOENT,
                "require existing mountpoint");
    errno = 0;
    TEST_ASSERT(mount(NULL, "target/old", "tmpfs", 0, NULL) == -1 && errno == ENOTDIR,
                "require directory mountpoint");
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
    TEST_ASSERT(unlink("target/new") == 0, "unlink mounted file");
    errno = 0;
    TEST_ASSERT(rmdir("target") == -1 && (errno == EBUSY || errno == EROFS),
                "mountpoint cannot be removed");
    TEST_ASSERT(stat("target", &after) == 0 && before.st_dev != after.st_dev,
                "target remains mounted");
    // LiteBox has no umount, so the mounts stay until the guest exits.
    test_mount_boundaries(directory);
    test_mount_over_held_ancestor(directory);
    puts("mount tmpfs ok");
    return 0;
}
