// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks mounts and mount namespaces: binds, `tmpfs`, read-only remounts, unmounting, propagation
// changes, `unshare` and `clone` with `CLONE_NEWNS`, `chroot`, `pivot_root` and runc's pivot
// sequence, `statfs`, and working directories left outside the root. Runs as guest root, and,
// with the argument `non-root`, as another user, who may not change mounts.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define DIR "/tmp/lb_mnt"
#define TMPFS_MAGIC 0x01021994

static int failures;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// Whether `call` failed with `error`.
#define FAILS_WITH(call, error) ((call) == -1 && errno == (error))

static int exists(const char *path) {
    struct stat status;
    return stat(path, &status) == 0;
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }
    ssize_t written = write(fd, data, strlen(data));
    close(fd);
    return written == (ssize_t)strlen(data) ? 0 : -1;
}

// Returns whether the file at `path` holds `expected`.
static int reads(const char *path, const char *expected) {
    char data[64] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    ssize_t length = read(fd, data, sizeof data - 1);
    close(fd);
    return length == (ssize_t)strlen(expected) && memcmp(data, expected, length) == 0;
}

static int tmpfs(const char *target, unsigned long flags, const char *data) {
    return mount("tmpfs", target, "tmpfs", flags, data);
}

// Returns whether the working directory, as the system call reports it, is `expected`.
static int cwd_is(const char *expected) {
    char cwd[4096];
    return syscall(SYS_getcwd, cwd, sizeof cwd) > 0 && strcmp(cwd, expected) == 0;
}

// Waits for `child` to exit with code 0.
static int exits_cleanly(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Runs `check` in a forked child, which fails if any of its checks do.
static void in_child(void (*check)(void)) {
    pid_t child = fork();
    if (child == 0) {
        failures = 0;
        check();
        _exit(failures != 0);
    }
    CHECK(exits_cleanly(child));
}

static void check_binds(void) {
    CHECK(mkdir(DIR "/src", 0755) == 0);
    CHECK(mkdir(DIR "/src/sub", 0755) == 0);
    CHECK(mkdir(DIR "/dst", 0755) == 0);
    CHECK(mkdir(DIR "/rdst", 0755) == 0);
    CHECK(write_file(DIR "/src/file", "bound") == 0);
    CHECK(tmpfs(DIR "/src/sub", 0, NULL) == 0);
    CHECK(write_file(DIR "/src/sub/inner", "inner") == 0);

    // A bind ignores the type and data, which runc passes as `bind`.
    CHECK(mount(DIR "/src", DIR "/dst", "bind", MS_BIND, "ignored") == 0);
    CHECK(reads(DIR "/dst/file", "bound"));
    CHECK(write_file(DIR "/dst/new", "shared") == 0);
    CHECK(reads(DIR "/src/new", "shared"));
    // Only a recursive bind shows the mounts below its source.
    CHECK(!exists(DIR "/dst/sub/inner"));
    CHECK(mount(DIR "/src", DIR "/rdst", NULL, MS_BIND | MS_REC, NULL) == 0);
    CHECK(reads(DIR "/rdst/sub/inner", "inner"));

    CHECK(FAILS_WITH(mount(NULL, DIR "/dst", NULL, MS_BIND, NULL), EINVAL));
    CHECK(FAILS_WITH(mount(DIR "/missing", DIR "/dst", NULL, MS_BIND, NULL), ENOENT));
    CHECK(FAILS_WITH(mount(DIR "/src", DIR "/src/file", NULL, MS_BIND, NULL), ENOTDIR));

    // A mount with mounts on it is busy, unless detached with them.
    CHECK(FAILS_WITH(umount2(DIR "/rdst", 0), EBUSY));
    CHECK(umount2(DIR "/rdst", MNT_DETACH) == 0);
    CHECK(umount2(DIR "/dst", 0) == 0);
    CHECK(umount2(DIR "/src/sub", 0) == 0);
}

static void check_tmpfs(void) {
    struct stat status;
    struct statfs fs;
    CHECK(mkdir(DIR "/t", 0755) == 0);
    CHECK(tmpfs(DIR "/t", MS_NOSUID | MS_NODEV, "size=1m,mode=0750,uid=12,gid=34") == 0);
    CHECK(stat(DIR "/t", &status) == 0 && (status.st_mode & 07777) == 0750 &&
          status.st_uid == 12 && status.st_gid == 34);
    CHECK(umount2(DIR "/t", 0) == 0);
    CHECK(tmpfs(DIR "/t", 0, NULL) == 0);
    // By default, the root is the caller's, and anyone's to write to.
    CHECK(stat(DIR "/t", &status) == 0 && (status.st_mode & 07777) == 01777 &&
          status.st_uid == geteuid() && status.st_gid == getegid());
    CHECK(statfs(DIR "/t", &fs) == 0 && fs.f_type == TMPFS_MAGIC && !(fs.f_flags & ST_RDONLY));
    // An open file stays on its mount once renamed or removed.
    int renamed = open(DIR "/t/renamed", O_RDWR | O_CREAT, 0644);
    int removed = open(DIR "/t/removed", O_RDWR | O_CREAT, 0644);
    CHECK(renamed >= 0 && removed >= 0);
    CHECK(rename(DIR "/t/renamed", DIR "/t/moved") == 0);
    CHECK(unlink(DIR "/t/removed") == 0);
    CHECK(fstatfs(renamed, &fs) == 0 && fs.f_type == TMPFS_MAGIC);
    CHECK(fstatfs(removed, &fs) == 0 && fs.f_type == TMPFS_MAGIC);
    CHECK(close(renamed) == 0 && close(removed) == 0);
    CHECK(umount2(DIR "/t", 0) == 0);
    // `sync` and `dirsync` are accepted and recorded, though not enforced.
    CHECK(tmpfs(DIR "/t", MS_SYNCHRONOUS | MS_DIRSYNC | MS_LAZYTIME, NULL) == 0);
    CHECK(mount(NULL, DIR "/t", NULL, MS_REMOUNT | MS_BIND | MS_SYNCHRONOUS, NULL) == 0);
    CHECK(umount2(DIR "/t", 0) == 0);

    CHECK(FAILS_WITH(tmpfs(DIR "/t", 0, "mode=8"), EINVAL));
    CHECK(FAILS_WITH(mount("proc", DIR "/t", "proc", 0, NULL), ENODEV));
    CHECK(FAILS_WITH(mount("none", DIR "/t", NULL, 0, NULL), EINVAL));
    CHECK(FAILS_WITH(mount(DIR "/src", DIR "/t", NULL, MS_MOVE, NULL), EINVAL));
}

static void check_read_only(void) {
    struct statfs fs;
    CHECK(mkdir(DIR "/ro", 0755) == 0);
    CHECK(tmpfs(DIR "/ro", 0, NULL) == 0);
    int writer = open(DIR "/ro/file", O_WRONLY | O_CREAT, 0644);
    CHECK(writer >= 0);
    // A file open for writing keeps the mount writable.
    CHECK(FAILS_WITH(mount(NULL, DIR "/ro", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL), EBUSY));
    CHECK(close(writer) == 0);
    CHECK(mount(NULL, DIR "/ro", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0);
    CHECK(FAILS_WITH(open(DIR "/ro/file", O_WRONLY), EROFS));
    CHECK(FAILS_WITH(mkdir(DIR "/ro/dir", 0755), EROFS));
    CHECK(statfs(DIR "/ro", &fs) == 0 && (fs.f_flags & ST_RDONLY));
    int reader = open(DIR "/ro/file", O_RDONLY);
    CHECK(reader >= 0 && fstatfs(reader, &fs) == 0 && (fs.f_flags & ST_RDONLY));
    CHECK(close(reader) == 0);
    CHECK(mount(NULL, DIR "/ro", NULL, MS_REMOUNT, NULL) == 0);
    CHECK(mkdir(DIR "/ro/dir", 0755) == 0);
    CHECK(statfs(DIR "/ro", &fs) == 0 && !(fs.f_flags & ST_RDONLY));
    CHECK(umount2(DIR "/ro", 0) == 0);

    // The magic number old programs pass is discarded.
    CHECK(mount("tmpfs", DIR "/ro", "tmpfs", MS_MGC_VAL | MS_RDONLY, NULL) == 0);
    CHECK(FAILS_WITH(mkdir(DIR "/ro/dir", 0755), EROFS));
    CHECK(umount2(DIR "/ro", 0) == 0);
}

static void check_unmount(void) {
    struct statfs fs;
    CHECK(mkdir(DIR "/u", 0755) == 0);
    CHECK(tmpfs(DIR "/u", 0, NULL) == 0);
    int fd = open(DIR "/u/file", O_RDWR | O_CREAT, 0644);
    CHECK(fd >= 0);
    CHECK(FAILS_WITH(umount2(DIR "/u", 0), EBUSY));
    CHECK(umount2(DIR "/u", MNT_DETACH) == 0);
    // The open file keeps working on the detached mount.
    CHECK(!exists(DIR "/u/file"));
    CHECK(write(fd, "x", 1) == 1);
    CHECK(fstatfs(fd, &fs) == 0 && fs.f_type == TMPFS_MAGIC);
    CHECK(close(fd) == 0);

    CHECK(FAILS_WITH(umount2(DIR "/u", 0), EINVAL));
    CHECK(FAILS_WITH(umount2(DIR "/missing", 0), ENOENT));
    CHECK(FAILS_WITH(umount2(DIR "/u", MNT_EXPIRE), EINVAL));
    CHECK(FAILS_WITH(umount2(DIR "/u", 0x100), EINVAL));
    // `UMOUNT_NOFOLLOW` names a final symbolic link itself, which isn't a mount.
    CHECK(tmpfs(DIR "/u", 0, NULL) == 0);
    CHECK(symlink(DIR "/u", DIR "/ulink") == 0);
    CHECK(FAILS_WITH(umount2(DIR "/ulink", UMOUNT_NOFOLLOW), EINVAL));
    CHECK(umount2(DIR "/ulink", MNT_FORCE) == 0);
    CHECK(FAILS_WITH(umount2(DIR "/u", 0), EINVAL));
}

static void check_propagation(void) {
    CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    CHECK(mkdir(DIR "/p", 0755) == 0);
    CHECK(tmpfs(DIR "/p", 0, NULL) == 0);
    CHECK(mount("none", DIR "/p", NULL, MS_SHARED, NULL) == 0);
    CHECK(mount(NULL, DIR "/p", NULL, MS_SLAVE | MS_REC | MS_SILENT, NULL) == 0);
    CHECK(mkdir(DIR "/p/sub", 0755) == 0);
    CHECK(FAILS_WITH(mount(NULL, DIR "/p/sub", NULL, MS_PRIVATE, NULL), EINVAL));
    CHECK(FAILS_WITH(mount(NULL, DIR "/p", NULL, MS_PRIVATE | MS_SHARED, NULL), EINVAL));
    CHECK(FAILS_WITH(mount(NULL, DIR "/p", NULL, MS_PRIVATE | MS_NOSUID, NULL), EINVAL));

    // A detached mount is in no namespace, and the working directory left on it is unreachable.
    CHECK(chdir(DIR "/p/sub") == 0);
    CHECK(umount2(DIR "/p", MNT_DETACH) == 0);
    CHECK(cwd_is("(unreachable)/sub"));
    CHECK(FAILS_WITH(mount(NULL, "..", NULL, MS_PRIVATE, NULL), EINVAL));
    CHECK(chdir("/") == 0);
}

// Mounts a `tmpfs` at `DIR/own` and writes a file there.
static void mount_own(void) {
    CHECK(tmpfs(DIR "/own", 0, NULL) == 0);
    CHECK(write_file(DIR "/own/file", "own") == 0);
    CHECK(reads(DIR "/own/file", "own"));
}

// In a copy of the mount namespace, sees the parent's mounts, and changes them alone.
static void unshare_and_change_mounts(void) {
    CHECK(unshare(CLONE_NEWNS) == 0);
    CHECK(reads(DIR "/shared/file", "parent"));
    CHECK(umount2(DIR "/shared", 0) == 0);
    CHECK(!exists(DIR "/shared/file"));
    mount_own();
}

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// Runs in a vfork-style child on its own stack: execs `self` to mount in its copy.
static int exec_mount_own(void *self) {
    char *const argv[] = {self, "mount-own", NULL};
    execve(self, argv, NULL);
    _exit(2);
}

static void check_namespaces(char *self) {
    CHECK(mkdir(DIR "/shared", 0755) == 0);
    CHECK(mkdir(DIR "/own", 0755) == 0);
    CHECK(tmpfs(DIR "/shared", 0, NULL) == 0);
    CHECK(write_file(DIR "/shared/file", "parent") == 0);

    in_child(unshare_and_change_mounts);
    CHECK(reads(DIR "/shared/file", "parent"));
    CHECK(!exists(DIR "/own/file"));

    pid_t child = (pid_t)syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0);
    if (child == 0) {
        failures = 0;
        mount_own();
        _exit(failures != 0);
    }
    CHECK(exits_cleanly(child));
    CHECK(!exists(DIR "/own/file"));

    // A vfork-style child gets its copy before it runs, and keeps it across `execve`.
    child = clone(exec_mount_own, vfork_stack + sizeof vfork_stack,
                  CLONE_VM | CLONE_VFORK | CLONE_NEWNS | SIGCHLD, self);
    CHECK(exits_cleanly(child));
    CHECK(!exists(DIR "/own/file"));

    // A child with its own namespace can't share its parent's root and working directory.
    CHECK(FAILS_WITH(syscall(SYS_clone, CLONE_NEWNS | CLONE_FS | SIGCHLD, 0, 0, 0, 0), EINVAL));
    CHECK(umount2(DIR "/shared", 0) == 0);
}

static void chroot_into_root(void) {
    struct stat root, parent;
    CHECK(FAILS_WITH(chroot(DIR "/missing"), ENOENT));
    CHECK(FAILS_WITH(chroot(DIR "/root/etc/name"), ENOTDIR));
    CHECK(chroot(DIR "/root") == 0);
    CHECK(reads("/etc/name", "chrooted"));
    // The working directory stays where it was, outside the new root.
    CHECK(cwd_is("(unreachable)/"));
    CHECK(chdir("/") == 0);
    CHECK(cwd_is("/"));
    CHECK(stat("/", &root) == 0 && stat("/..", &parent) == 0 && root.st_ino == parent.st_ino);
}

static void check_chroot(void) {
    CHECK(mkdir(DIR "/root", 0755) == 0);
    CHECK(mkdir(DIR "/root/etc", 0755) == 0);
    CHECK(write_file(DIR "/root/etc/name", "chrooted") == 0);
    in_child(chroot_into_root);
    CHECK(cwd_is("/"));
}

static void check_pivot_root_errors(void) {
    CHECK(mkdir(DIR "/pr", 0755) == 0);
    CHECK(mkdir(DIR "/pr2", 0755) == 0);
    CHECK(tmpfs(DIR "/pr", 0, NULL) == 0);
    CHECK(tmpfs(DIR "/pr2", 0, NULL) == 0);
    CHECK(mkdir(DIR "/pr/old", 0755) == 0);
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, DIR "/missing", DIR "/pr"), ENOENT));
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, DIR "/root/etc/name", DIR "/pr"), ENOTDIR));
    // Neither the new root nor the mount at `put_old` may be the root's mount.
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, "/", "/"), EBUSY));
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, DIR "/pr", DIR), EBUSY));
    // The new root must be a mount's root, with `put_old` at or below it.
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, DIR "/pr/old", DIR "/pr/old"), EINVAL));
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, DIR "/pr", DIR "/pr2"), EINVAL));
    CHECK(umount2(DIR "/pr", 0) == 0);
    CHECK(umount2(DIR "/pr2", 0) == 0);
}

// runc's sequence: in a mount namespace of its own, bind the root file system onto itself, enter
// it, pivot into it with the old root stacked on the new one, and detach the old root.
static void pivot_like_runc(void) {
    CHECK(unshare(CLONE_NEWNS) == 0);
    CHECK(mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == 0);
    CHECK(mount(DIR "/rootfs", DIR "/rootfs", "bind", MS_BIND | MS_REC, "") == 0);
    CHECK(chdir(DIR "/rootfs") == 0);
    int oldroot = open("/", O_DIRECTORY | O_RDONLY);
    CHECK(oldroot >= 0);
    CHECK(syscall(SYS_pivot_root, ".", ".") == 0);
    CHECK(fchdir(oldroot) == 0);
    CHECK(mount("", ".", "", MS_SLAVE | MS_REC, "") == 0);
    CHECK(umount2(".", MNT_DETACH) == 0);
    CHECK(chdir("/") == 0);
    CHECK(close(oldroot) == 0);

    CHECK(reads("/etc/hostname", "container"));
    CHECK(reads("/../etc/hostname", "container"));
    CHECK(!exists(DIR));
    CHECK(cwd_is("/"));
}

static void check_runc_sequence(void) {
    CHECK(mkdir(DIR "/rootfs", 0755) == 0);
    CHECK(mkdir(DIR "/rootfs/etc", 0755) == 0);
    CHECK(write_file(DIR "/rootfs/etc/hostname", "container") == 0);
    in_child(pivot_like_runc);
    CHECK(exists(DIR "/rootfs/etc/hostname"));
}

// As a user other than root, mounts and mount namespaces can't change, but contexts can be
// unshared.
static void check_non_root(void) {
    CHECK(geteuid() != 0);
    CHECK(FAILS_WITH(tmpfs("/tmp", 0, NULL), EPERM));
    CHECK(FAILS_WITH(umount2("/tmp", 0), EPERM));
    CHECK(FAILS_WITH(syscall(SYS_pivot_root, "/tmp", "/tmp"), EPERM));
    CHECK(FAILS_WITH(chroot("/tmp"), EPERM));
    CHECK(FAILS_WITH(unshare(CLONE_NEWNS), EPERM));
    CHECK(FAILS_WITH(syscall(SYS_clone, CLONE_NEWNS | SIGCHLD, 0, 0, 0, 0), EPERM));
    CHECK(unshare(CLONE_FS) == 0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "mount-own") == 0) {
        mount_own();
        return failures != 0;
    }
    if (argc > 1 && strcmp(argv[1], "non-root") == 0) {
        check_non_root();
        printf("mount-namespace non-root failures=%d\n", failures);
        return failures != 0;
    }
    CHECK(mkdir(DIR, 0755) == 0);
    CHECK(chdir("/") == 0);
    check_binds();
    check_tmpfs();
    check_read_only();
    check_unmount();
    check_propagation();
    check_namespaces(argv[0]);
    check_chroot();
    check_pivot_root_errors();
    check_runc_sequence();
    printf("mount-namespace failures=%d\n", failures);
    return failures != 0;
}
