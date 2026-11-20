// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

// Walking from a held directory needs search permission on that directory only, not on its
// ancestors; neither does `getcwd` under an unsearchable ancestor. Runs in the working directory
// `tmp`.
static void test_search_permission(const char *tmp) {
    // Root can search any directory.
    if (geteuid() == 0) {
        return;
    }
    TEST_ASSERT(mkdir("perm", 0700) == 0 && mkdir("perm/child", 0700) == 0, "create perm tree");
    int fd = open("perm/child", O_PATH | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open perm/child");
    struct stat st;

    TEST_ASSERT(chdir("perm/child") == 0 && chmod("..", 0) == 0, "deny search on ancestor");
    char cwd[4096];
    TEST_ASSERT(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd under unsearchable ancestor");
    int parent = openat(fd, "..", O_PATH | O_DIRECTORY);
    TEST_ASSERT(parent >= 0, "dot-dot needs search on the start only");
    TEST_ASSERT(close(parent) == 0 && chmod("..", 0700) == 0 && chdir(tmp) == 0,
                "restore ancestor");

    int perm = open("perm", O_PATH | O_DIRECTORY);
    TEST_ASSERT(perm >= 0, "open perm");
    TEST_ASSERT(chmod("perm/child", 0) == 0, "deny search on start");
    expect_errno(openat(fd, "..", O_PATH | O_DIRECTORY), EACCES, "dot-dot without search");
    expect_errno(fstatat(fd, ".", &st, 0), EACCES, "dot without search");
    expect_errno(openat(fd, "new", O_CREAT | O_WRONLY, 0600), EACCES, "create without search");
    expect_errno(mkdirat(perm, "child/new", 0700), EACCES, "mkdir below unsearchable directory");
    TEST_ASSERT(chmod("perm/child", 0700) == 0, "restore search on start");
    expect_errno(fstatat(fd, "new", &st, 0), ENOENT, "denied creation left no file");
    TEST_ASSERT(close(perm) == 0 && close(fd) == 0 && rmdir("perm/child") == 0 &&
                rmdir("perm") == 0, "cleanup perm tree");
}

// Creating through a held directory that holds the program, which LiteBox serves from its
// read-only lower layer, must keep the directory's existing entries visible through the fd.
static void test_program_directory(const char *program) {
    char dir[4096];
    const char *slash = strrchr(program, '/');
    TEST_ASSERT(slash != NULL && (size_t)(slash - program) < sizeof(dir),
                "program path names its directory");
    memcpy(dir, program, (size_t)(slash - program));
    dir[slash - program] = '\0';
    int fd = open(dir[0] ? dir : "/", O_PATH | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open program directory");
    char sub[64];
    snprintf(sub, sizeof(sub), "lb-dirfd-lower-%d", (int)getpid());
    // The name repeats across runs with the same pid, so clear an empty one a failed run left.
    int made = mkdirat(fd, sub, 0700);
    if (made != 0 && errno == EEXIST) {
        TEST_ASSERT(unlinkat(fd, sub, AT_REMOVEDIR) == 0, "remove stale program directory entry");
        made = mkdirat(fd, sub, 0700);
    }
    if (made != 0) {
        // Only a program directory that belongs to another user may refuse the creation.
        TEST_ASSERT(errno == EACCES, "create in program directory");
        fprintf(stderr, "skipping program directory checks: %s is not writable\n",
                dir[0] ? dir : "/");
        TEST_ASSERT(close(fd) == 0, "close program directory");
        return;
    }
    struct stat st;
    TEST_ASSERT(fstatat(fd, sub, &st, 0) == 0 && S_ISDIR(st.st_mode),
                "creation is visible through the fd");
    TEST_ASSERT(fstatat(fd, slash + 1, &st, 0) == 0 && S_ISREG(st.st_mode),
                "existing entries stay visible after creation");
    TEST_ASSERT(unlinkat(fd, sub, AT_REMOVEDIR) == 0 && close(fd) == 0,
                "cleanup program directory");
}

// Usage: dirfd_rename [base-directory [no-symlinks]], like `enter_test_dir`.
int main(int argc, char **argv) {
    test_program_directory(argv[0]);
    char tmp[4096];
    int symlinks = enter_test_dir(argc, argv, "lb-dirfd", tmp, sizeof(tmp));
    test_search_permission(tmp);
    TEST_ASSERT(mkdir("old", 0700) == 0 && mkdir("old/sub", 0700) == 0, "create subtree");
    int fd = open("old/sub", O_PATH | O_DIRECTORY);
    TEST_ASSERT(fd >= 0, "open directory");
    create_test_file("old/sub/original", 0600);
    int file = openat(fd, "original", O_RDONLY);
    TEST_ASSERT(file >= 0, "open file through directory fd");

    TEST_ASSERT(rename("old", "new") == 0, "rename ancestor");
    TEST_ASSERT(mkdir("old", 0700) == 0 && mkdir("old/sub", 0700) == 0, "replace subtree");
    struct stat st;
    TEST_ASSERT(fstatat(fd, "original", &st, 0) == 0, "lookup follows renamed ancestor");
    char link[64], target[4096], expect[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", file);
    snprintf(expect, sizeof(expect), "%s/new/sub/original", tmp);
    ssize_t length = readlink(link, target, sizeof(target) - 1);
    TEST_ASSERT(length >= 0, "read file fd link");
    target[length] = '\0';
    TEST_ASSERT(!strcmp(target, expect), "file fd link follows renamed ancestor");
    // `fd` was opened as old/sub but now lies in new/sub, so a stale name would let this rename
    // move `new` into the unrelated old/sub.
    expect_errno(renameat(AT_FDCWD, "new", fd, "moved"), EINVAL,
                 "cannot move renamed ancestor into its held descendant");
    int parent = openat(fd, "..", O_PATH | O_DIRECTORY);
    TEST_ASSERT(parent >= 0, "open parent of held directory");
    expect_errno(renameat(parent, "sub", fd, "moved"), EINVAL,
                 "cannot move held directory into itself");
    // Linux: do_renameat2() rejects a source that is an ancestor of the target with EINVAL
    // before comparing the two entries' types, so an existing file there does not give ENOTDIR.
    create_test_file("new/sub/blocker", 0600);
    expect_errno(renameat(parent, "sub", fd, "blocker"), EINVAL,
                 "cannot move held directory over a file inside itself");
    TEST_ASSERT(unlinkat(fd, "blocker", 0) == 0, "remove blocker");
    TEST_ASSERT(close(parent) == 0 && stat("new/sub/original", &st) == 0,
                "rejected renames left the source in place");
    expect_errno(fstatat(fd, "moved", &st, 0), ENOENT, "rejected renames created nothing");
    expect_errno(stat("old/sub/moved", &st), ENOENT, "stale name was not a rename target");
    const struct timespec times[2] = {{12345, 0}, {23456, 0}};
    TEST_ASSERT(utimensat(fd, "original", times, 0) == 0, "set times through moved ancestor");
    TEST_ASSERT(stat("new/sub/original", &st) == 0 && st.st_mtime == 23456,
                "timestamps changed on original inode");
    const struct timespec later[2] = {{34567, 0}, {45678, 0}};
    TEST_ASSERT(futimens(file, later) == 0 && stat("new/sub/original", &st) == 0 &&
                st.st_mtime == 45678 && close(file) == 0, "set times on file under renamed parent");
    TEST_ASSERT(mkdirat(fd, "created", 0700) == 0, "create through directory fd");
    TEST_ASSERT(stat("new/sub/created", &st) == 0, "creation lands in original directory");
    expect_errno(stat("old/sub/created", &st), ENOENT, "replacement is untouched");

    int replaced = open("old/sub", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(replaced >= 0, "open rename destination");
    // Without symlinks, a regular file stands in for the link so the renames still run.
    if (symlinks) {
        TEST_ASSERT(symlinkat("../marker", fd, "link") == 0, "create relative symlink");
    } else {
        create_test_file("new/sub/link", 0600);
    }
    create_test_file("old/marker", 0600);
    if (symlinks) {
        expect_errno(fstatat(fd, "link", &st, 0), ENOENT, "link does not resolve in replacement");
    }
    TEST_ASSERT(rename("new/sub", "old/sub") == 0, "move open directory over replacement");
    TEST_ASSERT(fstatat(fd, "link", &st, 0) == 0, "relative link follows new parent");
    expect_errno(fstatat(replaced, "original", &st, 0), ENOENT, "replaced fd stays detached");
    struct stat expected;
    TEST_ASSERT(fstat(replaced, &expected) == 0 && fstatat(replaced, ".", &st, 0) == 0 &&
                st.st_ino == expected.st_ino, "dot still names the detached directory");
    TEST_ASSERT(stat("old", &expected) == 0 && fstatat(replaced, "..", &st, 0) == 0 &&
                st.st_ino == expected.st_ino, "dot-dot names the detached directory's parent");
    char dents[256];
    expect_errno(syscall(SYS_getdents64, replaced, dents, sizeof(dents)), ENOENT,
                 "cannot enumerate removed directory");
    TEST_ASSERT(close(replaced) == 0, "close detached directory");
    int dest = open("new", O_RDONLY | O_DIRECTORY);
    TEST_ASSERT(dest >= 0 && renameat(fd, "link", dest, "moved-link") == 0,
                "rename between independent directory fds");
    TEST_ASSERT(unlinkat(dest, "moved-link", 0) == 0 && close(dest) == 0 &&
                unlink("old/marker") == 0, "cleanup link");
    TEST_ASSERT(unlinkat(fd, "original", 0) == 0 && unlinkat(fd, "created", AT_REMOVEDIR) == 0,
                "remove entries through moved directory fd");
    TEST_ASSERT(rmdir("old/sub") == 0 && mkdir("old/sub", 0700) == 0, "replace removed directory");
    expect_errno(mkdirat(fd, "absent", 0700), ENOENT, "cannot create in removed directory");
    expect_errno(openat(fd, "absent", O_CREAT | O_WRONLY, 0600), ENOENT,
                 "cannot create file in removed directory");
    if (symlinks) {
        expect_errno(symlinkat("target", fd, "absent"), ENOENT,
                     "cannot create symlink in removed directory");
    }
    create_test_file("new/source", 0600);
    int live = open("new", O_PATH | O_DIRECTORY);
    TEST_ASSERT(live >= 0, "open live directory");
    expect_errno(renameat(live, "source", fd, "absent"), ENOENT,
                 "cannot rename into removed directory");
    expect_errno(renameat(AT_FDCWD, "new/source", fd, "absent"), ENOENT,
                 "cannot rename from cwd into removed directory");
    TEST_ASSERT(fstatat(live, "source", &st, 0) == 0 && unlinkat(live, "source", 0) == 0 &&
                close(live) == 0, "rename source is untouched");
    TEST_ASSERT(close(fd) == 0 && rmdir("old/sub") == 0 && rmdir("old") == 0 &&
                rmdir("new") == 0 && chdir("/") == 0 && rmdir(tmp) == 0, "cleanup");
    puts("All directory fd rename tests passed.");
    return 0;
}
