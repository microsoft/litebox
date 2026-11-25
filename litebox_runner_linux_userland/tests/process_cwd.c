// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <assert.h>

static int cwd_link_matches(const char *path, const char *expected) {
    char link[4096];
    ssize_t len = readlink(path, link, sizeof(link));
    return len >= 0 && (size_t)len == strlen(expected) && memcmp(link, expected, len) == 0;
}

static void check_cwd_link(const char *expected) {
    char cwd[4096];
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(expected == NULL || strcmp(cwd, expected) == 0);
    assert(cwd_link_matches("/proc/self/cwd", cwd));
}

static int vfork_cwd_is_separate(const char *parent_link, const char *parent_cwd) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, parent_cwd) || chdir("/") != 0 ||
        getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/"))
        return 0;
    int fd = open("tmp", O_PATH | O_DIRECTORY);
    return fd >= 0 && close(fd) == 0 && cwd_link_matches(parent_link, parent_cwd);
}

static void check_detached(void) {
    char buf[4096];
    struct stat st;
    assert(getcwd(buf, sizeof(buf)) == NULL && errno == ENOENT);
    assert(stat(".", &st) == 0 && S_ISDIR(st.st_mode));
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "child")) {
        check_detached();
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "child-fd")) {
        // The cwd must outlive any inherited descriptor that names it.
        assert(close(atoi(argv[2])) == 0);
        check_detached();
        return 0;
    }
    // Usage: process_cwd [absolute directory to detach], defaulting to one in `test_dir()`. The
    // program re-executes itself, so it must be started by its absolute path.
    assert(argc <= 2 && argv[0][0] == '/');
    const char *dir = argc == 2 ? argv[1] : test_path("detached");
    assert(dir[0] == '/');
    check_cwd_link(NULL);
    char *before;
    assert(asprintf(&before, "%s-before-rename", dir) >= 0);
    assert(mkdir(before, 0700) == 0 && chdir(before) == 0);
    check_cwd_link(NULL);
    assert(rename(before, dir) == 0);
    free(before);
    char renamed[4096];
    assert(getcwd(renamed, sizeof(renamed)) != NULL);
    check_cwd_link(renamed);

    int status;
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        check_cwd_link(renamed);
        assert(chdir("/") == 0);
        check_cwd_link("/");
        _exit(0);
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_cwd_link(renamed);
    // Use the PID as seen by this procfs mount, not necessarily by getpid().
    char proc_pid[32], parent_link[64];
    ssize_t proc_len = readlink("/proc/self", proc_pid, sizeof(proc_pid));
    assert(proc_len > 0 && proc_len < (ssize_t)sizeof(proc_pid));
    snprintf(parent_link, sizeof(parent_link), "/proc/%.*s/cwd", (int)proc_len, proc_pid);
    pid = vfork();
    if (pid == 0)
        _exit(!vfork_cwd_is_separate(parent_link, renamed));
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_cwd_link(renamed);

    int fd = open(dir, O_PATH | O_DIRECTORY);
    assert(fd >= 0 && chdir("/") == 0 && fchdir(fd) == 0);
    check_cwd_link(renamed);
    assert(rmdir(dir) == 0);
    char *args[] = {argv[0], "child", NULL};
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(close(fd) == 0);
        check_detached();
        execv(args[0], args);
        _exit(111);
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char fd_arg[16];
    snprintf(fd_arg, sizeof(fd_arg), "%d", fd);
    char *fd_args[] = {argv[0], "child-fd", fd_arg, NULL};
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        execv(fd_args[0], fd_args);
        _exit(113);
    }
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(fd) == 0); // vfork/exec now has no descriptor naming the cwd.
    // Replace the old cwd name. A relative exec must start lookup at the detached
    // directory, and the fresh runner must be able to repeat that lookup.
    assert(symlink(args[0], dir) == 0);
    char relative[4096];
    int len = snprintf(relative, sizeof(relative), "..%s", strrchr(dir, '/'));
    assert(len > 0 && (size_t)len < sizeof(relative));
    pid = vfork();
    if (pid == 0) {
        execv(relative, args);
        _exit(112);
    }
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_detached();
    assert(unlink(dir) == 0);
    puts("All process cwd tests passed.");
    return 0;
}
