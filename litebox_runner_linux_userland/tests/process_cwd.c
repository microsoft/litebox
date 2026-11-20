// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <assert.h>

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
        // The cwd shares the inherited descriptor's reference but must outlive it.
        assert(close(atoi(argv[2])) == 0);
        check_detached();
        return 0;
    }
    // Usage: process_cwd [absolute directory to detach], defaulting to one in `test_dir()`. The
    // program re-executes itself, so it must be started by its absolute path.
    assert(argc <= 2 && argv[0][0] == '/');
    const char *dir = argc == 2 ? argv[1] : test_path("detached");
    assert(dir[0] == '/');
    assert(mkdir(dir, 0700) == 0);
    int fd = open(dir, O_PATH | O_DIRECTORY);
    assert(fd >= 0 && fchdir(fd) == 0 && rmdir(dir) == 0);
    char *args[] = {argv[0], "child", NULL};
    int status;
    pid_t pid = fork();
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
