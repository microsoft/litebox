// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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
    assert(argc == 3 && argv[1][0] == '/' && argv[2][0] == '/');
    assert(mkdir(argv[2], 0700) == 0);
    int fd = open(argv[2], O_PATH | O_DIRECTORY);
    assert(fd >= 0 && fchdir(fd) == 0 && rmdir(argv[2]) == 0);
    char *args[] = {argv[1], "child", NULL};
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
    assert(close(fd) == 0); // vfork/exec now has no descriptor naming the cwd.
    // Replace the old cwd name. A relative exec must start lookup at the detached
    // directory, and the fresh runner must be able to repeat that lookup.
    assert(symlink(args[0], argv[2]) == 0);
    char relative[4096];
    int len = snprintf(relative, sizeof(relative), "..%s", strrchr(argv[2], '/'));
    assert(len > 0 && (size_t)len < sizeof(relative));
    pid = vfork();
    if (pid == 0) {
        execv(relative, args);
        _exit(112);
    }
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_detached();
    assert(unlink(argv[2]) == 0);
    puts("All process cwd tests passed.");
    return 0;
}
