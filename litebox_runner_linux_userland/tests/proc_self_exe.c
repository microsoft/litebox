// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static char original[PATH_MAX];

static void check_executable(const char *expected) {
    char path[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", path, sizeof path);
    assert(length == (ssize_t)strlen(expected));
    assert(memcmp(path, expected, length) == 0);
    char short_path[4];
    assert(readlink("/proc/self/exe", short_path, sizeof short_path) == sizeof short_path);
    assert(memcmp(short_path, expected, sizeof short_path) == 0);
}

static void *check_thread(void *unused) {
    (void)unused;
    check_executable(original);
    return NULL;
}

static void fork_exec(const char *path, const char *expected) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        check_executable(original);
        assert(chdir("/tmp") == 0);
        execl(path, "not-the-executable-path", "after-exec", expected, NULL);
        _exit(1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_executable(original);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "after-exec") == 0) {
        check_executable(argv[2]);
        return 0;
    }
    ssize_t length = readlink("/proc/self/exe", original, sizeof original - 1);
    assert(length > 0);
    original[length] = '\0';
    assert(original[0] == '/');
    assert(strstr(original, "proc_self_exe") != NULL);

    pthread_t thread;
    assert(pthread_create(&thread, NULL, check_thread, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    execl("/missing-executable", "missing", NULL);
    assert(errno == ENOENT);
    check_executable(original);

    assert(symlink(original, "/tmp/exe-link") == 0);
    fork_exec("/tmp/exe-link", original);

    int input = open(original, O_RDONLY);
    int output = open("/tmp/exe-copy", O_WRONLY | O_CREAT | O_EXCL, 0755);
    assert(input >= 0 && output >= 0);
    char buffer[8192];
    while ((length = read(input, buffer, sizeof buffer)) > 0) {
        ssize_t written = 0;
        while (written < length) {
            ssize_t n = write(output, buffer + written, length - written);
            assert(n > 0);
            written += n;
        }
    }
    assert(length == 0);
    assert(close(input) == 0 && close(output) == 0);
    fork_exec("./exe-copy", "/tmp/exe-copy");
    puts("proc-self-exe: OK");
    return 0;
}
