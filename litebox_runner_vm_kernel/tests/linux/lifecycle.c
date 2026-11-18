// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Booted as litebox.init, for debug kernels' leak check: ends children in
// each way the other tests end theirs (spawned, execve'd, killed blocked or
// spinning, killed by the kernel), and exits 0 only if each ended as expected.

#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

// Waits for `pid` and reports whether it exited with `code` (if `exited`) or
// was killed by the signal `code`.
static int ended(pid_t pid, const char *what, int exited, int code) {
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) {
        printf("%s: no child\n", what);
        return 0;
    }
    int ok = exited ? WIFEXITED(status) && WEXITSTATUS(status) == code
                    : WIFSIGNALED(status) && WTERMSIG(status) == code;
    printf("%s: %s (status %#x)\n", what, ok ? "ok" : "unexpected", status);
    return ok;
}

static void *spin(void *arg) {
    for (;;) {
    }
    return arg;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "exit") == 0) {
        return atoi(argv[2]);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    int ok = 1;

    pid_t pid;
    char *spawned[] = {argv[0], "exit", "3", NULL};
    if (posix_spawn(&pid, argv[0], NULL, NULL, spawned, environ) != 0) {
        pid = -1;
    }
    ok &= ended(pid, "posix_spawn", 1, 3);

    pid = fork();
    if (pid == 0) {
        char *execed[] = {argv[0], "exit", "4", NULL};
        execve(argv[0], execed, environ);
        _exit(127);
    }
    ok &= ended(pid, "fork and execve", 1, 4);

    // Killed once it likely blocks; earlier, it is killed all the same.
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    pid = fork();
    if (pid == 0) {
        char byte;
        _exit(read(fds[0], &byte, 1) == 1 ? 1 : 2);
    }
    usleep(100 * 1000);
    kill(pid, SIGKILL);
    ok &= ended(pid, "SIGKILL in read", 0, SIGKILL);
    close(fds[0]);
    close(fds[1]);

    pid = fork();
    if (pid == 0) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, spin, NULL) != 0) {
            _exit(1);
        }
        spin(NULL);
    }
    usleep(100 * 1000);
    kill(pid, SIGKILL);
    ok &= ended(pid, "SIGKILL while two threads spin", 0, SIGKILL);

    pid = fork();
    if (pid == 0) {
        __asm__ volatile("wrfsbase %0" ::"r"((uint64_t)0xffff800000000000));
        for (;;) {
        }
    }
    ok &= ended(pid, "killed by the kernel (invalid FS base)", 0, SIGKILL);

    return ok ? 0 : 1;
}
