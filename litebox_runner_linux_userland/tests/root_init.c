// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The guest's first process, which its child tries to kill. If it survives, it exits leaving a child
// that reports outliving it.

#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    printf("root-init started\n");
    fflush(stdout);
    pid_t sender = fork();
    if (sender == 0) {
        _exit(kill(1, SIGTERM) == 0 && kill(1, SIGKILL) == 0 ? 0 : 1);
    }
    // Reaping the sender takes the signals it sent first.
    int status;
    if (waitpid(sender, &status, 0) != sender || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 1;
    }
    pid_t survivor = fork();
    if (survivor == 0) {
        sleep(10);
        printf("root-init outlived\n");
        _exit(0);
    }
    printf("root-init survived\n");
    return survivor > 0 ? 0 : 1;
}
