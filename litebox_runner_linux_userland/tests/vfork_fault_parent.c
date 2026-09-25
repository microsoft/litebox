// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    printf("vfork-started\n");
    fflush(stdout);

    pid_t child_pid = vfork();
    if (child_pid == 0) {
        __builtin_trap();
        _exit(111);
    }
    if (child_pid < 0) {
        perror("vfork");
        printf("vfork-error\n");
        return 2;
    }

    printf("parent-resumed child=%d\n", child_pid);
    return 3;
}
