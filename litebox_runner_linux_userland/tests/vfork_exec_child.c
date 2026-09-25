// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *marker = argc > 1 ? argv[1] : "";
    const char *environment = getenv("VFORK_EXEC_TEST");
    printf("child pid=%d ppid=%d tid=%ld marker=%s env=%s\n", getpid(),
           getppid(), syscall(SYS_gettid), marker,
           environment == NULL ? "" : environment);
    return 0;
}
