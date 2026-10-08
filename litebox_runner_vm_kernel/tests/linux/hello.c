// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A static hello world for dev_tools/run_linux_on_vm_userland.sh; see
// hello.json.

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[]) {
    printf("Hello, world!\n");
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    for (int i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }
    fprintf(stderr, "to stderr\n");
    return argc > 1 && strcmp(argv[1], "fail") == 0 ? 3 : 0;
}
