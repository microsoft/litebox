// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Prints its arguments and environment, and something on stderr. Ends as its
// first argument says: "exit <code>", or "abort". See args.json.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[]) {
    for (int i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    for (int i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }
    fprintf(stderr, "to stderr\n");
    if (argc > 2 && strcmp(argv[1], "exit") == 0) {
        return atoi(argv[2]);
    }
    if (argc > 1 && strcmp(argv[1], "abort") == 0) {
        fflush(stdout);
        abort();
    }
    return 0;
}
