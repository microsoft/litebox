// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Linux lays out the initial argv and envp strings contiguously in ascending
// order: argv[0], ..., argv[argc-1], envp[0], ..., envp[n-1]. Some programs
// (e.g., those that rewrite their process title) rely on this.

#include "helpers.h"

int main(int argc, char *argv[], char *envp[]) {
    printf("stack string layout tests starting...\n");

    TEST_ASSERT(argc >= 1, "expected at least argv[0]");

    const char *expected = argv[0];
    for (int i = 0; i < argc; i++) {
        TEST_ASSERT(argv[i] == expected, "argv strings not contiguous and ascending");
        expected = argv[i] + strlen(argv[i]) + 1;
    }

    int envc = 0;
    for (; envp[envc] != NULL; envc++) {
        TEST_ASSERT(envp[envc] == expected,
                    "envp strings not contiguous, ascending, and after argv");
        expected = envp[envc] + strlen(envp[envc]) + 1;
    }
    TEST_ASSERT(argc + envc >= 2, "need at least two strings to check ordering");

    printf("All stack string layout tests passed.\n");
    return 0;
}
