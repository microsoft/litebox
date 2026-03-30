// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Helper binary compiled as static (non-PIE / ET_EXEC).
// Reads stdin, echoes each line to stdout prefixed with "ECHO:".

#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[4096];
    while (fgets(buf, sizeof(buf), stdin)) {
        fputs("ECHO:", stdout);
        fputs(buf, stdout);
        fflush(stdout);
    }
    return 0;
}
