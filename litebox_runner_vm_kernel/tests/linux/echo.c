// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Copies standard input to standard output until its end, as `cat`. See
// echo.json.

#include <stdio.h>

int main(void) {
    char line[256];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        fputs(line, stdout);
    }
    return ferror(stdin) ? 1 : 0;
}
