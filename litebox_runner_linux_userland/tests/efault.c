// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <unistd.h>
#include <errno.h>
#include <stdio.h>

int main() {
    int r = write(STDOUT_FILENO, (const void *)0x10000, 1);
    if (r >= 0) {
        fprintf(stderr, "write to invalid address succeeded unexpectedly\n");
        abort();
    }
    if (errno != EFAULT) {
        perror("write");
        return 1;
    }
}
