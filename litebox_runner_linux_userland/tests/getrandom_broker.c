// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <string.h>
#include <sys/random.h>

int main(void) {
    unsigned char buffer[259];
    memset(buffer, 0xa5, sizeof(buffer));

    if (getrandom(&buffer[1], 257, 0) != 257) {
        return 1;
    }
    if (buffer[0] != 0xa5 || buffer[258] != 0xa5) {
        return 2;
    }
    return 0;
}
