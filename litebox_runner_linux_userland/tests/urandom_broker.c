// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    unsigned char buffer[531];
    memset(buffer, 0xa5, sizeof(buffer));

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return 1;
    }
    if (read(fd, &buffer[1], 529) != 529) {
        return 2;
    }
    if (buffer[0] != 0xa5 || buffer[530] != 0xa5) {
        return 3;
    }
    for (size_t i = 1; i < 530; ++i) {
        if (buffer[i] != 0x5a) {
            return 4;
        }
    }
    return close(fd) == 0 ? 0 : 5;
}
