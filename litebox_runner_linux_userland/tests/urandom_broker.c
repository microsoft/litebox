// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
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
    // The broker harness passes its deterministic provider's fill byte.
    if (argc == 2) {
        unsigned char expected = (unsigned char)strtoul(argv[1], NULL, 0);
        for (size_t i = 1; i < 530; ++i) {
            if (buffer[i] != expected) {
                return 4;
            }
        }
    }
    return close(fd) == 0 ? 0 : 5;
}
