// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <assert.h>
#include <errno.h>
#include <sys/socket.h>

int main(void) {
    assert(socket(AF_INET, SOCK_STREAM, 0) == -1);
    assert(errno == EAFNOSUPPORT);

    assert(socket(AF_INET, SOCK_DGRAM, 0) == -1);
    assert(errno == EAFNOSUPPORT);

    return 0;
}
