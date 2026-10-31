// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Without a vsock device, LiteBox has no AF_VSOCK sockets, as Linux without a vsock transport.

#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>

int main(void) {
    errno = 0;
    if (socket(AF_VSOCK, SOCK_STREAM, 0) != -1 || errno != EAFNOSUPPORT) {
        printf("socket(AF_VSOCK, SOCK_STREAM, 0): errno %d, expected EAFNOSUPPORT\n", errno);
        return 1;
    }
    return 0;
}
