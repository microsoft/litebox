// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Reads standard input from the console, which the host sends only once this
// prints `ready` (see console.json and console.input.txt): until then, a read
// would block, as the console's input has not ended. Then waits for input
// with poll(2), and copies it to standard output until a line `end`.

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "%s:%d: check failed: %s (errno %d)\n",     \
                    __FILE__, __LINE__, #cond, errno);                  \
            return 1;                                                   \
        }                                                               \
    } while (0)

int main(void) {
    char buf[256];
    size_t len = 0;

    int flags = fcntl(0, F_GETFL);
    CHECK(flags >= 0);
    CHECK(fcntl(0, F_SETFL, flags | O_NONBLOCK) == 0);
    CHECK(read(0, buf, sizeof(buf)) == -1 && errno == EAGAIN);
    CHECK(fcntl(0, F_SETFL, flags) == 0);

    CHECK(write(1, "ready\n", 6) == 6);

    struct pollfd pfd = {.fd = 0, .events = POLLIN};
    CHECK(poll(&pfd, 1, -1) == 1 && (pfd.revents & POLLIN));

    for (;;) {
        char *newline = memchr(buf, '\n', len);
        if (newline == NULL) {
            CHECK(len < sizeof(buf));
            ssize_t n = read(0, buf + len, sizeof(buf) - len);
            CHECK(n > 0);
            len += (size_t)n;
            continue;
        }
        size_t line = (size_t)(newline - buf) + 1;
        if (line == 4 && memcmp(buf, "end\n", 4) == 0) {
            return 0;
        }
        CHECK(write(1, buf, line) == (ssize_t)line);
        memmove(buf, buf + line, len - line);
        len -= line;
    }
}
