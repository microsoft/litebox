// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

int main(void) {
    unsigned char buffer[259];
    memset(buffer, 0xa5, sizeof(buffer));

    if (getrandom(&buffer[1], 257, 0) != 257) {
        return 1;
    }
    if (buffer[0] != 0xa5 || buffer[258] != 0xa5) {
        return 2;
    }

    if (getrandom((void *)1, 16, 0) != -1 || errno != EFAULT) {
        return 3;
    }

    // A fault after progress returns the progress. Linux counts every byte before the fault,
    // while LiteBox counts whole 256-byte chunks.
    long page_size = sysconf(_SC_PAGESIZE);
    unsigned char *pages =
        mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED || mprotect(pages + page_size, page_size, PROT_NONE) != 0) {
        return 4;
    }
    ssize_t filled = getrandom(pages + page_size - 300, 600, 0);
    if (filled < 256 || filled > 300) {
        return 5;
    }
    munmap(pages, 2 * page_size);
    return 0;
}
