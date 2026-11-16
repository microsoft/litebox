// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Maps and touches more memory than q35 puts below 4 GiB (2 GiB once -m is
// at least 2816M), so some of it must be RAM above 4 GiB. Prints
// "highmem: ok".

#include <stdio.h>
#include <sys/mman.h>

#define SIZE (3UL << 30)
#define PAGE 4096UL

int main(void) {
    char *p = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    // Each page's index at its start, so that pages sharing a frame would show.
    for (unsigned long i = 0; i < SIZE / PAGE; i++) {
        *(unsigned long *)(p + i * PAGE) = i;
    }
    for (unsigned long i = 0; i < SIZE / PAGE; i++) {
        unsigned long v = *(unsigned long *)(p + i * PAGE);
        if (v != i) {
            fprintf(stderr, "page %lu reads %lu\n", i, v);
            return 1;
        }
    }
    printf("highmem: ok\n");
    return 0;
}
