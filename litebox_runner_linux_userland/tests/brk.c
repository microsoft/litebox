// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <stdint.h>

static uintptr_t raw_brk(uintptr_t address) {
    return (uintptr_t)syscall(SYS_brk, address);
}

static void test_shrink_within_current_page(void) {
    uintptr_t initial = raw_brk(0);
    long page_size = sysconf(_SC_PAGESIZE);
    TEST_ASSERT(initial != 0, "query initial program break");
    TEST_ASSERT(page_size > 0, "query page size");

    uintptr_t page_mask = (uintptr_t)page_size - 1;
    uintptr_t grown = ((initial + page_mask) & ~page_mask) + (uintptr_t)page_size + 123;
    uintptr_t requested = grown - 64;

    TEST_ASSERT(raw_brk(grown) == grown, "grow program break");
    TEST_ASSERT(raw_brk(requested) == requested,
                "shrink program break within current page");
    TEST_ASSERT(raw_brk(0) == requested, "query shrunken program break");
    TEST_ASSERT(raw_brk(initial) == initial, "restore initial program break");
}

int main(void) {
    printf("brk tests starting...\n");
    test_shrink_within_current_page();
    printf("All brk tests passed.\n");
    return 0;
}
