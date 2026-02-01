// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: mmap, munmap, mprotect, mremap - advanced cases
// Based on patterns from Asterinas and LTP test suites

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#define PAGE_SIZE 4096

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s (errno=%d)\n", \
                __func__, __LINE__, msg, errno); \
        return 1; \
    } \
} while(0)

static sigjmp_buf jump_buffer;
static volatile sig_atomic_t got_signal = 0;

static void segv_handler(int sig) {
    got_signal = 1;
    siglongjmp(jump_buffer, 1);
}

int test_mmap_anonymous(void) {
    // Basic anonymous mapping
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(addr != MAP_FAILED, "mmap anonymous failed");

    // Write to it
    memset(addr, 0x42, PAGE_SIZE);
    TEST_ASSERT(((char*)addr)[0] == 0x42, "write to mmap failed");

    // Unmap
    int ret = munmap(addr, PAGE_SIZE);
    TEST_ASSERT(ret == 0, "munmap failed");

    printf("mmap anonymous: PASS\n");
    return 0;
}

int test_mmap_fixed(void) {
    // First get a valid address
    void *hint = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(hint != MAP_FAILED, "initial mmap failed");
    munmap(hint, PAGE_SIZE * 2);

    // Now map at that fixed address
    void *addr = mmap(hint, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    TEST_ASSERT(addr == hint, "mmap MAP_FIXED returned different address");

    munmap(addr, PAGE_SIZE);
    printf("mmap MAP_FIXED: PASS\n");
    return 0;
}

int test_mprotect_basic(void) {
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(addr != MAP_FAILED, "mmap failed");

    // Write something
    memset(addr, 0x42, PAGE_SIZE);

    // Change to read-only
    int ret = mprotect(addr, PAGE_SIZE, PROT_READ);
    TEST_ASSERT(ret == 0, "mprotect to PROT_READ failed");

    // Reading should still work
    TEST_ASSERT(((char*)addr)[0] == 0x42, "read after mprotect failed");

    // Change back to read-write
    ret = mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
    TEST_ASSERT(ret == 0, "mprotect to PROT_READ|PROT_WRITE failed");

    // Writing should work again
    ((char*)addr)[0] = 0x24;
    TEST_ASSERT(((char*)addr)[0] == 0x24, "write after mprotect failed");

    munmap(addr, PAGE_SIZE);
    printf("mprotect basic: PASS\n");
    return 0;
}

int test_mremap_grow(void) {
    void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(addr != MAP_FAILED, "mmap failed");

    // Write pattern
    memset(addr, 0xAB, PAGE_SIZE);

    // Grow the mapping
    void *new_addr = mremap(addr, PAGE_SIZE, PAGE_SIZE * 2, MREMAP_MAYMOVE);
    TEST_ASSERT(new_addr != MAP_FAILED, "mremap grow failed");

    // Original data should be preserved
    TEST_ASSERT(((unsigned char*)new_addr)[0] == 0xAB, "data not preserved after mremap");

    // Write to new area
    ((char*)new_addr)[PAGE_SIZE] = 0xCD;
    TEST_ASSERT(((unsigned char*)new_addr)[PAGE_SIZE] == 0xCD, "write to grown area failed");

    munmap(new_addr, PAGE_SIZE * 2);
    printf("mremap grow: PASS\n");
    return 0;
}

int test_mremap_shrink(void) {
    void *addr = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(addr != MAP_FAILED, "mmap failed");

    // Write pattern to first page
    memset(addr, 0xEF, PAGE_SIZE);

    // Shrink the mapping
    void *new_addr = mremap(addr, PAGE_SIZE * 2, PAGE_SIZE, 0);
    TEST_ASSERT(new_addr != MAP_FAILED, "mremap shrink failed");
    TEST_ASSERT(new_addr == addr, "shrink should not move");

    // Data should be preserved
    TEST_ASSERT(((unsigned char*)new_addr)[0] == 0xEF, "data not preserved after shrink");

    munmap(new_addr, PAGE_SIZE);
    printf("mremap shrink: PASS\n");
    return 0;
}

int test_mmap_errors(void) {
    // Invalid length (0)
    void *addr = mmap(NULL, 0, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(addr == MAP_FAILED && errno == EINVAL, "mmap(len=0) should return EINVAL");

    // Invalid fd for non-anonymous mapping
    // Note: This may vary by implementation

    printf("mmap errors: PASS\n");
    return 0;
}

int test_munmap_errors(void) {
    // Unmap NULL with length 0
    int ret = munmap(NULL, 0);
    TEST_ASSERT(ret == -1 && errno == EINVAL, "munmap(NULL, 0) should return EINVAL");

    printf("munmap errors: PASS\n");
    return 0;
}

int main(void) {
    printf("Starting mmap advanced tests...\n");

    if (test_mmap_anonymous() != 0) return 1;
    if (test_mmap_fixed() != 0) return 1;
    if (test_mprotect_basic() != 0) return 1;
    if (test_mremap_grow() != 0) return 1;
    if (test_mremap_shrink() != 0) return 1;
    if (test_mmap_errors() != 0) return 1;
    if (test_munmap_errors() != 0) return 1;

    printf("All mmap advanced tests passed!\n");
    return 0;
}
