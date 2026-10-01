// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "AOT mappings line %d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static uintptr_t target(const uint32_t *pc) {
    if ((*pc & 0xfc000000) != 0x14000000) return 0;
    return (uintptr_t)pc + ((int64_t)(int32_t)(*pc << 6) >> 4);
}
int main(void) {
    int fd = open("/lib/aot_growth.so", O_RDONLY);
    CHECK(fd >= 0);
    Elf64_Ehdr eh;
    Elf64_Phdr ph[2];
    CHECK(pread(fd, &eh, sizeof eh, 0) == sizeof eh && eh.e_phnum == 2);
    CHECK(pread(fd, ph, sizeof ph, eh.e_phoff) == sizeof ph);
    size_t span = (ph[1].p_vaddr + ph[1].p_memsz + 4095) & ~4095UL;
    size_t first_len = (ph[0].p_memsz + 4095) & ~4095UL;
    uint32_t serialized_branch;
    CHECK(pread(fd, &serialized_branch, 4, eh.e_entry + 4) == 4);
    CHECK((serialized_branch & 0xfc000000) == 0x14000000);
    // Keep one prepatched DSO low enough that top-down full chunks are truly
    // farther than 4GiB, not just transport-shaped nearby direct trampolines.
    char *base = mmap((void *)0x100000000UL, span, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
    CHECK(base != MAP_FAILED);
    CHECK(mmap(base + ph[1].p_vaddr, 4096, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, ph[1].p_offset) == base + ph[1].p_vaddr);
    // A second instance starts with a nonzero-offset LOAD. Its gaps are free,
    // not an assumed reservation, and must be claimed with NOREPLACE.
    char *other = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(other != MAP_FAILED && munmap(other, span) == 0);
    CHECK(mmap(other + ph[1].p_vaddr, 4096, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, ph[1].p_offset) == other + ph[1].p_vaddr);
    CHECK(mmap(other, first_len, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd, 0) == other);
    CHECK(close(fd) == 0);
    for (int i = 0; i < 2; ++i) {
        char *p = i ? other : base;
        long (*first)(void) = (void *)(p + eh.e_entry);
        long (*second)(void) = (void *)(p + ph[1].p_vaddr);
        CHECK(mprotect(p + ph[1].p_vaddr, 4096, PROT_READ | PROT_EXEC) == 0);
        uintptr_t saved = target((const uint32_t *)second + 1);
        CHECK(saved && second() == 201);
        uint32_t slot[6]; memcpy(slot, (void *)saved, sizeof slot);
        CHECK(mprotect(p, first_len, PROT_READ | PROT_EXEC) == 0);
        CHECK(((uint32_t *)first)[1] == serialized_branch && first() == 200);
        if (!i) {
            uintptr_t near = target((const uint32_t *)first + 1) & ~4095UL;
            CHECK(*(const uint32_t *)near == 0x58000090);
            uintptr_t far = near + 44 + *(const uint64_t *)(near + 16) - 16;
            uint64_t distance = far > near ? far - near : near - far;
            CHECK(distance > (1ULL << 32));
            printf("AOT DSO island: near=%p far=%p distance=%llu\n", (void *)near, (void *)far, (unsigned long long)distance);
        }
        CHECK(target((const uint32_t *)second + 1) == saved && second() == 201);
        CHECK(memcmp(slot, (void *)saved, sizeof slot) == 0);
        // Gap reprotection must preserve every installed pair.
        if (!i) CHECK(mprotect(p + first_len, ph[1].p_vaddr - first_len, PROT_NONE) == 0);
        CHECK(first() == 200 && second() == 201);
        errno = 0;
        CHECK(mremap(p, first_len, first_len + 4096, MREMAP_MAYMOVE) == MAP_FAILED && errno == EINVAL);
        errno = 0;
        CHECK(mmap((void *)(saved & ~4095UL), 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED && errno == EBUSY);
        // Writable transition invalidates the permission cache. The file marker
        // cannot suppress scanning an SVC introduced after serialization.
        CHECK(mprotect(p + eh.e_entry, 4096, PROT_READ | PROT_WRITE) == 0);
        uint32_t *changed = (void *)(p + eh.e_entry);
        changed[0] = 0xd2801588; // mov x8, #172 (getpid)
        changed[1] = 0xd4000001; // svc #0
        changed[2] = 0xd65f03c0; // ret
        CHECK(mprotect(changed, 4096, PROT_READ | PROT_EXEC) == 0);
        CHECK(changed[1] != 0xd4000001 && first() > 0);
        CHECK(memcmp(slot, (void *)saved, sizeof slot) == 0 && second() == 201);
        // Partial source removal must retain the second LOAD's references.
        CHECK(munmap(changed, 4096) == 0 && second() == 201);
        CHECK(mmap(changed, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == changed);
        changed[0] = 0x12345678;
        CHECK(second() == 201 && changed[0] == 0x12345678);
        CHECK(munmap(p, span) == 0);
    }
    puts("AOT islands: serialized branches, multi-bias close/mprotect, immutable reuse, rescan, retirement ok");
    return 0;
}
