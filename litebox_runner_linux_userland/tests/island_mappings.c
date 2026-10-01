// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Mapping-lifetime version of the read-only trampoline branch's runtime-growth
// probe. No compact/ADRP path is admitted by this test.
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "island mappings line %d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static uintptr_t branch(const uint32_t *pc) {
    return (uintptr_t)pc + ((int64_t)(int32_t)(*pc << 6) >> 4);
}
static uintptr_t island_entry(const uint32_t *site) {
    if ((*site & 0xfc000000) != 0x14000000) return 0;
    const uint32_t *entry = (const uint32_t *)branch(site);
    if (entry[0] != 0xd10043ff || entry[1] != 0xa9007bf0
        || (entry[2] & 0xfc000000) != 0x94000000) return 0;
    return (uintptr_t)entry;
}
int main(void) {
    int fd = open("/lib/island_growth.so", O_RDONLY);
    CHECK(fd >= 0);
    Elf64_Ehdr eh;
    Elf64_Phdr ph[2];
    CHECK(pread(fd, &eh, sizeof eh, 0) == sizeof eh);
    CHECK(eh.e_phnum == 2 && eh.e_phentsize == sizeof ph[0]);
    CHECK(pread(fd, ph, sizeof ph, eh.e_phoff) == sizeof ph);
    size_t span = (ph[1].p_vaddr + ph[1].p_memsz + 4095) & ~4095UL;
    char *base = mmap(NULL, span, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(base != MAP_FAILED);
    // Like ld.so, replace later LOADs at their own file offsets. The first
    // whole-span reservation is not proof that file offset equals object VA.
    CHECK(mmap(base + ph[1].p_vaddr, 4096, PROT_READ, MAP_FIXED | MAP_PRIVATE,
               fd, ph[1].p_offset) == base + ph[1].p_vaddr);
    // Same descriptor, another load bias, mmap+X rather than mprotect+X.
    // Keep the following page occupied during publication so it cannot become
    // transport, then create a hole for a non-destructive replacement failure.
    size_t other_size = (ph[0].p_memsz + 4095) & ~4095UL;
    char *other = mmap(NULL, other_size + 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(other != MAP_FAILED);
    CHECK(mmap(other, other_size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0) == other);
    CHECK(munmap(other + other_size, 4096) == 0);
    long (*first)(void) = (void *)(base + eh.e_entry);
    long (*second)(void) = (void *)(base + ph[1].p_vaddr);
    long (*another)(void) = (void *)(other + eh.e_entry);
    CHECK(another() == 200);
    errno = 0;
    CHECK(mmap(other + eh.e_entry, 4096, PROT_READ | PROT_EXEC,
               MAP_FIXED | MAP_PRIVATE, -1, 0) == MAP_FAILED && errno == EBADF);
    CHECK(another() == 200); // preflight failure did not revoke RX or retire pairs
    errno = 0;
    CHECK(mmap(other, other_size + 4096, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == ENOMEM);
    CHECK(another() == 200); // Vmem rejected a mapping + hole before allocation
    CHECK(mprotect(other, other_size, PROT_READ | PROT_EXEC) == 0);
    CHECK(another() == 200); // preserved metadata still admits an idempotent +X
    CHECK(close(fd) == 0);
    // Out-of-order executable transitions AFTER close must retain offsets.
    CHECK(mprotect(base + ph[1].p_vaddr, 4096, PROT_READ | PROT_EXEC) == 0);
    uintptr_t old_target = island_entry((const uint32_t *)second + 1);
    CHECK(old_target && second() == 201);
    CHECK(mprotect(base, (ph[0].p_memsz + 4095) & ~4095UL, PROT_READ | PROT_EXEC) == 0);
    CHECK(island_entry((const uint32_t *)first + 1) && first() == 200);
    CHECK(island_entry((const uint32_t *)second + 1) == old_target && second() == 201);
    size_t gap = (ph[0].p_memsz + 4095) & ~4095UL;
    CHECK(ph[1].p_vaddr - gap == 4096);
    CHECK(mprotect(base + gap, 4096, PROT_NONE) == 0);
    CHECK(second() == 201 && first() == 200);
    errno = 0;
    CHECK(mmap((void *)(old_target & ~4095UL), 4096, PROT_NONE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == EBUSY);
    errno = 0;
    CHECK(mremap(base + ph[1].p_vaddr, 4096, 8192, MREMAP_MAYMOVE) == MAP_FAILED && errno == EINVAL);
    CHECK(munmap(base + eh.e_entry, 4096) == 0);
    CHECK(second() == 201 && another() == 200);
    CHECK(munmap(base, span) == 0);
    CHECK(another() == 200);
    CHECK(munmap(other, (ph[0].p_memsz + 4095) & ~4095UL) == 0);
    puts("runtime mmap+X / close / mprotect+X / multi-batch / gap / partial-unmap islands ok");
    return 0;
}
