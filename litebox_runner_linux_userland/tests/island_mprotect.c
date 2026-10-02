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

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "island mprotect line %d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static uintptr_t island_entry(const uint32_t *site) {
    if ((*site & 0xfc000000) != 0x14000000) return 0;
    const uint32_t *entry = (const uint32_t *)((uintptr_t)site + ((int64_t)(int32_t)(*site << 6) >> 4));
    if (entry[0] != 0xd10043ff || entry[1] != 0xa9007bf0
        || (entry[2] & 0xfc000000) != 0x94000000) return 0;
    return (uintptr_t)entry;
}
int main(void) {
    int fd = open("/lib/island_growth.so", O_RDONLY);
    int readonly_fd = open("/island-mprotect-readonly", O_RDONLY);
    CHECK(fd >= 0 && readonly_fd >= 0);
    Elf64_Ehdr eh;
    Elf64_Phdr ph[2];
    CHECK(pread(fd, &eh, sizeof eh, 0) == sizeof eh);
    CHECK(eh.e_phnum == 2 && eh.e_phentsize == sizeof ph[0]);
    CHECK(pread(fd, ph, sizeof ph, eh.e_phoff) == sizeof ph);
    CHECK(ph[1].p_memsz <= 4096);
    char *base = mmap(NULL, 3 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(base != MAP_FAILED);
    uint32_t *code = (uint32_t *)(base + 4096);
    CHECK(mmap(code, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
               fd, ph[1].p_offset) == code);
    CHECK(mmap(base, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, readonly_fd, 0) == base);
    CHECK(mmap(base + 8192, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, readonly_fd, 0) == base + 8192);
    CHECK(close(fd) == 0 && close(readonly_fd) == 0);
    long (*original)(void) = (void *)code;
    uintptr_t old_entry = island_entry(code + 1);
    CHECK(old_entry && original() == 201);
    uint32_t old_slot[6], old_code[3];
    memcpy(old_slot, (void *)old_entry, sizeof old_slot);
    memcpy(old_code, code, sizeof old_code);

    // A rejected request that changes nothing must leave the mapping usable,
    // even though conservative invalidation forces the exact-range RX to rescan.
    errno = 0;
    CHECK(mprotect(base, 3 * 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    CHECK(original() == 201);
    CHECK(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0);
    CHECK(island_entry(code + 1) == old_entry && original() == 201);

    // Vmem preflights the trailing shared page: rejection must leave the RX
    // code unchanged and callable. Only an explicit successful RW may edit it.
    errno = 0;
    CHECK(mprotect(code, 2 * 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    CHECK(memcmp(old_code, code, sizeof old_code) == 0);
    CHECK(island_entry(code + 1) == old_entry && original() == 201);
    CHECK(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0);
    CHECK(island_entry(code + 1) == old_entry && original() == 201);
    CHECK(mprotect(code, 4096, PROT_READ | PROT_WRITE) == 0);
    code[0] = 0xd2800708; // mov x8, #56 (openat)
    code[1] = 0xd4000001; // svc #0
    code[2] = 0xd65f03c0; // ret
    __builtin___clear_cache((char *)code, (char *)(code + 3));
    CHECK(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0);
    CHECK(island_entry(code + 1) && island_entry(code + 1) != old_entry);
    CHECK(memcmp(old_slot, (void *)old_entry, sizeof old_slot) == 0);
    // This path exists only in the guest rootfs. A native openat cannot return
    // a usable guest descriptor; checking the branch above also forbids SVC.
    long (*open_guest)(long, const char *, long, long) = (void *)code;
    long reopened = open_guest(AT_FDCWD, "/island-mprotect-readonly", O_RDONLY, 0);
    CHECK(reopened >= 0);
    unsigned char byte = 0;
    CHECK(read((int)reopened, &byte, 1) == 1 && byte == 0x5a);
    CHECK(close((int)reopened) == 0);
    CHECK(munmap(base, 3 * 4096) == 0);
    puts("mprotect EACCES preserved RX; explicit RW/RX rescanned SVC and guest-only openat stayed intercepted");
    return 0;
}
