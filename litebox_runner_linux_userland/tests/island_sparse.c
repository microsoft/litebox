// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    int fd = open("/lib/island_sparse.so", O_RDONLY);
    Elf64_Ehdr eh;
    Elf64_Phdr ph[2];
    if (fd < 0 || pread(fd, &eh, sizeof eh, 0) != sizeof eh
        || pread(fd, ph, sizeof ph, eh.e_phoff) != sizeof ph) return 1;
    size_t span = (ph[1].p_vaddr + ph[1].p_memsz + 4095) & ~4095UL;
    // Unrelated reservation below the final LOAD eliminates ALL lower and
    // inter-LOAD candidates in branch reach, without granting gap ownership.
    char *base = mmap((void *)0x200000000ULL, span, PROT_NONE,
        MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return 2;
    char *code = mmap(base + ph[1].p_vaddr, 4096, PROT_READ | PROT_EXEC,
        MAP_PRIVATE | MAP_FIXED, fd, ph[1].p_offset);
    if (code == MAP_FAILED || close(fd)) return 3;
    const uint32_t *site = (const uint32_t *)code + 1;
    if ((*site & 0xfc000000) != 0x14000000) return 4;
    uintptr_t target = (uintptr_t)site + ((int64_t)(int32_t)(*site << 6) >> 4);
    if (target < (uintptr_t)base + span) return 5;
    if (((long (*)(void))code)() != 201) return 6;
    if (munmap(base, span)) return 7;
    puts("sparse >256MiB DSO executed through above-image islands; unrelated gap untouched");
    return 0;
}
