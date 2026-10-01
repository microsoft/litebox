// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The static non-PIE guest lives low while full chunks are allocated top-down.
// Inspect the *executed* branch chain rather than accepting an old-path pass.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern long island_pair_probe(void);
extern const uint32_t island_pair_site[];
asm(".text\n"
    ".global island_pair_probe\n"
    ".type island_pair_probe,%function\n"
    "island_pair_probe:\n"
    "mov x9, x30\n"
    "mov x16, #12345\n"
    "mov x30, #54321\n"
    // getrandom writes over the entire old callback/island frame while the
    // shim runs on its own stack. Outbound must rebuild x16 AND x30 from PtRegs.
    "sub x0, sp, #32\n"
    "mov x1, #32\n"
    "mov x2, #0\n"
    "mov x8, #278\n"
    ".global island_pair_site\n"
    "island_pair_site: svc #0\n"
    "cmp x0, #32\n"
    "b.ne 1f\n"
    "mov x10, #12345\n"
    "cmp x16, x10\n"
    "b.ne 1f\n"
    "mov x10, #54321\n"
    "cmp x30, x10\n"
    "b.ne 1f\n"
    "mov x0, #0\n"
    "br x9\n"
    "1: mov x0, #1\n"
    "br x9\n"
    ".size island_pair_probe, .-island_pair_probe\n");

static uintptr_t branch(const uint32_t *pc) {
    int64_t delta = (int32_t)(*pc << 6) >> 4;
    return (uintptr_t)pc + delta;
}
int main(void) {
    if ((*island_pair_site & 0xfc000000) != 0x14000000) return 2;
    const uint32_t *entry = (const uint32_t *)branch(island_pair_site);
    if (entry[0] != 0xd10043ff || entry[1] != 0xa9007bf0
        || (entry[2] & 0xfc000000) != 0x94000000) return 3;
    const uint32_t *island = (const uint32_t *)branch(entry + 2);
    if (island[0] != 0x58000090 || island[2] != 0xd61f0200) return 4;
    uint64_t delta = *(const uint64_t *)(island + 4);
    uintptr_t table = (uintptr_t)island + 44 + delta;
    uintptr_t far = table - 16;
    uintptr_t distance = far > (uintptr_t)island ? far - (uintptr_t)island : (uintptr_t)island - far;
    if (distance <= (1ULL << 32)) return 5;
    if (island_pair_probe() != 0) return 6;
    // The main-image provenance must prevent an island at image+16MiB from
    // capping brk. Full chunks belong at arbitrary top-down VA, not in this gap.
    char *heap = sbrk(32 * 1024 * 1024);
    if (heap == (void *)-1) return 7;
    heap[0] = 1;
    heap[32 * 1024 * 1024 - 1] = 2;
    printf("island execution: near=%p far=%p distance=%lu; overwritten-frame x16/x30 restored\n",
           (void *)island, (void *)far, (unsigned long)distance);
    return 0;
}
