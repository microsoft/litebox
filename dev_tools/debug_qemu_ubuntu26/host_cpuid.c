// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// DEBUG (ubuntu-26.04 CI SIGILL): prints the host's CPUID leaves, as the
// runner VM sees them, and what KVM supports exposing to its guests
// (KVM_GET_SUPPORTED_CPUID).

#include <cpuid.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

static const unsigned LEAVES[][2] = {
    {0x1, 0},  {0x7, 0},  {0x7, 1},  {0xd, 0},  {0xd, 1},  {0x14, 0},
    {0x19, 0}, {0x24, 0}, {0x80000001, 0}, {0x80000007, 0}, {0x80000008, 0},
    {0x80000021, 0},
};

int main(void) {
    for (size_t i = 0; i < sizeof(LEAVES) / sizeof(LEAVES[0]); i++) {
        unsigned a, b, c, d;
        if (!__get_cpuid_count(LEAVES[i][0], LEAVES[i][1], &a, &b, &c, &d)) {
            continue;
        }
        printf("host cpuid %#x.%u: %#010x %#010x %#010x %#010x\n", LEAVES[i][0], LEAVES[i][1],
               a, b, c, d);
    }
    int kvm = open("/dev/kvm", O_RDWR);
    if (kvm < 0) {
        perror("/dev/kvm");
        return 1;
    }
    int n = 256;
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + n * sizeof(struct kvm_cpuid_entry2));
    cpuid->nent = n;
    if (ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) < 0) {
        perror("KVM_GET_SUPPORTED_CPUID");
        return 1;
    }
    for (unsigned i = 0; i < cpuid->nent; i++) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        printf("kvm supported %#x.%u: %#010x %#010x %#010x %#010x\n", e->function, e->index,
               e->eax, e->ebx, e->ecx, e->edx);
    }
    return 0;
}
