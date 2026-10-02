// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A guest whose AArch64 trampoline outgrows the hole between its segments, so
// the rewriter splits it into several independently mapped sub-trampolines.
//
// One asm block fixes the site order: `split_early_svc`, then 4096 never-run
// padding sites needing 256KiB of gates, more than the hole holds, then
// `split_late_svc`. Gates are placed in site order, so the early one lands in
// the hole and the late one past it. The guest checks where its rewritten
// sites branch, then executes both gates.

#include <stdio.h>

#if defined(__aarch64__)
extern const unsigned int split_early_svc[];
extern const unsigned int split_late_svc[];
// Linker- and crt-provided bounds of the hole between text and data.
extern const char etext[];
extern const char __data_start[];

// Target of the `B` the rewriter put at `site`, or 0 if the site is not one.
static unsigned long branch_target(const unsigned int *site) {
    unsigned int word = *site;
    if ((word & 0xfc000000u) != 0x14000000u) {
        return 0;
    }
    long offset = (long)((int)(word << 6) >> 6) * 4;
    return (unsigned long)site + (unsigned long)offset;
}

// Between text and data: a superset of the hole between the segments, which
// still tells it apart from space past the last segment or a runtime region.
static int in_hole(unsigned long address) {
    return address >= (unsigned long)etext && address < (unsigned long)__data_start;
}

static void two_writes(const char *early, unsigned long early_len, const char *late,
                       unsigned long late_len, long run_padding, long *early_ret,
                       long *late_ret) {
    long first, second;
    __asm__ volatile(
        "mov x8, #64\n\t" // SYS_write
        "mov x0, #1\n\t"
        "mov x1, %[early]\n\t"
        "mov x2, %[early_len]\n\t"
        ".globl split_early_svc\n"
        "split_early_svc:\n\t"
        "svc #0\n\t"
        "mov %[first], x0\n\t"
        "cbz %[pad], 1f\n\t"
        ".rept 4096\n\t"
        "svc #0\n\t"
        ".endr\n"
        "1:\n\t"
        "mov x8, #64\n\t"
        "mov x0, #1\n\t"
        "mov x1, %[late]\n\t"
        "mov x2, %[late_len]\n\t"
        ".globl split_late_svc\n"
        "split_late_svc:\n\t"
        "svc #0\n\t"
        "mov %[second], x0\n\t"
        : [first] "=&r"(first), [second] "=&r"(second)
        : [early] "r"(early), [early_len] "r"(early_len), [late] "r"(late),
          [late_len] "r"(late_len), [pad] "r"(run_padding)
        : "x0", "x1", "x2", "x8", "memory");
    *early_ret = first;
    *late_ret = second;
}
#endif

int main(int argc, char **argv) {
    (void)argv;
#if defined(__aarch64__)
    unsigned long early_gate = branch_target(split_early_svc);
    unsigned long late_gate = branch_target(split_late_svc);
    if (!early_gate || !late_gate) {
        printf("sites were not rewritten\n");
        return 1;
    }
    if (!in_hole(early_gate) || in_hole(late_gate)) {
        printf("unexpected gate placement: early %#lx, late %#lx, hole [%p, %p)\n", early_gate,
               late_gate, (const void *)etext, (const void *)__data_start);
        return 1;
    }
    static const char early[] = "early sub-trampoline ok\n";
    static const char late[] = "late sub-trampoline ok\n";
    long early_ret, late_ret;
    two_writes(early, sizeof(early) - 1, late, sizeof(late) - 1, argc > 1000, &early_ret,
               &late_ret);
    if (early_ret < 0 || late_ret < 0) {
        return 1;
    }
#else
    (void)argc;
    printf("early sub-trampoline ok\nlate sub-trampoline ok\n");
#endif
    printf("split trampoline ok\n");
    return 0;
}
