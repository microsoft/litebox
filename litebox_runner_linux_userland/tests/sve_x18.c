// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// SVE instructions with x18 operands keep their native results, faults and
// signal behavior when the rewriter virtualizes x18. Each asm block sets x18
// before using it, so every x18 use is a rewritten site.

#include "helpers.h"

#include <signal.h>
#include <sys/mman.h>

#if defined(__aarch64__)

#include "sve.h"

#define MAX_LANES (SVE_MAX_VL / 8)

static uint64_t src[2 * MAX_LANES], dst[2 * MAX_LANES];

static void check_memory(unsigned long lanes) {
    for (unsigned long i = 0; i < 2 * MAX_LANES; i++) {
        src[i] = 0x1000 + i;
    }
    memset(dst, 0, sizeof(dst));
    // Copies the first vector to the second with an x18 base, then the second
    // vector of `src` to the first of `dst` with an x18 index.
    asm volatile(".arch_extension sve\n\t"
                 "ptrue p0.d\n\t"
                 "mov x18, %[src]\n\t"
                 "ld1d { z0.d }, p0/z, [x18]\n\t"
                 "mov x18, %[dst]\n\t"
                 "st1d { z0.d }, p0, [x18, #1, mul vl]\n\t"
                 "mov x18, %[lanes]\n\t"
                 "ld1d { z1.d }, p0/z, [%[src], x18, lsl #3]\n\t"
                 "mov x18, xzr\n\t"
                 "st1d { z1.d }, p0, [%[dst], x18, lsl #3]\n\t"
                 :
                 : [src] "r"(src), [dst] "r"(dst), [lanes] "r"(lanes)
                 : "x18", "v0", "v1", "p0", "memory");
    for (unsigned long i = 0; i < lanes; i++) {
        TEST_ASSERT(dst[i] == src[lanes + i], "LD1D with an x18 index differs");
        TEST_ASSERT(dst[lanes + i] == src[i], "ST1D with an x18 base differs");
    }
}

// SP and the gates' default scratches x16 and x17 as operands next to x18.
static void check_special_operands(unsigned long vl, unsigned long lanes) {
    uint64_t stack_data[MAX_LANES], sp, addvl_sp;
    for (unsigned long i = 0; i < lanes; i++) {
        stack_data[i] = 0x3000 + i;
    }
    memset(dst, 0, sizeof(dst));
    asm volatile(".arch_extension sve\n\t"
                 "mov %[sp], sp\n\t"
                 "addvl x18, sp, #3\n\t"
                 "mov %[addvl_sp], x18\n\t"
                 "sub x18, %[data], %[sp]\n\t"
                 "lsr x18, x18, #3\n\t"
                 "ptrue p0.d\n\t"
                 "ld1d { z7.d }, p0/z, [sp, x18, lsl #3]\n\t"
                 "st1d { z7.d }, p0, [%[dst]]\n\t"
                 : [sp] "=&r"(sp), [addvl_sp] "=&r"(addvl_sp)
                 : [data] "r"(stack_data), [dst] "r"(dst)
                 : "x18", "v7", "p0", "memory");
    TEST_ASSERT(addvl_sp == sp + 3 * vl, "ADDVL from SP into x18 differs");
    TEST_ASSERT(memcmp(dst, stack_data, lanes * 8) == 0,
                "LD1D with an SP base and an x18 index differs");

    // WHILELO from x17 = 1 below x18 = 3 activates lanes 0 and 1, which ST1D
    // stores from x16 + 8 * (x18 = 1).
    for (unsigned long i = 0; i < lanes; i++) {
        src[i] = 0x4000 + i;
    }
    memset(dst, 0, sizeof(dst));
    register uint64_t x16 asm("x16") = (uintptr_t)dst;
    register uint64_t x17 asm("x17") = 1;
    asm volatile(".arch_extension sve\n\t"
                 "ptrue p0.d\n\t"
                 "ld1d { z0.d }, p0/z, [%[src]]\n\t"
                 "mov x18, #3\n\t"
                 "whilelo p1.d, x17, x18\n\t"
                 "mov x18, #1\n\t"
                 "st1d { z0.d }, p1, [x16, x18, lsl #3]\n\t"
                 : "+r"(x16), "+r"(x17)
                 : [src] "r"(src)
                 : "x18", "v0", "p0", "p1", "memory");
    TEST_ASSERT(x16 == (uintptr_t)dst && x17 == 1, "an x18 gate changed x16 or x17");
    for (unsigned long i = 0; i < 2 * MAX_LANES; i++) {
        uint64_t expected = i == 1 || i == 2 ? src[i - 1] : 0;
        TEST_ASSERT(dst[i] == expected, "WHILELO from x17 to x18 or ST1D from x16 and x18 differs");
    }
}

// LDFF1D with an x18 base whose first element is readable and whose second is
// on an inaccessible page raises no signal, loads lane 0 and leaves FFR true
// for element 0 only.
static void check_partial_first_fault(unsigned long lanes) {
    uint8_t *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(pages != MAP_FAILED, "mmap failed");
    TEST_ASSERT(mprotect(pages + 4096, 4096, PROT_NONE) == 0, "mprotect failed");
    uint64_t *first = (uint64_t *)(pages + 4096) - 1;
    *first = 0x5151;
    uint8_t ffr[SVE_MAX_VL / 8];
    uint64_t lane0;
    asm volatile(".arch_extension sve\n\t"
                 "ptrue p0.d\n\t"
                 "setffr\n\t"
                 "mov x18, %[first]\n\t"
                 "ldff1d { z5.d }, p0/z, [x18]\n\t"
                 "rdffr p1.b\n\t"
                 "str p1, [%[ffr]]\n\t"
                 "fmov %[lane0], d5\n\t"
                 : [lane0] "=r"(lane0)
                 : [first] "r"(first), [ffr] "r"(ffr)
                 : "x18", "v5", "p0", "p1", "ffr", "memory");
    TEST_ASSERT(lane0 == 0x5151, "LDFF1D with an x18 base did not load lane 0");
    TEST_ASSERT(ffr[0] == 0xff, "LDFF1D with an x18 base cleared FFR for element 0");
    for (unsigned long i = 1; i < lanes; i++) {
        TEST_ASSERT(ffr[i] == 0, "LDFF1D with an x18 base kept FFR for a faulting element");
    }
    TEST_ASSERT(munmap(pages, 8192) == 0, "munmap failed");
}

// Returns NZCV after CTERMEQ of x18 = `a` and x0 = `b`, starting from `preset`.
static uint64_t ctermeq_x18_nzcv(uint64_t a, uint64_t b, uint64_t preset) {
    register uint64_t x0 asm("x0") = b;
    uint64_t nzcv;
    asm volatile(".arch_extension sve\n\t"
                 "msr nzcv, %[preset]\n\t"
                 "mov x18, %[a]\n\t"
                 "ctermeq x18, x0\n\t"
                 "mrs %[nzcv], nzcv\n\t"
                 : [nzcv] "=&r"(nzcv)
                 : [preset] "r"(preset), [a] "r"(a), "r"(x0)
                 : "x18", "cc");
    return nzcv;
}

static volatile uintptr_t fault_site, fault_pc, fault_address, fault_x18, fault_sp;

static void segv_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    ucontext_t *uc = context;
    fault_pc = uc->uc_mcontext.pc;
    fault_address = (uintptr_t)info->si_addr;
    fault_x18 = uc->uc_mcontext.regs[18];
    fault_sp = uc->uc_mcontext.sp;
    // Skip the faulting load.
    uc->uc_mcontext.pc = fault_site + 4;
}

// A load with an x18 base from an inaccessible page raises SIGSEGV at the
// load, for its first element, with the guest's x18 and SP at the load.
static void check_fault(unsigned long vl) {
    uint8_t *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(page != MAP_FAILED, "mmap failed");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    TEST_ASSERT(sigaction(SIGSEGV, &sa, NULL) == 0, "sigaction failed");
    uintptr_t site, sp;
    asm volatile(".arch_extension sve\n\t"
                 "adr %[site], 1f\n\t"
                 "str %[site], [%[slot]]\n\t"
                 "mov %[sp], sp\n\t"
                 "ptrue p0.d\n\t"
                 "mov x18, %[page]\n\t"
                 "1: ld1d { z6.d }, p0/z, [x18]\n\t"
                 : [site] "=&r"(site), [sp] "=&r"(sp)
                 : [slot] "r"(&fault_site), [page] "r"(page)
                 : "x18", "v6", "p0", "memory");
    TEST_ASSERT(fault_pc == site, "SIGSEGV from an x18-based load has the wrong PC");
    TEST_ASSERT(fault_address >= (uintptr_t)page && fault_address < (uintptr_t)page + vl,
                "SIGSEGV from an x18-based load has the wrong fault address");
    TEST_ASSERT(fault_x18 == (uintptr_t)page, "SIGSEGV from an x18-based load has the wrong x18");
    TEST_ASSERT(fault_sp == sp, "SIGSEGV from an x18-based load has the wrong SP");
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    TEST_ASSERT(sigaction(SIGSEGV, &sa, NULL) == 0, "sigaction failed");
    TEST_ASSERT(munmap(page, 4096) == 0, "munmap failed");
}

static void check_scalars(unsigned long vl, unsigned long lanes) {
    uint64_t cntd, incd;
    asm volatile(".arch_extension sve\n\t"
                 "cntd x18\n\t"
                 "mov %[cntd], x18\n\t"
                 "mov x18, #5\n\t"
                 "incd x18, all, mul #2\n\t"
                 "mov %[incd], x18\n\t"
                 : [cntd] "=&r"(cntd), [incd] "=&r"(incd)
                 :
                 : "x18");
    TEST_ASSERT(cntd == lanes, "CNTD into x18 differs");
    TEST_ASSERT(incd == 5 + 2 * lanes, "INCD of x18 differs");

    // WHILELO from x18 = 1 below 2 activates only the first lane: N set (first
    // lane active), Z clear (a lane active), C set (last lane inactive). It
    // starts from Z and V set, which no WHILELO result has.
    uint64_t whilelo_nzcv;
    asm volatile(".arch_extension sve\n\t"
                 "msr nzcv, %[preset]\n\t"
                 "mov x18, %[start]\n\t"
                 "whilelo p1.d, x18, %[limit]\n\t"
                 "mrs %[nzcv], nzcv\n\t"
                 : [nzcv] "=&r"(whilelo_nzcv)
                 : [preset] "r"(0x50000000UL), [start] "r"(1UL), [limit] "r"(2UL)
                 : "x18", "p1", "cc");
    TEST_ASSERT(whilelo_nzcv == 0xa0000000, "WHILELO from x18: only the first lane");

    // CTERMEQ keeps Z and C. Equal operands set N and clear V; otherwise it
    // clears N and sets V to NOT C.
    TEST_ASSERT(ctermeq_x18_nzcv(7, 7, 0x70000000) == 0xe0000000, "CTERMEQ of equal x18 differs");
    TEST_ASSERT(ctermeq_x18_nzcv(7, 8, 0xc0000000) == 0x50000000,
                "CTERMEQ of unequal x18 differs");

    // UQINCW of w18 zero-extends, and SQINCW of x18, w18 sign-extends, both
    // ignoring x18's high bits.
    uint64_t uqincw, sqincw;
    asm volatile(".arch_extension sve\n\t"
                 "mov x18, %[unsigned_start]\n\t"
                 "uqincw w18\n\t"
                 "mov %[uqincw], x18\n\t"
                 "mov x18, %[signed_start]\n\t"
                 "sqincw x18, w18\n\t"
                 "mov %[sqincw], x18\n\t"
                 : [uqincw] "=&r"(uqincw), [sqincw] "=&r"(sqincw)
                 : [unsigned_start] "r"(0xdeadbeef00000005UL),
                   [signed_start] "r"(0x12345678fffffc18UL)
                 : "x18");
    TEST_ASSERT(uqincw == 5 + vl / 4, "UQINCW of w18 differs");
    TEST_ASSERT(sqincw == (uint64_t)(-1000 + (int64_t)(vl / 4)), "SQINCW of x18, w18 differs");
}

#define GATE_INTERRUPTIONS 30

static int gate_alarms;
static struct sve_regs pattern, observed;
static const struct itimerval gate_timer = {.it_value = {.tv_usec = 1000}};

// Clobbers x18 and SVE registers, which the frame restores, and re-arms the
// one-shot timer until enough alarms arrived.
static void gate_alarm_handler(int signo) {
    (void)signo;
    asm volatile("mov x18, xzr" : : : "x18");
    SVE_CLOBBER_SOME();
    if (__atomic_add_fetch(&gate_alarms, 1, __ATOMIC_RELEASE) < GATE_INTERRUPTIONS) {
        setitimer(ITIMER_REAL, &gate_timer, NULL);
    }
}

// Spins through x18 gates with a live state in every Z and P register and
// FFR, which the loop does not touch, until enough alarms interrupt it or the
// budget runs out.
static void check_interrupted_gates(unsigned long vl, unsigned long lanes) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = gate_alarm_handler;
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");
    sve_fill_pattern(&pattern, 0);
    unsigned long budget = 1UL << 36, iterations = 0;
    uint64_t x18;
    TEST_ASSERT(setitimer(ITIMER_REAL, &gate_timer, NULL) == 0, "setitimer failed");
    asm volatile(".arch_extension sve\n\t" SVE_LOAD_ALL
                 "mov x18, xzr\n\t"
                 "1:\n\t"
                 "incd x18\n\t"
                 "addvl x18, x18, #1\n\t"
                 "incd x18\n\t"
                 "addvl x18, x18, #1\n\t"
                 "add %[iterations], %[iterations], #1\n\t"
                 "ldar w9, [%[alarms]]\n\t"
                 "subs %[budget], %[budget], #1\n\t"
                 "ccmp w9, #%[target], #0, ne\n\t"
                 "b.lt 1b\n\t"
                 "mov %[x18], x18\n\t" SVE_STORE_ALL
                 : [budget] "+r"(budget), [iterations] "+r"(iterations), [x18] "=&r"(x18)
                 : SVE_LOAD_OPERANDS(&pattern), SVE_STORE_OPERANDS(&observed),
                   [alarms] "r"(&gate_alarms), [target] "i"(GATE_INTERRUPTIONS)
                 : SVE_CLOBBERS, "x9", "x18", "cc");
    const struct itimerval disarm = {0};
    TEST_ASSERT(setitimer(ITIMER_REAL, &disarm, NULL) == 0, "disarming setitimer failed");
    TEST_ASSERT(__atomic_load_n(&gate_alarms, __ATOMIC_ACQUIRE) >= GATE_INTERRUPTIONS,
                "too few alarms interrupted the x18 gates");
    TEST_ASSERT(x18 == iterations * 2 * (lanes + vl), "interrupted x18 gates computed wrong x18");
    const char *error = sve_compare(&observed, &pattern, vl);
    TEST_ASSERT(error == NULL, error);
}

int main(void) {
    if (!sve_available()) {
        printf("sve unavailable\n");
        return 0;
    }
    unsigned long vl = sve_vl();
    TEST_ASSERT(vl % 16 == 0 && vl <= SVE_MAX_VL, "unexpected vector length");
    printf("sve vl %lu\n", vl);
    check_memory(vl / 8);
    check_special_operands(vl, vl / 8);
    check_partial_first_fault(vl / 8);
    check_scalars(vl, vl / 8);
    check_fault(vl);
    check_interrupted_gates(vl, vl / 8);
    printf("sve x18 ok\n");
    return 0;
}

#else

int main(void) { return 0; }

#endif
