// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#ifdef __x86_64__
#include <cpuid.h>

enum { PRESERVE, EDIT, LEGACY, RESET, NESTED, NO_TRAILER, INITIAL_RESET, INITIAL,
       BAD_MXCSR, BAD_POINTER, BAD_XCOMP, BAD_FEATURE, BAD_ALIGN, BAD_LEGACY_ALIGN };
static volatile sig_atomic_t mode, handled, use_avx;
static sigjmp_buf recovery;
static long pid, tid;
static unsigned int ymm_offset;
static const uint32_t initial_mxcsr = 0x3f80, handler_mxcsr = 0x1f80;
static const unsigned short initial_cw = 0x077f;
static const unsigned char expected[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
};

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s (mode %d)\n", message, mode);
        exit(1);
    }
}

static void handler(int signo, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = context;
    struct _libc_fpstate *fp = uc->uc_mcontext.fpregs;
    if (signo == SIGSEGV) {
        if (mode >= BAD_MXCSR && handled)
            siglongjmp(recovery, 1);
        _exit(2);
    }
    check(fp != NULL, "missing fpregs");
    check(((uintptr_t)fp & 63) == 0, "unaligned extended state");
    if (mode == INITIAL_RESET) {
        uc->uc_mcontext.fpregs = NULL;
        return;
    }
    if (mode == INITIAL) {
        unsigned char zero[16] = {0};
        uint64_t *header = (uint64_t *)((unsigned char *)fp + 512);
        check(fp->cwd == 0x037f && fp->mxcsr == 0x1f80, "materialized initial controls");
        check(memcmp(&fp->_xmm[0], zero, 16) == 0, "materialized initial XMM0");
        check((header[0] & 3) == 3, "initial legacy components marked present");
        fp->cwd = 0x0b7f;
        fp->mxcsr = 0x5f80;
        memset(&fp->_xmm[0], 0x5a, 16);
        handled = 1;
        return;
    }
    if (signo == SIGUSR2) {
        asm volatile("pxor %%xmm0, %%xmm0" : : : "xmm0");
        return;
    }
    check(fp->cwd == initial_cw, "saved x87 control word");
    check(fp->mxcsr == initial_mxcsr, "saved MXCSR");
    check(fp->_st[0].exponent == 0x3fff && fp->_st[0].significand[3] == 0x8000,
          "saved x87 register");
    check(memcmp(&fp->_xmm[0], expected, 16) == 0, "saved XMM0");
    uint32_t *sw = (uint32_t *)((unsigned char *)fp + 464);
    check(sw[0] == 0x46505853, "missing XSAVE metadata");
    check(*(uint32_t *)((unsigned char *)fp + sw[1] - 4) == 0x46505845,
          "missing XSAVE trailer");
    uint64_t *header = (uint64_t *)((unsigned char *)fp + 512);
    check((header[0] & 3) == 3, "legacy state must be materialized");
    if (use_avx) {
        check(memcmp((unsigned char *)fp + ymm_offset, expected + 16, 16) == 0,
              "saved YMM0 high half");
    }
    if (mode == EDIT) {
        memset(&fp->_xmm[0], 0x5a, 16);
        fp->cwd = 0x0b7f;
        fp->mxcsr = 0x5f80;
        fp->_st[0].significand[3] = 0xa000;
        if (use_avx)
            memset((unsigned char *)fp + ymm_offset, 0x5a, 16);
    } else if (mode == LEGACY) {
        sw[0] = 0;
    } else if (mode == RESET) {
        uc->uc_mcontext.fpregs = NULL;
    } else if (mode == NO_TRAILER) {
        *(uint32_t *)((unsigned char *)fp + sw[1] - 4) = 0;
    } else if (mode == BAD_MXCSR) {
        fp->mxcsr = 0xffffffff;
    } else if (mode == BAD_POINTER) {
        uc->uc_mcontext.fpregs = (void *)1;
    } else if (mode == BAD_XCOMP) {
        header[1] = UINT64_C(1) << 63;
    } else if (mode == BAD_FEATURE) {
        header[0] |= UINT64_C(1) << 63;
    } else if (mode == BAD_ALIGN || mode == BAD_LEGACY_ALIGN) {
        static unsigned char copy[65536] __attribute__((aligned(64)));
        unsigned int offset = mode == BAD_ALIGN ? 16 : 1;
        size_t size = sw[1];
        check(size < sizeof(copy) - 64, "FP-state test buffer too small");
        if (mode == BAD_LEGACY_ALIGN) {
            size = 512;
            sw[0] = 0;
        }
        memcpy(copy + offset, fp, size);
        uc->uc_mcontext.fpregs = (void *)(copy + offset);
    }
    asm volatile("fninit\n\tldmxcsr %0\n\tpxor %%xmm0, %%xmm0"
                 : : "m"(handler_mxcsr) : "xmm0", "memory");
    if (use_avx)
        asm volatile("vpxor %%ymm0, %%ymm0, %%ymm0" : : : "xmm0");
    if (mode == NESTED) {
        unsigned char observed[16];
        long result;
        asm volatile("movdqu (%[expected]), %%xmm0\n\t"
                     "syscall\n\t"
                     "movdqu %%xmm0, (%[observed])"
                     : "=a"(result)
                     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR2),
                       [expected] "r"(expected), [observed] "r"(observed)
                     : "rcx", "r11", "xmm0", "memory");
        check(result == 0, "nested tgkill");
        check(memcmp(observed, expected, 16) == 0, "nested signal restoration");
    }
    handled = 1;
}

static void run_case(int test_mode) {
    unsigned char observed[32] = {0};
    unsigned short cw;
    uint32_t mxcsr;
    long double st0;
    long result;
    mode = test_mode;
    handled = 0;
    if (use_avx) {
        asm volatile("fldcw %[cw]\n\tldmxcsr %[mxcsr]\n\tfld1\n\t"
                     "vmovdqu (%[expected]), %%ymm0\n\tsyscall\n\t"
                     "vmovdqu %%ymm0, (%[observed])\n\t"
                     "fnstcw %[out_cw]\n\tstmxcsr %[out_mxcsr]\n\t"
                     "fstpt %[st0]\n\tfninit"
                     : "=a"(result), [out_cw] "=m"(cw), [out_mxcsr] "=m"(mxcsr),
                       [st0] "=m"(st0)
                     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),
                       [cw] "m"(initial_cw), [mxcsr] "m"(initial_mxcsr),
                       [expected] "r"(expected), [observed] "r"(observed)
                     : "rcx", "r11", "xmm0", "memory");
    } else {
        asm volatile("fldcw %[cw]\n\tldmxcsr %[mxcsr]\n\tfld1\n\t"
                     "movdqu (%[expected]), %%xmm0\n\tsyscall\n\t"
                     "movdqu %%xmm0, (%[observed])\n\t"
                     "fnstcw %[out_cw]\n\tstmxcsr %[out_mxcsr]\n\t"
                     "fstpt %[st0]\n\tfninit"
                     : "=a"(result), [out_cw] "=m"(cw), [out_mxcsr] "=m"(mxcsr),
                       [st0] "=m"(st0)
                     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),
                       [cw] "m"(initial_cw), [mxcsr] "m"(initial_mxcsr),
                       [expected] "r"(expected), [observed] "r"(observed)
                     : "rcx", "r11", "xmm0", "memory");
    }
    check(result == 0 && handled, "signal delivery");
    check(cw == (mode == EDIT ? 0x0b7f : mode == RESET ? 0x037f : initial_cw),
          "restored x87 control word");
    check(mxcsr == (mode == EDIT ? 0x5f80 : mode == RESET ? 0x1f80 : initial_mxcsr),
          "restored MXCSR");
    if (mode != RESET)
        check(st0 == (mode == EDIT ? 1.25L : 1.0L), "restored x87 register");
    unsigned char edited[32], zero[32] = {0};
    memset(edited, 0x5a, sizeof(edited));
    const unsigned char *want = mode == EDIT ? edited : mode == RESET ? zero : expected;
    size_t len = use_avx && mode != LEGACY && mode != NO_TRAILER ? 32 : 16;
    check(memcmp(observed, want, len) == 0, "restored vector registers");
}

static void test_initial_state(void) {
    unsigned char observed[16], edited[16];
    unsigned short cw;
    uint32_t mxcsr;
    long result;
    mode = INITIAL_RESET;
    handled = 0;
    /* No FP/SIMD instructions between resetting state and the second signal. */
    asm volatile("syscall\n\tmovl %[initial], %[mode]\n\t"
                 "movl %[sysno], %%eax\n\tsyscall\n\t"
                 "movdqu %%xmm0, (%[observed])\n\t"
                 "fnstcw %[cw]\n\tstmxcsr %[mxcsr]"
                 : "=a"(result), [mode] "+m"(mode), [cw] "=m"(cw),
                   [mxcsr] "=m"(mxcsr)
                 : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),
                   [initial] "i"(INITIAL), [sysno] "i"(SYS_tgkill),
                   [observed] "r"(observed)
                 : "rcx", "r11", "xmm0", "memory");
    memset(edited, 0x5a, sizeof(edited));
    check(result == 0 && handled, "initial-state delivery");
    check(cw == 0x0b7f && mxcsr == 0x5f80, "edits to initial controls");
    check(memcmp(observed, edited, 16) == 0, "edits to initially absent XMM0");
}

int main(void) {
    puts("Testing x86-64 signal FP state");
    static unsigned char altstack[65536];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack) };
    check(sigaltstack(&ss, NULL) == 0, "sigaltstack");
    struct sigaction sa = { .sa_sigaction = handler, .sa_flags = SA_SIGINFO | SA_ONSTACK };
    sigemptyset(&sa.sa_mask);
    check(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction SIGUSR1");
    check(sigaction(SIGUSR2, &sa, NULL) == 0, "sigaction SIGUSR2");
    check(sigaction(SIGSEGV, &sa, NULL) == 0, "sigaction SIGSEGV");
    pid = getpid();
    tid = syscall(SYS_gettid);
    for (int i = PRESERVE; i <= NO_TRAILER; i++)
        run_case(i);
    test_initial_state();
    unsigned int a, b, c, d;
    __cpuid(1, a, b, c, d);
    if ((c & bit_AVX) && (c & bit_OSXSAVE)) {
        unsigned int lo, hi;
        asm volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        if ((lo & 6) == 6) {
            __cpuid_count(0xd, 2, a, b, c, d);
            ymm_offset = b;
            use_avx = 1;
            for (int i = PRESERVE; i <= NO_TRAILER; i++)
                run_case(i);
        }
    }
    for (int i = BAD_MXCSR; i <= BAD_LEGACY_ALIGN; i++) {
        if (sigsetjmp(recovery, 1) == 0) {
            run_case(i);
            check(0, "invalid FP state was accepted");
        }
    }
    puts("All x86-64 signal FP-state tests passed.");
    return 0;
}

#else
int main(void) { return 0; }
#endif
