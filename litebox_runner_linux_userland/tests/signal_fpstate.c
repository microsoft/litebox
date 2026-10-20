// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>

#ifdef __x86_64__
#include <cpuid.h>

#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51
#endif

enum { PRESERVE, EDIT, LEGACY, RESET, NESTED, NO_TRAILER, INITIAL_RESET, INITIAL,
       MASK_SSE, INIT_SSE, MASK_AVX, SHORT_XSTATE,
       FAULT, ASYNC, RED_ZONE, MIN_ALTSTACK,
       BAD_MXCSR, BAD_POINTER, BAD_XCOMP, BAD_FEATURE, BAD_ALIGN, BAD_LEGACY_ALIGN,
       BAD_INACCESSIBLE, BAD_UNMAPPED, BAD_LEGACY_READ, BAD_TRAILER_READ,
       BAD_SHORT_XSTATE };
static volatile sig_atomic_t mode, handled, use_avx;
static volatile greg_t frame_rip;
static sigjmp_buf recovery;
static long pid, tid;
static unsigned int ymm_offset;
static unsigned char *guard_page;
static void *unmapped_fpstate;
static stack_t current_altstack;
/* Handlers load values that differ from every state a restore can produce. */
static const uint32_t initial_mxcsr = 0x3f80, handler_mxcsr = 0x9f80, default_mxcsr = 0x1f80;
static const unsigned short initial_cw = 0x077f, handler_cw = 0x0f7f;
static const unsigned char expected[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
};

/* Async-signal-safe: failures are also reported from signal handlers. */
static void check(int condition, const char *message) {
    if (condition)
        return;
    char buf[192], digits[12];
    size_t len = 0, ndigits = 0;
    unsigned int value = (unsigned int)mode;
    const char *parts[] = {"FAIL: ", message, " (mode "};
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
        for (const char *c = parts[i]; *c && len < sizeof(buf) - 16; c++)
            buf[len++] = *c;
    do
        digits[ndigits++] = (char)('0' + value % 10);
    while ((value /= 10) != 0);
    while (ndigits)
        buf[len++] = digits[--ndigits];
    buf[len++] = ')';
    buf[len++] = '\n';
    (void)!write(STDERR_FILENO, buf, len);
    _exit(1);
}

static void check_initial_fpstate(const struct _libc_fpstate *fp, const char *message) {
    static const unsigned char zero[16];
    check(fp != NULL && fp->cwd == 0x037f && fp->mxcsr == default_mxcsr, message);
    check(memcmp(&fp->_xmm[0], zero, 16) == 0, message);
    if (use_avx)
        check(memcmp((const unsigned char *)fp + ymm_offset, zero, 16) == 0, message);
}

/* Checks the state that fault and async cases load before being interrupted. */
static void check_interrupted_fpstate(const struct _libc_fpstate *fp) {
    check(fp != NULL && ((uintptr_t)fp & 63) == 0, "interrupted FP state");
    check(fp->cwd == initial_cw && fp->mxcsr == initial_mxcsr, "interrupted controls");
    check(memcmp(&fp->_xmm[0], expected, 16) == 0, "interrupted XMM0");
    if (use_avx)
        check(memcmp((const unsigned char *)fp + ymm_offset, expected + 16, 16) == 0,
              "interrupted YMM0 high half");
}

static void clobber_vector_state(void) {
    asm volatile("fninit\n\tfldcw %0\n\tldmxcsr %1\n\tpcmpeqd %%xmm0, %%xmm0"
                 : : "m"(handler_cw), "m"(handler_mxcsr) : "xmm0", "memory");
    if (use_avx)
        asm volatile("vxorps %%ymm0, %%ymm0, %%ymm0\n\t"
                     "vcmpps $0, %%ymm0, %%ymm0, %%ymm0" : : : "xmm0");
}

static void fault_handler(int signo, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = context;
    check(signo == SIGILL && mode == FAULT, "unexpected SIGILL");
    check_interrupted_fpstate(uc->uc_mcontext.fpregs);
    clobber_vector_state();
    uc->uc_mcontext.gregs[REG_RIP] += 2; /* ud2 */
    handled = 1;
}

static void async_handler(int signo, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = context;
    check(signo == SIGALRM && mode == ASYNC, "unexpected SIGALRM");
    check_interrupted_fpstate(uc->uc_mcontext.fpregs);
    clobber_vector_state();
    handled = 1;
}

static void stack_handler(int signo, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = context;
    const unsigned char *fp = (const unsigned char *)uc->uc_mcontext.fpregs;
    check(((uintptr_t)__builtin_frame_address(0) & 15) == 0, "handler stack alignment");
    check(fp != NULL && ((uintptr_t)fp & 63) == 0 && fp > (const unsigned char *)uc,
          "FP state placement");
    if (signo == SIGXCPU) {
        const unsigned char *bottom = current_altstack.ss_sp;
        const unsigned char *top = bottom + current_altstack.ss_size;
        uint32_t extended_size = *(const uint32_t *)(fp + 468);
        check((const unsigned char *)uc >= bottom && fp + extended_size <= top,
              "signal frame within the minimum alternate stack");
    }
    handled = 1;
}

static void handler(int signo, siginfo_t *info, void *context) {
    (void)info;
    ucontext_t *uc = context;
    struct _libc_fpstate *fp = uc->uc_mcontext.fpregs;
    check(((uintptr_t)__builtin_frame_address(0) & 15) == 0, "handler stack alignment");
    if (signo == SIGSEGV) {
        check(mode >= BAD_MXCSR && handled, "unexpected SIGSEGV");
        /* Linux restores registers first, then fails with initial FP state. */
        check(info->si_code == SI_KERNEL, "bad-frame SIGSEGV code");
        check(uc->uc_mcontext.gregs[REG_RIP] == frame_rip &&
                  uc->uc_mcontext.gregs[REG_RAX] == 0,
              "registers restored before FP-state failure");
        check_initial_fpstate(fp, "FP state reset after failed sigreturn");
        siglongjmp(recovery, 1);
    }
    check(fp != NULL, "missing fpregs");
    check(((uintptr_t)fp & 63) == 0, "unaligned extended state");
    if (mode == INITIAL_RESET) {
        uc->uc_mcontext.fpregs = NULL;
        return;
    }
    if (mode == INITIAL) {
        uint64_t *header = (uint64_t *)((unsigned char *)fp + 512);
        check_initial_fpstate(fp, "materialized initial state");
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
    check((uc->uc_flags & 7) == 7, "UC_FP_XSTATE, UC_SIGCONTEXT_SS and UC_STRICT_RESTORE_SS");
    frame_rip = uc->uc_mcontext.gregs[REG_RIP];
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
    } else if (mode == MASK_SSE) {
        *(uint64_t *)(sw + 2) &= ~UINT64_C(2);
        fp->mxcsr = 0x5f80;
    } else if (mode == INIT_SSE) {
        header[0] &= ~UINT64_C(2);
        fp->mxcsr = 0x5f80;
    } else if (mode == MASK_AVX) {
        *(uint64_t *)(sw + 2) &= ~UINT64_C(4);
    } else if (mode == SHORT_XSTATE) {
        header[0] = 3;
        sw[1] = 580;
        sw[4] = 576;
        /* The trailer follows the shortened XSAVE area. */
        *(uint32_t *)((unsigned char *)fp + 576) = 0x46505845;
    } else if (mode == BAD_SHORT_XSTATE) {
        unsigned char *copy = guard_page - 640;
        memcpy(copy, fp, 576);
        uint32_t *copy_sw = (uint32_t *)(copy + 464);
        uint64_t *copy_header = (uint64_t *)(copy + 512);
        copy_sw[1] = 580;
        copy_sw[4] = 576;
        copy_header[0] = 7;
        *(uint32_t *)(copy + 576) = 0x46505845;
        uc->uc_mcontext.fpregs = (void *)copy;
    } else if (mode == BAD_MXCSR) {
        fp->mxcsr = 0xffffffff;
    } else if (mode == BAD_POINTER) {
        /* Aligned, but not a user address. */
        uc->uc_mcontext.fpregs = (void *)UINT64_C(0xffff800000000000);
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
    } else if (mode == BAD_INACCESSIBLE) {
        uc->uc_mcontext.fpregs = (void *)guard_page;
    } else if (mode == BAD_UNMAPPED) {
        uc->uc_mcontext.fpregs = unmapped_fpstate;
    } else if (mode == BAD_LEGACY_READ) {
        memcpy(guard_page - 256, fp, 256);
        uc->uc_mcontext.fpregs = (void *)(guard_page - 256);
    } else if (mode == BAD_TRAILER_READ) {
        unsigned char *copy = guard_page - 576;
        memcpy(copy, fp, 576);
        uint32_t *copy_sw = (uint32_t *)(copy + 464);
        copy_sw[1] = 580;
        copy_sw[4] = 576;
        uc->uc_mcontext.fpregs = (void *)copy;
    }
    clobber_vector_state();
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
                     "fstpt %[st0]\n\tfninit\n\tldmxcsr %[default_mxcsr]"
                     : "=a"(result), [out_cw] "=m"(cw), [out_mxcsr] "=m"(mxcsr),
                       [st0] "=m"(st0)
                     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),
                       [cw] "m"(initial_cw), [mxcsr] "m"(initial_mxcsr),
                       [default_mxcsr] "m"(default_mxcsr),
                       [expected] "r"(expected), [observed] "r"(observed)
                     : "rcx", "r11", "xmm0", "memory");
    } else {
        asm volatile("fldcw %[cw]\n\tldmxcsr %[mxcsr]\n\tfld1\n\t"
                     "movdqu (%[expected]), %%xmm0\n\tsyscall\n\t"
                     "movdqu %%xmm0, (%[observed])\n\t"
                     "fnstcw %[out_cw]\n\tstmxcsr %[out_mxcsr]\n\t"
                     "fstpt %[st0]\n\tfninit\n\tldmxcsr %[default_mxcsr]"
                     : "=a"(result), [out_cw] "=m"(cw), [out_mxcsr] "=m"(mxcsr),
                       [st0] "=m"(st0)
                     : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),
                       [cw] "m"(initial_cw), [mxcsr] "m"(initial_mxcsr),
                       [default_mxcsr] "m"(default_mxcsr),
                       [expected] "r"(expected), [observed] "r"(observed)
                     : "rcx", "r11", "xmm0", "memory");
    }
    check(result == 0 && handled, "signal delivery");
    check(cw == (mode == EDIT ? 0x0b7f : mode == RESET ? 0x037f : initial_cw),
          "restored x87 control word");
    /* Linux sigreturn initializes SSE controls when software xfeatures omits SSE. */
    check(mxcsr == (mode == EDIT || mode == INIT_SSE ? 0x5f80 :
                   mode == RESET || mode == MASK_SSE ? 0x1f80 : initial_mxcsr),
          "restored MXCSR");
    if (mode != RESET)
        check(st0 == (mode == EDIT ? 1.25L : 1.0L), "restored x87 register");
    unsigned char edited[32], zero[32] = {0};
    memset(edited, 0x5a, sizeof(edited));
    const unsigned char *want =
        mode == EDIT ? edited :
        mode == RESET || mode == MASK_SSE || mode == INIT_SSE ? zero : expected;
    check(memcmp(observed, want, 16) == 0, "restored XMM0");
    if (use_avx) {
        /* Linux initializes components omitted by legacy frames or feature masks. */
        const unsigned char *want_high = mode == EDIT ? edited :
            mode == RESET || mode == LEGACY || mode == NO_TRAILER ||
            mode == MASK_AVX || mode == SHORT_XSTATE ? zero : expected + 16;
        check(memcmp(observed + 16, want_high, 16) == 0, "restored YMM0 high half");
    }
}

static void test_initial_state(void) {
    unsigned char observed[32], edited[16], zero[16] = {0};
    unsigned short cw;
    uint32_t mxcsr;
    long result;
    mode = INITIAL_RESET;
    handled = 0;
    /* No FP/SIMD instructions between resetting state and the second signal. */
#define INITIAL_STATE_ASM(store)                                                     \
    asm volatile("syscall\n\tmovl %[initial], %[mode]\n\t"                          \
                 "movl %[sysno], %%eax\n\tsyscall\n\t" store "\n\t"                 \
                 "fnstcw %[cw]\n\tstmxcsr %[mxcsr]\n\tfninit\n\tldmxcsr %[default_mxcsr]" \
                 : "=a"(result), [mode] "+m"(mode), [cw] "=m"(cw), [mxcsr] "=m"(mxcsr) \
                 : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGUSR1),      \
                   [initial] "i"(INITIAL), [sysno] "i"(SYS_tgkill),                    \
                   [default_mxcsr] "m"(default_mxcsr), [observed] "r"(observed)        \
                 : "rcx", "r11", "xmm0", "memory")
    if (use_avx)
        INITIAL_STATE_ASM("vmovdqu %%ymm0, (%[observed])");
    else
        INITIAL_STATE_ASM("movdqu %%xmm0, (%[observed])");
#undef INITIAL_STATE_ASM
    memset(edited, 0x5a, sizeof(edited));
    check(result == 0 && handled, "initial-state delivery");
    check(cw == 0x0b7f && mxcsr == 0x5f80, "edits to initial controls");
    check(memcmp(observed, edited, 16) == 0, "edits to initially absent XMM0");
    if (use_avx)
        check(memcmp(observed + 16, zero, 16) == 0, "initial YMM0 high half");
}

/* Operands shared by cases that load `expected` and observe it afterwards. */
#define LOAD_STATE(mov, reg) \
    "fldcw %[cw]\n\tldmxcsr %[mxcsr]\n\t" mov " (%[expected]), %%" reg "\n\t"
#define STORE_STATE(mov, reg)                                                   \
    mov " %%" reg ", (%[observed])\n\tfnstcw %[out_cw]\n\tstmxcsr %[out_mxcsr]\n\t" \
    "fninit\n\tldmxcsr %[default_mxcsr]"
#define STATE_OUTPUTS [out_cw] "=m"(cw), [out_mxcsr] "=m"(mxcsr)
#define STATE_INPUTS                                                            \
    [cw] "m"(initial_cw), [mxcsr] "m"(initial_mxcsr),                           \
    [default_mxcsr] "m"(default_mxcsr), [expected] "r"(expected), [observed] "r"(observed)

static void check_restored_state(const unsigned char *observed, unsigned short cw,
                                 uint32_t mxcsr) {
    check(handled, "signal delivery");
    check(cw == initial_cw && mxcsr == initial_mxcsr, "restored controls");
    check(memcmp(observed, expected, use_avx ? 32 : 16) == 0, "restored vector register");
}

/* A handler for a hardware exception must save and restore the faulting state. */
static void test_fault(void) {
    unsigned char observed[32] = {0};
    unsigned short cw;
    uint32_t mxcsr;
    mode = FAULT;
    handled = 0;
#define FAULT_ASM(mov, reg)                                                      \
    asm volatile(LOAD_STATE(mov, reg) "ud2\n\t" STORE_STATE(mov, reg)            \
                 : STATE_OUTPUTS : STATE_INPUTS : "xmm0", "memory")
    if (use_avx)
        FAULT_ASM("vmovdqu", "ymm0");
    else
        FAULT_ASM("movdqu", "xmm0");
#undef FAULT_ASM
    check_restored_state(observed, cw, mxcsr);
}

/* A timer interrupts guest code asynchronously, outside any syscall. */
static void test_async(void) {
    unsigned char observed[32] = {0};
    unsigned short cw;
    uint32_t mxcsr;
    long result;
    struct itimerval timer = { .it_value = { .tv_usec = 10000 } };
    mode = ASYNC;
    handled = 0;
#define ASYNC_ASM(mov, reg)                                                      \
    asm volatile(LOAD_STATE(mov, reg) "syscall\n"                                 \
                 "1:\n\tcmpl $0, (%[flag])\n\tje 1b\n\t" STORE_STATE(mov, reg)     \
                 : "=a"(result), STATE_OUTPUTS                                    \
                 : "a"((long)SYS_setitimer), "D"((long)ITIMER_REAL), "S"(&timer),   \
                   "d"(0L), [flag] "r"(&handled), STATE_INPUTS                      \
                 : "rcx", "r11", "xmm0", "memory")
    if (use_avx)
        ASYNC_ASM("vmovdqu", "ymm0");
    else
        ASYNC_ASM("movdqu", "xmm0");
#undef ASYNC_ASM
    check(result == 0, "setitimer");
    check_restored_state(observed, cw, mxcsr);
}

/* Delivery on the current stack must skip the 128-byte red zone below SP. */
static void test_red_zone(void) {
    long result, intact;
    mode = RED_ZONE;
    handled = 0;
    asm volatile("sub $256, %%rsp\n\t"
                 "movabs $0x5a5a5a5a5a5a5a5a, %%r9\n\t"
                 "mov $16, %%ecx\n"
                 "1:\n\tmov %%rcx, %%r8\n\txor %%r9, %%r8\n\t"
                 "mov %%r8, -136(%%rsp,%%rcx,8)\n\tdec %%rcx\n\tjnz 1b\n\t"
                 "syscall\n\t"
                 "xor %%ebx, %%ebx\n\tmov $16, %%ecx\n"
                 "2:\n\tmov %%rcx, %%r8\n\txor %%r9, %%r8\n\t"
                 "cmp %%r8, -136(%%rsp,%%rcx,8)\n\tjne 3f\n\tdec %%rcx\n\tjnz 2b\n\t"
                 "mov $1, %%ebx\n"
                 "3:\n\tadd $256, %%rsp"
                 : "=a"(result), "=&b"(intact)
                 : "a"((long)SYS_tgkill), "D"(pid), "S"(tid), "d"((long)SIGURG)
                 : "rcx", "r8", "r9", "r11", "memory", "cc");
    check(result == 0 && handled, "red-zone signal delivery");
    check(intact, "red zone preserved");
}

/* A frame must fit in an alternate stack of the advertised minimum size. */
static void test_min_altstack(void) {
    static unsigned char buffer[65536] __attribute__((aligned(64)));
    unsigned long size = getauxval(AT_MINSIGSTKSZ);
    check(size != 0, "AT_MINSIGSTKSZ");
    if (size < (unsigned long)MINSIGSTKSZ)
        size = (unsigned long)MINSIGSTKSZ;
    check(size <= sizeof(buffer) / 2, "AT_MINSIGSTKSZ too large");
    stack_t old;
    /* The handler's own frames may grow below the alternate stack into `buffer`. */
    current_altstack = (stack_t){ .ss_sp = buffer + sizeof(buffer) - size, .ss_size = size };
    check(sigaltstack(&current_altstack, &old) == 0, "minimum sigaltstack");
    mode = MIN_ALTSTACK;
    handled = 0;
    check(syscall(SYS_tgkill, pid, tid, SIGXCPU) == 0 && handled, "minimum-altstack delivery");
    check(sigaltstack(&old, NULL) == 0, "restore sigaltstack");
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
    sa.sa_sigaction = fault_handler;
    check(sigaction(SIGILL, &sa, NULL) == 0, "sigaction SIGILL");
    sa.sa_sigaction = async_handler;
    check(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction SIGALRM");
    sa.sa_sigaction = stack_handler;
    check(sigaction(SIGXCPU, &sa, NULL) == 0, "sigaction SIGXCPU");
    sa.sa_flags = SA_SIGINFO;
    check(sigaction(SIGURG, &sa, NULL) == 0, "sigaction SIGURG");
    pid = getpid();
    tid = syscall(SYS_gettid);
    long page_size = sysconf(_SC_PAGESIZE);
    check(page_size >= 640 && page_size % 64 == 0, "page size");
    unsigned char *mapping = mmap(NULL, 2 * (size_t)page_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mapping != MAP_FAILED, "mmap guarded FP state");
    guard_page = mapping + page_size;
    check(mprotect(guard_page, page_size, PROT_NONE) == 0, "mprotect FP-state guard");
    for (int i = PRESERVE; i <= NO_TRAILER; i++)
        run_case(i);
    for (int i = MASK_SSE; i <= SHORT_XSTATE; i++)
        run_case(i);
    test_initial_state();
    test_fault();
    test_async();
    test_red_zone();
    test_min_altstack();
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
            for (int i = MASK_SSE; i <= SHORT_XSTATE; i++)
                run_case(i);
            test_initial_state();
            test_fault();
            test_async();
        }
    }
    for (int i = BAD_MXCSR; i <= BAD_SHORT_XSTATE; i++) {
        if (i == BAD_SHORT_XSTATE && !use_avx)
            continue;
        if (i == BAD_UNMAPPED) {
            /* Unmap just before use so that no later mapping can reuse the address. */
            unmapped_fpstate =
                mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            check(unmapped_fpstate != MAP_FAILED, "mmap unmapped FP state");
            check(munmap(unmapped_fpstate, page_size) == 0, "munmap FP-state probe");
        }
        if (sigsetjmp(recovery, 1) == 0) {
            run_case(i);
            check(0, "invalid FP state was accepted");
        }
    }
    check(munmap(mapping, 2 * (size_t)page_size) == 0, "munmap guarded FP state");
    puts("All x86-64 signal FP-state tests passed.");
    return 0;
}

#else
int main(void) { return 0; }
#endif
