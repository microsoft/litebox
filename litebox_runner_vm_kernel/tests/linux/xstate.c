// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// User extended state under the VM kernel, which gives user mode every XCR0
// component the CPU offers but PKRU and AMX, and no CET (whose user state is
// not in XCR0). The first argument picks a mode:
// - "xcr0": XCR0 is CPUID.(EAX=0Dh,ECX=0):EDX:EAX but PKRU and AMX, and
//   protection keys are off (CPUID.(EAX=7,ECX=0):ECX.OSPKE clear).
// - "signal": vector registers survive a signal whose handler clobbers them.
// - "fork": vector registers survive a fork, on both sides.
// - "thread": a new thread starts with its creator's MXCSR and x87 control
//   word, which are not the defaults.
// - "spin MS PATTERN": vector registers loaded with PATTERN survive MS
//   milliseconds of busy-waiting with no syscalls, while other programs run
//   (e.g., preempting it with other patterns, see xstate.json).
// - "yield COUNT PATTERN": vector registers loaded with PATTERN survive
//   COUNT sched_yield calls.
// The vector registers are YMM0-15, or, with AVX-512, ZMM0-31 and the opmask
// registers. Each check loads, then stores, them in one inline assembly
// block, which makes its system calls directly: C code, the C library's
// included, may use them in between. Without AVX, the vector checks are
// skipped (saying so on standard error), as under TCG with a small CPU
// model; the modes still print their results.

#define _GNU_SOURCE
#include <cpuid.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

// XCR0 components that the kernel withholds: PKRU, and AMX tile state.
#define XCR0_EXCLUDED ((1ULL << 9) | (1ULL << 17) | (1ULL << 18))
#define XCR0_AVX 0x6ULL
#define XCR0_AVX512 0xe6ULL

// Vector register contents, as the assembly loads and stores them: register
// `i` at `v[i]` (YMM registers use the first 32 bytes), opmask registers at
// `k` (16 bits each, all that AVX-512F moves).
struct vregs {
    _Alignas(64) unsigned char v[32][64];
    unsigned short k[8];
};

_Static_assert(__builtin_offsetof(struct vregs, k) == 2048, "the assembly's opmask offset");

#define FOR8(m) m(0) m(1) m(2) m(3) m(4) m(5) m(6) m(7)
#define FOR16(m) FOR8(m) m(8) m(9) m(10) m(11) m(12) m(13) m(14) m(15)
#define FOR32(m)                                                                                \
    FOR16(m) m(16) m(17) m(18) m(19) m(20) m(21) m(22) m(23) m(24) m(25) m(26) m(27) m(28) m(29) \
        m(30) m(31)

#define LOAD_YMM(i) "vmovdqu " #i "*64(%[in]), %%ymm" #i "\n\t"
#define STORE_YMM(i) "vmovdqu %%ymm" #i ", " #i "*64(%[out])\n\t"
#define LOAD_ZMM(i) "vmovdqu64 " #i "*64(%[in]), %%zmm" #i "\n\t"
#define STORE_ZMM(i) "vmovdqu64 %%zmm" #i ", " #i "*64(%[out])\n\t"
#define LOAD_K(i) "kmovw 2048+" #i "*2(%[in]), %%k" #i "\n\t"
#define STORE_K(i) "kmovw %%k" #i ", 2048+" #i "*2(%[out])\n\t"

#define LOAD_AVX FOR16(LOAD_YMM)
#define STORE_AVX FOR16(STORE_YMM)
#define LOAD_AVX512 FOR32(LOAD_ZMM) FOR8(LOAD_K)
#define STORE_AVX512 FOR32(STORE_ZMM) FOR8(STORE_K)

// The compiler only knows the registers its target has; it uses no others.
#define CLOBBERS_SSE                                                                          \
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",   \
        "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
#ifdef __AVX512F__
#define CLOBBERS                                                                              \
    CLOBBERS_SSE, "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",     \
        "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31", "k0", "k1",   \
        "k2", "k3", "k4", "k5", "k6", "k7"
#else
#define CLOBBERS CLOBBERS_SSE
#endif

// For each register set: a system call (`nr`, up to three arguments) with
// the registers loaded from `in` before, and stored to `out` after; a busy
// wait of `ticks` TSC ticks, returning the longest gap between consecutive
// TSC reads; `count` sched_yield calls; and loading `in` alone.
#define DEFINE_OPS(set, LOAD, STORE)                                                              \
    static long syscall_##set(const struct vregs *in, struct vregs *out, long nr, long a, long b, \
                              long c) {                                                           \
        long ret = nr;                                                                            \
        __asm__ volatile(LOAD "syscall\n\t" STORE                                                 \
                         : "+a"(ret)                                                              \
                         : [in] "r"(in), [out] "r"(out), "D"(a), "S"(b), "d"(c)                   \
                         : "rcx", "r11", "memory", CLOBBERS);                                     \
        return ret;                                                                               \
    }                                                                                             \
    static unsigned long long spin_##set(const struct vregs *in, struct vregs *out,               \
                                         unsigned long long ticks) {                              \
        unsigned long long gap;                                                                   \
        __asm__ volatile(LOAD "rdtsc\n\t"                                                         \
                              "shl $32, %%rdx\n\t"                                                \
                              "or %%rdx, %%rax\n\t"                                               \
                              "mov %%rax, %%r8\n\t"                                               \
                              "mov %%rax, %%r9\n\t"                                               \
                              "xor %[gap], %[gap]\n"                                              \
                              "1:\n\t"                                                            \
                              "rdtsc\n\t"                                                         \
                              "shl $32, %%rdx\n\t"                                                \
                              "or %%rdx, %%rax\n\t"                                               \
                              "mov %%rax, %%rcx\n\t"                                              \
                              "sub %%r9, %%rcx\n\t"                                               \
                              "cmp %[gap], %%rcx\n\t"                                             \
                              "jbe 2f\n\t"                                                        \
                              "mov %%rcx, %[gap]\n"                                               \
                              "2:\n\t"                                                            \
                              "mov %%rax, %%r9\n\t"                                               \
                              "sub %%r8, %%rax\n\t"                                               \
                              "cmp %[ticks], %%rax\n\t"                                           \
                              "jb 1b\n\t" STORE                                                   \
                         : [gap] "=&r"(gap)                                                       \
                         : [in] "r"(in), [out] "r"(out), [ticks] "r"(ticks)                       \
                         : "rax", "rcx", "rdx", "r8", "r9", "cc", "memory", CLOBBERS);            \
        return gap;                                                                               \
    }                                                                                             \
    static void yield_##set(const struct vregs *in, struct vregs *out, long count) {              \
        __asm__ volatile(LOAD "1:\n\t"                                                            \
                              "mov %[nr], %%eax\n\t"                                              \
                              "syscall\n\t"                                                       \
                              "dec %[count]\n\t"                                                  \
                              "jnz 1b\n\t" STORE                                                  \
                         : [count] "+r"(count)                                                    \
                         : [in] "r"(in), [out] "r"(out), [nr] "i"(SYS_sched_yield)                \
                         : "rax", "rcx", "r11", "cc", "memory", CLOBBERS);                        \
    }                                                                                             \
    static void load_##set(const struct vregs *in) {                                              \
        __asm__ volatile(LOAD : : [in] "r"(in) : "memory", CLOBBERS);                             \
    }

DEFINE_OPS(avx, LOAD_AVX, STORE_AVX)
DEFINE_OPS(avx512, LOAD_AVX512, STORE_AVX512)

enum level { NONE, AVX, AVX512 };
static enum level level;

static unsigned long long xgetbv0(void) {
    unsigned int eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((unsigned long long)edx << 32) | eax;
}

static enum level detect_level(void) {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & bit_OSXSAVE) || !(ecx & bit_AVX)) {
        return NONE;
    }
    unsigned long long xcr0 = xgetbv0();
    if ((xcr0 & XCR0_AVX) != XCR0_AVX) {
        return NONE;
    }
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    if ((ebx & bit_AVX512F) && (xcr0 & XCR0_AVX512) == XCR0_AVX512) {
        return AVX512;
    }
    return AVX;
}

// Whether the vector checks are skipped, which it then says.
static int skipped(void) {
    if (level == NONE) {
        fprintf(stderr, "no AVX: vector checks skipped\n");
    }
    return level == NONE;
}

static void fill(struct vregs *r, int pattern) {
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 64; j++) {
            r->v[i][j] = (unsigned char)(pattern * 37 + i * 11 + j * 3 + 1);
        }
    }
    for (int i = 0; i < 8; i++) {
        r->k[i] = (unsigned short)(pattern * 0x1357 + i * 0x0101 + 1);
    }
}

// Whether `a` and `b` agree on the registers of `level`; reports the first
// difference as `what`.
static int same(const struct vregs *a, const struct vregs *b, const char *what) {
    int count = level == AVX512 ? 32 : 16;
    int width = level == AVX512 ? 64 : 32;
    for (int i = 0; i < count; i++) {
        if (memcmp(a->v[i], b->v[i], width) != 0) {
            fprintf(stderr, "%s: vector register %d changed\n", what, i);
            return 0;
        }
    }
    if (level == AVX512 && memcmp(a->k, b->k, sizeof(a->k)) != 0) {
        fprintf(stderr, "%s: opmask registers changed\n", what);
        return 0;
    }
    return 1;
}

static long vector_syscall(const struct vregs *in, struct vregs *out, long nr, long a, long b,
                           long c) {
    return level == AVX512 ? syscall_avx512(in, out, nr, a, b, c)
                           : syscall_avx(in, out, nr, a, b, c);
}

static int xcr0_mode(void) {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx & bit_OSXSAVE)) {
        fprintf(stderr, "xcr0: OSXSAVE is clear\n");
        return 1;
    }
    __cpuid_count(0xd, 0, eax, ebx, ecx, edx);
    unsigned long long supported = ((unsigned long long)edx << 32) | eax;
    unsigned long long expected = supported & ~XCR0_EXCLUDED;
    unsigned long long xcr0 = xgetbv0();
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    int ospke = (ecx & bit_OSPKE) != 0;
    if (xcr0 != expected || ospke) {
        fprintf(stderr, "xcr0: %#llx, expected %#llx (supported %#llx), OSPKE %d\n", xcr0,
                expected, supported, ospke);
        return 1;
    }
    printf("xcr0: ok\n");
    return 0;
}

static struct vregs clobber;
static volatile sig_atomic_t handled;

static void on_signal(int signal) {
    (void)signal;
    if (level == AVX512) {
        load_avx512(&clobber);
    } else {
        load_avx(&clobber);
    }
    handled = 1;
}

static int signal_mode(void) {
    if (!skipped()) {
        struct sigaction action = {.sa_handler = on_signal};
        sigaction(SIGUSR1, &action, NULL);
        fill(&clobber, 0x55);
        static struct vregs in, out;
        fill(&in, 1);
        // Delivered as the call returns.
        long ret = vector_syscall(&in, &out, SYS_tgkill, getpid(), gettid(), SIGUSR1);
        if (ret != 0 || !handled) {
            fprintf(stderr, "signal: tgkill %ld, handled %d\n", ret, (int)handled);
            return 1;
        }
        if (!same(&in, &out, "signal")) {
            return 1;
        }
    }
    printf("signal: ok\n");
    return 0;
}

static int fork_mode(void) {
    if (!skipped()) {
        static struct vregs in, out;
        fill(&in, 2);
        fflush(NULL);
        long pid = vector_syscall(&in, &out, SYS_fork, 0, 0, 0);
        if (pid < 0) {
            fprintf(stderr, "fork: %ld\n", pid);
            return 1;
        }
        if (pid == 0) {
            _exit(same(&in, &out, "fork child") ? 0 : 1);
        }
        int parent = same(&in, &out, "fork parent");
        int status;
        if (waitpid((pid_t)pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 || !parent) {
            return 1;
        }
    }
    printf("fork: ok\n");
    return 0;
}

struct fp_control {
    unsigned int mxcsr;
    unsigned short fcw;
};

static struct fp_control read_fp_control(void) {
    struct fp_control control;
    control.mxcsr = _mm_getcsr();
    __asm__ volatile("fnstcw %0" : "=m"(control.fcw));
    return control;
}

static void *read_in_thread(void *arg) {
    *(struct fp_control *)arg = read_fp_control();
    return NULL;
}

static int thread_mode(void) {
    struct fp_control initial = read_fp_control();
    // Round toward zero (SSE), and down with double precision (x87).
    struct fp_control set = {.mxcsr = 0x1f80 | 0x6000, .fcw = 0x067f};
    _mm_setcsr(set.mxcsr);
    __asm__ volatile("fldcw %0" : : "m"(set.fcw));
    struct fp_control seen = {0};
    pthread_t thread;
    int created = pthread_create(&thread, NULL, read_in_thread, &seen) == 0;
    if (created) {
        pthread_join(thread, NULL);
    }
    _mm_setcsr(initial.mxcsr);
    __asm__ volatile("fldcw %0" : : "m"(initial.fcw));
    if (!created || seen.mxcsr != set.mxcsr || seen.fcw != set.fcw) {
        fprintf(stderr, "thread: MXCSR %#x, FCW %#x, expected %#x, %#x\n", seen.mxcsr, seen.fcw,
                set.mxcsr, set.fcw);
        return 1;
    }
    printf("thread: ok\n");
    return 0;
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static int spin_mode(long long ms, int pattern) {
    if (skipped()) {
        return 0;
    }
    // TSC ticks per microsecond.
    unsigned long long ticks = __rdtsc();
    long long start = now_us();
    struct timespec five_ms = {0, 5 * 1000 * 1000};
    nanosleep(&five_ms, NULL);
    double per_us = (double)(__rdtsc() - ticks) / (double)(now_us() - start);

    static struct vregs in, out;
    fill(&in, pattern);
    unsigned long long duration = (unsigned long long)(ms * 1000 * per_us);
    unsigned long long gap = level == AVX512 ? spin_avx512(&in, &out, duration)
                                             : spin_avx(&in, &out, duration);
    // For the log: a gap shows that other programs ran meanwhile.
    fprintf(stderr, "spin %d: max gap %.0f us\n", pattern, (double)gap / per_us);
    return same(&in, &out, "spin") ? 0 : 1;
}

static int yield_mode(long count, int pattern) {
    if (skipped() || count <= 0) {
        return 0;
    }
    static struct vregs in, out;
    fill(&in, pattern);
    if (level == AVX512) {
        yield_avx512(&in, &out, count);
    } else {
        yield_avx(&in, &out, count);
    }
    return same(&in, &out, "yield") ? 0 : 1;
}

int main(int argc, char *argv[]) {
    level = detect_level();
    const char *mode = argc > 1 ? argv[1] : "";
    if (strcmp(mode, "xcr0") == 0) {
        return xcr0_mode();
    } else if (strcmp(mode, "signal") == 0) {
        return signal_mode();
    } else if (strcmp(mode, "fork") == 0) {
        return fork_mode();
    } else if (strcmp(mode, "thread") == 0) {
        return thread_mode();
    } else if (strcmp(mode, "spin") == 0 && argc == 4) {
        return spin_mode(atoll(argv[2]), atoi(argv[3]));
    } else if (strcmp(mode, "yield") == 0 && argc == 4) {
        return yield_mode(atol(argv[2]), atoi(argv[3]));
    }
    fprintf(stderr, "usage: %s xcr0|signal|fork|thread|spin MS PATTERN|yield COUNT PATTERN\n",
            argv[0]);
    return 2;
}
