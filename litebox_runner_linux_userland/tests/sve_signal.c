// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// An SA_SIGINFO handler that interrupts live SVE state finds the interrupted Z,
// P and FFR registers in an sve_context record; its edits to the record, not
// its own register changes, take effect on return.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>

#if defined(__aarch64__)

#include <asm/sigcontext.h>

// Largest architectural vector length in bytes.
#define MAX_VL 256

struct sve_regs {
    uint8_t z[32 * MAX_VL];
    uint8_t p[16 * MAX_VL / 8];
    uint8_t ffr[MAX_VL / 8];
};

static unsigned long vl;
static struct sve_regs pattern;
static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t loaded;
static const struct itimerval alarm_timer = {.it_value = {.tv_usec = 50000}};

static const uint8_t edited_v2[16] = {0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                                      0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};
#define EDITED_P3 0xa5
#define EDITED_Z5 0x5e

static const char *frame_error;

static unsigned long read_vl(void) {
    unsigned long bytes;
    asm volatile(".arch_extension sve\n\trdvl %0, #1" : "=r"(bytes));
    return bytes;
}

// Loads every Z and P register and FFR from `pattern`, sets `loaded`, spins
// until `*flag` becomes nonzero, then stores them to `out`, packed at the
// current VL.
static void run(volatile sig_atomic_t *flag, struct sve_regs *out) {
#define ZL(n) "ldr z" #n ", [%[zi], #" #n ", mul vl]\n\t"
#define ZS(n) "str z" #n ", [%[zo], #" #n ", mul vl]\n\t"
#define PL(n) "ldr p" #n ", [%[pi], #" #n ", mul vl]\n\t"
#define PS(n) "str p" #n ", [%[po], #" #n ", mul vl]\n\t"
#define Z8(m, a, b, c, d, e, f, g, h) m(a) m(b) m(c) m(d) m(e) m(f) m(g) m(h)
    asm volatile(".arch_extension sve\n\t"
                 Z8(ZL, 0, 1, 2, 3, 4, 5, 6, 7) Z8(ZL, 8, 9, 10, 11, 12, 13, 14, 15)
                 Z8(ZL, 16, 17, 18, 19, 20, 21, 22, 23) Z8(ZL, 24, 25, 26, 27, 28, 29, 30, 31)
                 // WRFFR needs a monotonic predicate.
                 "ptrue p0.b, vl3\n\t"
                 "wrffr p0.b\n\t"
                 Z8(PL, 0, 1, 2, 3, 4, 5, 6, 7) Z8(PL, 8, 9, 10, 11, 12, 13, 14, 15)
                 "mov w9, #1\n\t"
                 "str w9, [%[loaded]]\n\t"
                 "1:\n\t"
                 "ldr w9, [%[flag]]\n\t"
                 "cbz w9, 1b\n\t"
                 Z8(ZS, 0, 1, 2, 3, 4, 5, 6, 7) Z8(ZS, 8, 9, 10, 11, 12, 13, 14, 15)
                 Z8(ZS, 16, 17, 18, 19, 20, 21, 22, 23) Z8(ZS, 24, 25, 26, 27, 28, 29, 30, 31)
                 Z8(PS, 0, 1, 2, 3, 4, 5, 6, 7) Z8(PS, 8, 9, 10, 11, 12, 13, 14, 15)
                 "rdffr p0.b\n\t"
                 "str p0, [%[ffr]]\n\t"
                 :
                 : [flag] "r"(flag), [loaded] "r"(&loaded), [zi] "r"(pattern.z),
                   [pi] "r"(pattern.p), [zo] "r"(out->z), [po] "r"(out->p), [ffr] "r"(out->ffr)
                 : "x9", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
                   "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20",
                   "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31",
                   "p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12",
                   "p13", "p14", "p15", "ffr");
#undef ZL
#undef ZS
#undef PL
#undef PS
#undef Z8
}

// Finds the SVE and FP/SIMD records.
static void find_records(ucontext_t *uc, struct fpsimd_context **fpsimd,
                         struct sve_context **sve) {
    uint8_t *records = (uint8_t *)uc->uc_mcontext.__reserved;
    *fpsimd = NULL;
    *sve = NULL;
    for (;;) {
        struct _aarch64_ctx *head = (struct _aarch64_ctx *)records;
        if (head->magic == 0) {
            return;
        }
        if (head->magic == FPSIMD_MAGIC) {
            *fpsimd = (struct fpsimd_context *)head;
        } else if (head->magic == SVE_MAGIC) {
            *sve = (struct sve_context *)head;
        }
        records += head->size;
    }
}

static void inspecting_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)info;
    if (interrupted) {
        return;
    }
    // A signal before `run` has loaded the pattern must not be inspected, so
    // it re-arms the timer instead.
    if (!loaded) {
        setitimer(ITIMER_REAL, &alarm_timer, NULL);
        return;
    }
    struct fpsimd_context *fpsimd;
    struct sve_context *sve;
    find_records(context, &fpsimd, &sve);
    unsigned long vq = sve_vq_from_vl(vl);
    if (fpsimd == NULL || sve == NULL) {
        frame_error = "missing fpsimd_context or sve_context";
    } else if (sve->vl != vl || sve->flags != 0) {
        frame_error = "sve_context has the wrong VL or flags";
    } else if (sve->head.size < SVE_SIG_CONTEXT_SIZE(vq)) {
        frame_error = "sve_context carries no register payload";
    } else {
        uint8_t *regs = (uint8_t *)sve;
        uint8_t expected_ffr[MAX_VL / 8] = {0x07};
        if (memcmp(regs + SVE_SIG_ZREG_OFFSET(vq, 0), pattern.z, 32 * vl) != 0) {
            frame_error = "sve_context Z registers differ";
        } else if (memcmp(regs + SVE_SIG_PREG_OFFSET(vq, 0), pattern.p, 16 * vl / 8) != 0) {
            frame_error = "sve_context P registers differ";
        } else if (memcmp(regs + SVE_SIG_FFR_OFFSET(vq), expected_ffr, vl / 8) != 0) {
            frame_error = "sve_context FFR differs";
        } else {
            // FP/SIMD state replaces Z[127:0] on return, so only the V2 edit
            // reaches Z2 and the Z5 edit is overridden by V5.
            memcpy(&fpsimd->vregs[2], edited_v2, sizeof(edited_v2));
            memset(regs + SVE_SIG_ZREG_OFFSET(vq, 5), EDITED_Z5, 16);
            memset(regs + SVE_SIG_PREG_OFFSET(vq, 3), EDITED_P3, vl / 8);
        }
    }
    // The registers must come back from the frame, not from this handler.
    asm volatile(".arch_extension sve\n\t"
                 "pfalse p0.b\n\t"
                 "pfalse p7.b\n\t"
                 "pfalse p15.b\n\t"
                 "setffr\n\t"
                 "mov z0.b, #0\n\t"
                 "mov z31.b, #0\n\t"
                 :
                 :
                 : "memory", "v0", "v31", "p0", "p7", "p15", "ffr");
    interrupted = 1;
}

int main(void) {
    vl = read_vl();
    TEST_ASSERT(vl % 16 == 0 && vl <= MAX_VL, "unexpected vector length");
    for (size_t i = 0; i < sizeof(pattern.z); i++) {
        pattern.z[i] = (uint8_t)(i * 7 + 3);
    }
    for (size_t i = 0; i < sizeof(pattern.p); i++) {
        pattern.p[i] = (uint8_t)(i * 13 + 1);
    }

    static struct sve_regs expected, observed;
    volatile sig_atomic_t done = 1;
    run(&done, &expected);
    TEST_ASSERT(memcmp(expected.z, pattern.z, 32 * vl) == 0, "Z registers did not load");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = inspecting_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");
    loaded = 0;
    TEST_ASSERT(setitimer(ITIMER_REAL, &alarm_timer, NULL) == 0, "setitimer failed");
    run(&interrupted, &observed);
    struct itimerval disarm = {0};
    TEST_ASSERT(setitimer(ITIMER_REAL, &disarm, NULL) == 0, "disarming setitimer failed");
    TEST_ASSERT(frame_error == NULL, frame_error);
    memcpy(&expected.z[2 * vl], edited_v2, sizeof(edited_v2));
    memset(&expected.p[3 * vl / 8], EDITED_P3, vl / 8);
    TEST_ASSERT(memcmp(expected.z, observed.z, 32 * vl) == 0, "Z registers differ");
    TEST_ASSERT(memcmp(expected.p, observed.p, 16 * vl / 8) == 0, "P registers differ");
    TEST_ASSERT(memcmp(expected.ffr, observed.ffr, vl / 8) == 0, "FFR differs");

    printf("sve signal ok\n");
    return 0;
}

#else

int main(void) {
    return 0;
}

#endif
