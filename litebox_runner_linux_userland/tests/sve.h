// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Shared SVE helpers for the C tests in this directory. Only the inline
// assembly uses SVE, so the tests build without SVE compiler flags.

#ifndef LITEBOX_TESTS_SVE_H
#define LITEBOX_TESTS_SVE_H

#include <asm/sigcontext.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include <ucontext.h>

// Largest architectural vector length in bytes.
#define SVE_MAX_VL 256

// Z0-Z31, P0-P15 and FFR as stored by `STR` at the current VL.
struct sve_regs {
    uint8_t z[32 * SVE_MAX_VL];
    uint8_t p[16 * SVE_MAX_VL / 8];
    uint8_t ffr[SVE_MAX_VL / 8];
};

#define SVE_FOR_Z(m)                                                                    \
    m(0) m(1) m(2) m(3) m(4) m(5) m(6) m(7) m(8) m(9) m(10) m(11) m(12) m(13) m(14)     \
        m(15) m(16) m(17) m(18) m(19) m(20) m(21) m(22) m(23) m(24) m(25) m(26) m(27)   \
            m(28) m(29) m(30) m(31)
#define SVE_FOR_P(m)                                                                    \
    m(0) m(1) m(2) m(3) m(4) m(5) m(6) m(7) m(8) m(9) m(10) m(11) m(12) m(13) m(14) m(15)

// Loads every register from the `struct sve_regs` at operand `in`, FFR first
// because loading it goes through P0.
#define SVE_LDR_Z(n) "ldr z" #n ", [%[in_z], #" #n ", mul vl]\n\t"
#define SVE_LDR_P(n) "ldr p" #n ", [%[in_p], #" #n ", mul vl]\n\t"
#define SVE_LOAD_ALL                                                                    \
    SVE_FOR_Z(SVE_LDR_Z) "ldr p0, [%[in_ffr]]\n\t"                                      \
                         "wrffr p0.b\n\t" SVE_FOR_P(SVE_LDR_P)
#define SVE_LOAD_OPERANDS(regs)                                                         \
    [in_z] "r"((regs)->z), [in_p] "r"((regs)->p), [in_ffr] "r"((regs)->ffr)

// Stores every register to the `struct sve_regs` at operand `out`, FFR last
// because storing it goes through P0.
#define SVE_STR_Z(n) "str z" #n ", [%[out_z], #" #n ", mul vl]\n\t"
#define SVE_STR_P(n) "str p" #n ", [%[out_p], #" #n ", mul vl]\n\t"
#define SVE_STORE_ALL                                                                   \
    SVE_FOR_Z(SVE_STR_Z) SVE_FOR_P(SVE_STR_P) "rdffr p0.b\n\t"                          \
                                              "str p0, [%[out_ffr]]\n\t"
#define SVE_STORE_OPERANDS(regs)                                                        \
    [out_z] "r"((regs)->z), [out_p] "r"((regs)->p), [out_ffr] "r"((regs)->ffr)

#define SVE_CLOBBERS                                                                    \
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12",    \
        "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",    \
        "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "p0", "p1", "p2", "p3", \
        "p4", "p5", "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",   \
        "ffr", "memory"

// Overwrites some of every register kind, so a handler's return must restore them.
#define SVE_CLOBBER_SOME()                                                              \
    asm volatile(".arch_extension sve\n\t"                                              \
                 "pfalse p0.b\n\t"                                                      \
                 "pfalse p7.b\n\t"                                                      \
                 "pfalse p15.b\n\t"                                                     \
                 "setffr\n\t"                                                           \
                 "mov z0.b, #0\n\t"                                                     \
                 "mov z31.b, #0\n\t"                                                    \
                 :                                                                      \
                 :                                                                      \
                 : "v0", "v31", "p0", "p7", "p15", "ffr")

static inline int sve_available(void) { return (getauxval(AT_HWCAP) & HWCAP_SVE) != 0; }

static inline unsigned long sve_vl(void) {
    unsigned long vl;
    asm volatile(".arch_extension sve\n\trdvl %0, #1" : "=r"(vl));
    return vl;
}

// Fills `regs` with the high bytes of a 32-bit LCG started at `seed`. For seeds 0-3 and every
// VL, no two Z registers and no two P registers hold the same value, within a seed or across
// seeds, so the tests catch a register mix-up. FFR has `3 + seed` leading true elements, a
// monotonic predicate as `WRFFR` requires.
static inline void sve_fill_pattern(struct sve_regs *regs, uint32_t seed) {
    uint32_t state = seed;
    for (size_t i = 0; i < sizeof(regs->z); i++) {
        state = state * 1664525u + 1013904223u;
        regs->z[i] = (uint8_t)(state >> 24);
    }
    for (size_t i = 0; i < sizeof(regs->p); i++) {
        state = state * 1664525u + 1013904223u;
        regs->p[i] = (uint8_t)(state >> 24);
    }
    memset(regs->ffr, 0, sizeof(regs->ffr));
    for (uint32_t i = 0; i < 3 + seed; i++) {
        regs->ffr[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

// Finds the FP/SIMD and SVE records of a signal frame. Leaves both NULL if the
// record list is malformed or runs past `__reserved`.
static inline void sve_find_records(ucontext_t *uc, struct fpsimd_context **fpsimd,
                                    struct sve_context **sve) {
    uint8_t *records = (uint8_t *)uc->uc_mcontext.__reserved;
    size_t offset = 0;
    *fpsimd = NULL;
    *sve = NULL;
    while (offset + sizeof(struct _aarch64_ctx) <= sizeof(uc->uc_mcontext.__reserved)) {
        struct _aarch64_ctx *head = (struct _aarch64_ctx *)(records + offset);
        if (head->magic == 0) {
            return;
        }
        if (head->size == 0) {
            break;
        }
        if (head->magic == FPSIMD_MAGIC) {
            *fpsimd = (struct fpsimd_context *)head;
        } else if (head->magic == SVE_MAGIC) {
            *sve = (struct sve_context *)head;
        }
        offset += head->size;
    }
    *fpsimd = NULL;
    *sve = NULL;
}

// Returns NULL if `sve` holds the live state `expected`, or else what differs.
static inline const char *sve_check_record(const struct sve_context *sve,
                                           const struct sve_regs *expected, unsigned long vl) {
    unsigned long vq = sve_vq_from_vl(vl);
    const uint8_t *regs = (const uint8_t *)sve;
    if (sve->vl != vl || sve->flags != 0) {
        return "sve_context has the wrong VL or flags";
    }
    if (sve->head.size < SVE_SIG_CONTEXT_SIZE(vq)) {
        return "sve_context carries no register payload";
    }
    if (memcmp(regs + SVE_SIG_ZREGS_OFFSET, expected->z, 32 * vl) != 0) {
        return "sve_context Z registers differ";
    }
    if (memcmp(regs + SVE_SIG_PREGS_OFFSET(vq), expected->p, 16 * vl / 8) != 0) {
        return "sve_context P registers differ";
    }
    if (memcmp(regs + SVE_SIG_FFR_OFFSET(vq), expected->ffr, vl / 8) != 0) {
        return "sve_context FFR differs";
    }
    return NULL;
}

// Returns NULL if the first `vl` bytes of each register in `actual` and
// `expected` agree, or else which registers differ.
static inline const char *sve_compare(const struct sve_regs *actual,
                                      const struct sve_regs *expected, unsigned long vl) {
    if (memcmp(actual->z, expected->z, 32 * vl) != 0) {
        return "Z registers differ";
    }
    if (memcmp(actual->p, expected->p, 16 * vl / 8) != 0) {
        return "P registers differ";
    }
    if (memcmp(actual->ffr, expected->ffr, vl / 8) != 0) {
        return "FFR differs";
    }
    return NULL;
}

#endif
