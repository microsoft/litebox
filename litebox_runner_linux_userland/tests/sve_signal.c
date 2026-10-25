// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A synchronous trap with live SVE state delivers that state in a full
// sve_context. The handler's edits to the frame take effect on return, with
// Z registers taking their low 128 bits from fpsimd_context, and state the
// handler leaves alone survives its own register use. Inside the handler, a
// second live state survives a nested synchronous signal the same way, though
// the nested handler moves its sve_context behind an extra_context.
// AT_MINSIGSTKSZ is nonzero.

#include "helpers.h"

#include <signal.h>

#if defined(__aarch64__)

#include "sve.h"

#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51
#endif

#define EDITED_Z5 0x5e
#define EDITED_P3 0xa5
// The first six FFR elements, a monotonic predicate.
#define EDITED_FFR 0x3f

static const uint8_t edited_v2[16] = {0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                                      0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};

static unsigned long vl;
static struct sve_regs pattern, observed, expected, nested_pattern, nested_observed;
static const char *frame_error = "the SIGTRAP handler did not run";
static const char *nested_error = "the SIGILL handler did not run";

// Moves `sve` and the records after it into extra records that an extra_context
// in its place points to, right after the extra_context's terminator.
static const char *move_behind_extra_context(ucontext_t *uc, struct sve_context *sve) {
    uint8_t *reserved = (uint8_t *)uc->uc_mcontext.__reserved;
    uint8_t *moved = (uint8_t *)sve;
    size_t size = 0;
    while (((struct _aarch64_ctx *)(moved + size))->magic != 0) {
        size += ((struct _aarch64_ctx *)(moved + size))->size;
    }
    // Linux's TERMINATOR_SIZE.
    const size_t terminator = 16;
    uint8_t *data = moved + sizeof(struct extra_context) + terminator;
    if (data + size + terminator > reserved + sizeof(uc->uc_mcontext.__reserved)) {
        return "no room to move sve_context";
    }
    memmove(data, moved, size);
    memset(data + size, 0, terminator);
    memset(moved, 0, sizeof(struct extra_context) + terminator);
    struct extra_context *extra = (struct extra_context *)moved;
    extra->head.magic = EXTRA_MAGIC;
    extra->head.size = sizeof(*extra);
    extra->datap = (uint64_t)(uintptr_t)data;
    extra->size = size + terminator;
    return NULL;
}

static void ill_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)info;
    ucontext_t *uc = context;
    struct fpsimd_context *fpsimd;
    struct sve_context *sve;
    sve_find_records(uc, &fpsimd, &sve);
    nested_error = fpsimd == NULL || sve == NULL ? "missing nested fpsimd_context or sve_context"
                                                 : sve_check_record(sve, &nested_pattern, vl);
    if (nested_error == NULL) {
        nested_error = move_behind_extra_context(uc, sve);
    }
    // Skip the UDF.
    uc->uc_mcontext.pc += 4;
    SVE_CLOBBER_SOME();
}

static void trap_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)info;
    asm volatile(".arch_extension sve\n\t" SVE_LOAD_ALL "udf #0\n\t" SVE_STORE_ALL
                 :
                 : SVE_LOAD_OPERANDS(&nested_pattern), SVE_STORE_OPERANDS(&nested_observed)
                 : SVE_CLOBBERS);

    ucontext_t *uc = context;
    struct fpsimd_context *fpsimd;
    struct sve_context *sve;
    sve_find_records(uc, &fpsimd, &sve);
    if (fpsimd == NULL || sve == NULL) {
        frame_error = "missing fpsimd_context or sve_context";
    } else {
        frame_error = sve_check_record(sve, &pattern, vl);
    }
    if (frame_error == NULL) {
        unsigned long vq = sve_vq_from_vl(vl);
        uint8_t *regs = (uint8_t *)sve;
        memcpy(&fpsimd->vregs[2], edited_v2, sizeof(edited_v2));
        memset(regs + SVE_SIG_ZREG_OFFSET(vq, 5), EDITED_Z5, vl);
        memset(regs + SVE_SIG_PREG_OFFSET(vq, 3), EDITED_P3, vl / 8);
        memset(regs + SVE_SIG_FFR_OFFSET(vq), 0, vl / 8);
        regs[SVE_SIG_FFR_OFFSET(vq)] = EDITED_FFR;
    }
    // Skip the BRK.
    uc->uc_mcontext.pc += 4;
    SVE_CLOBBER_SOME();
}

static void install(int signo, void (*handler)(int, siginfo_t *, void *)) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(signo, &sa, NULL) == 0, "sigaction failed");
}

int main(void) {
    TEST_ASSERT(getauxval(AT_MINSIGSTKSZ) != 0, "AT_MINSIGSTKSZ is missing");
    if (!sve_available()) {
        printf("sve unavailable\n");
        return 0;
    }
    vl = sve_vl();
    TEST_ASSERT(vl % 16 == 0 && vl <= SVE_MAX_VL, "unexpected vector length");
    printf("sve vl %lu\n", vl);
    sve_fill_pattern(&pattern, 0);
    sve_fill_pattern(&nested_pattern, 1);
    install(SIGTRAP, trap_handler);
    install(SIGILL, ill_handler);

    asm volatile(".arch_extension sve\n\t" SVE_LOAD_ALL "brk #0\n\t" SVE_STORE_ALL
                 :
                 : SVE_LOAD_OPERANDS(&pattern), SVE_STORE_OPERANDS(&observed)
                 : SVE_CLOBBERS);
    TEST_ASSERT(nested_error == NULL, nested_error);
    const char *error = sve_compare(&nested_observed, &nested_pattern, vl);
    TEST_ASSERT(error == NULL, error);
    TEST_ASSERT(frame_error == NULL, frame_error);

    // V5 replaces the low 128 bits of the edited Z5; edited V2 replaces Z2's.
    expected = pattern;
    memset(&expected.z[5 * vl + 16], EDITED_Z5, vl - 16);
    memcpy(&expected.z[2 * vl], edited_v2, sizeof(edited_v2));
    memset(&expected.p[3 * vl / 8], EDITED_P3, vl / 8);
    memset(expected.ffr, 0, sizeof(expected.ffr));
    expected.ffr[0] = EDITED_FFR;
    error = sve_compare(&observed, &expected, vl);
    TEST_ASSERT(error == NULL, error);

    printf("sve signal ok\n");
    return 0;
}

#else

int main(void) { return 0; }

#endif
