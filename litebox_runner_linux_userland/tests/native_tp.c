// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <stdint.h>
#include <sys/mman.h>

#ifdef __aarch64__

// No compiled libc code runs with the private TP. x19-x22 and LR are
// callee-saved here; the SVC gate must preserve all non-result registers.
extern void changed_tp_syscall(void *tp, unsigned long observed[3], void *reader);
asm(".text\n"
    ".global changed_tp_syscall\n"
    ".type changed_tp_syscall, %function\n"
    "changed_tp_syscall:\n"
    "stp x19, x20, [sp, #-48]!\n"
    "stp x21, x22, [sp, #16]\n"
    "str x30, [sp, #32]\n"
    "mrs x19, tpidr_el0\n"
    "mov x20, x0\n"
    "mov x21, x1\n"
    "mov x22, x2\n"
    "msr tpidr_el0, x20\n"
    "mov x8, #172\n" // getpid
    "svc #0\n"
    "str x0, [x21]\n"
    "mrs x0, tpidr_el0\n"
    "str x0, [x21, #8]\n"
    "cbz x22, 1f\n"
    "blr x22\n"
    "str x0, [x21, #16]\n"
    "1: msr tpidr_el0, x19\n"
    "ldr x30, [sp, #32]\n"
    "ldp x21, x22, [sp, #16]\n"
    "ldp x19, x20, [sp], #48\n"
    "ret\n"
    ".size changed_tp_syscall, .-changed_tp_syscall\n");

#endif

int main(int argc, char **argv) {
#ifdef __aarch64__
    unsigned long private_tp[16] = {0};
    unsigned long observed[3] = {0};
    void *reader = NULL;
    if (argc > 1 && strcmp(argv[1], "jit") == 0) {
        // Generated native TP access has no syscall instruction and is never
        // passed through the ELF rewriter. This requires physical guest TP.
        uint32_t instructions[] = {0xd53bd040, 0xd65f03c0}; // MRS x0, TPIDR_EL0; RET
        reader = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        TEST_ASSERT(reader != MAP_FAILED, "mmap for native TP reader failed");
        memcpy(reader, instructions, sizeof(instructions));
        __builtin___clear_cache(reader, (char *)reader + sizeof(instructions));
        TEST_ASSERT(mprotect(reader, 4096, PROT_READ | PROT_EXEC) == 0,
                    "mprotect for native TP reader failed");
    }
    changed_tp_syscall(private_tp, observed, reader);
    TEST_ASSERT(observed[0] == (unsigned long)getpid(), "intercepted getpid failed");
    TEST_ASSERT(observed[1] == (uintptr_t)private_tp, "TP changed across intercepted syscall");
    if (reader) {
        TEST_ASSERT(observed[2] == (uintptr_t)private_tp, "generated MRS did not see physical guest TP");
        TEST_ASSERT(munmap(reader, 4096) == 0, "munmap native TP reader failed");
    }
#endif
    TEST_ASSERT(write(1, "native tp ok\n", 13) == 13, "write after TP restoration failed");
    return 0;
}
