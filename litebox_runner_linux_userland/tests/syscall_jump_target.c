// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: a `syscall` that is the target of an unconditional `jmp` and is also
// reached by fall-through. Neither shape leaves room to patch the syscall in
// place: the jump forbids extending its window backward and the `ret` leaves
// too few bytes after it. The rewriter must redirect the jumps themselves.

#include "helpers.h"

#ifdef __x86_64__

#define STR_(x) #x
#define STR(x) STR_(x)

// Each function issues getpid when `take_jump` is nonzero (via the jump) and
// getppid otherwise (via fall-through).
long jump_rel32_to_syscall(long take_jump);
long jump_rel8_to_syscall(long take_jump);

__asm__(".pushsection .text\n"
        ".globl jump_rel32_to_syscall\n"
        ".type jump_rel32_to_syscall, @function\n"
        "jump_rel32_to_syscall:\n"
        "    test %rdi, %rdi\n"
        "    jz 1f\n"
        "    mov $" STR(SYS_getpid) ", %eax\n"
        "    .byte 0xe9\n" // jmp rel32
        "    .long 2f - . - 4\n"
        "1:  mov $" STR(SYS_getppid) ", %eax\n"
        "2:  syscall\n"
        "    ret\n"
        ".size jump_rel32_to_syscall, . - jump_rel32_to_syscall\n"
        "\n"
        ".globl jump_rel8_to_syscall\n"
        ".type jump_rel8_to_syscall, @function\n"
        "jump_rel8_to_syscall:\n"
        "    test %rdi, %rdi\n"
        "    jz 1f\n"
        "    mov $" STR(SYS_getpid) ", %eax\n"
        "    .byte 0xeb\n" // jmp rel8
        "    .byte 2f - . - 1\n"
        "1:  mov $" STR(SYS_getppid) ", %eax\n"
        "2:  syscall\n"
        "    ret\n"
        ".size jump_rel8_to_syscall, . - jump_rel8_to_syscall\n"
        ".popsection\n");

int main(void) {
    long pid = getpid();
    long ppid = getppid();

    TEST_ASSERT(jump_rel32_to_syscall(1) == pid, "rel32 jump reaches the syscall");
    TEST_ASSERT(jump_rel32_to_syscall(0) == ppid, "fall-through after rel32 jump site");
    TEST_ASSERT(jump_rel8_to_syscall(1) == pid, "rel8 jump reaches the syscall");
    TEST_ASSERT(jump_rel8_to_syscall(0) == ppid, "fall-through after rel8 jump site");
    printf("syscall_jump_target: ok\n");
    return 0;
}

#else

int main(void) { return 0; }

#endif
