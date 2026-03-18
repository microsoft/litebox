// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#pragma GCC target("avx")

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t handled = 0;

static void handler(int sig) {
    (void)sig;
    handled = 1;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction");
        return 2;
    }

    __attribute__((aligned(32))) uint64_t in[4] = {
        0x1111111122222222ULL,
        0x3333333344444444ULL,
        0x5555555566666666ULL,
        0x7777777788888888ULL,
    };
    __attribute__((aligned(32))) uint64_t out[4] = {0, 0, 0, 0};

    long pid = getpid();
    long tid = syscall(SYS_gettid);

    asm volatile(
        "vmovdqa (%[in]), %%ymm0\n\t"
        "mov %[sysno], %%rax\n\t"
        "mov %[pid], %%rdi\n\t"
        "mov %[tid], %%rsi\n\t"
        "mov %[sig], %%rdx\n\t"
        "syscall\n\t"
        "vmovdqa %%ymm0, (%[out])\n\t"
        :
        : [in] "r"(in),
          [out] "r"(out),
          [sysno] "i"(SYS_tgkill),
          [pid] "r"(pid),
          [tid] "r"(tid),
          [sig] "i"(SIGUSR1)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory");

    printf("handled=%d\n", handled);
    for (int i = 0; i < 4; ++i) {
        printf("%016llx %016llx\n", (unsigned long long)in[i], (unsigned long long)out[i]);
    }

    if (!handled || memcmp(in, out, sizeof(in)) != 0) {
        fprintf(stderr, "AVX state mismatch across signal return\n");
        return 1;
    }

    puts("AVX state preserved");
    return 0;
}
