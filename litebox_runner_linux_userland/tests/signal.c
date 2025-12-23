// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdint.h>

static volatile void *recover_ip = NULL;

static void segv_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *ctx = (ucontext_t *)ucontext;
    printf("Caught signal %d (%s)\n", sig, strsignal(sig));
    if (info) {
        printf("  Fault address: %p\n", info->si_addr);
        if (info->si_addr == (void *)0xdeadbeef) {
#if defined(__x86_64__)
            ctx->uc_mcontext.gregs[REG_RIP] = (greg_t)recover_ip;
#elif defined(__i386__)
            ctx->uc_mcontext.gregs[REG_EIP] = (greg_t)recover_ip;
#elif defined(__aarch64__)
            ctx->uc_mcontext.pc = (uintptr_t)recover_ip;
#else
            /* Unsupported arch: fail fast */
            _exit(3);
#endif
            return; // Resume execution at recover_ip
        }
    }
    // Not our deliberate fault; exit
    _exit(1); // Exit immediately (async-signal-safe)
}

int main(void) {
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* Capture label address for recovery */
    void *after_fault_label = &&after_fault;
    recover_ip = after_fault_label;

    printf("About to trigger SIGSEGV...\n");

    // Deliberately cause a segmentation fault
    int *p = (int *)0xdeadbeef;
    *p = 42;

    /* We never execute the next statement directly (recovered instead) */
    printf("This line should never be printed directly.\n");

after_fault:
    printf("Resumed after skipping faulting instruction.\n");
    printf("Test succeeded; continuing normal execution.\n");
    return 0;
}