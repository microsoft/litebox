// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Reports the guest's AT_HWCAP/AT_HWCAP2 and checks that FPCR control bits (RMode, plus those of
// the offered FP16, AFP, and EBF16 features) survive a syscall and a signal whose handler
// clobbers FPCR.

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "this test checks AArch64 hwcaps and FPCR state"
#endif

// Linux uapi `arch/arm64/include/uapi/asm/hwcap.h`; older libc headers may lack them.
#ifndef HWCAP_FPHP
#define HWCAP_FPHP (1UL << 9)
#endif
#ifndef HWCAP2_AFP
#define HWCAP2_AFP (1UL << 20)
#endif
#ifndef HWCAP2_EBF16
#define HWCAP2_EBF16 (1UL << 32)
#endif

#define FPCR_FIZ_AH_NEP 0x7UL
#define FPCR_EBF (1UL << 13)
#define FPCR_FZ16 (1UL << 19)
// RMode = round toward zero; every FP host supports it.
#define FPCR_RMODE_RZ (3UL << 22)

static uint64_t read_fpcr(void) {
    uint64_t fpcr;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    return fpcr;
}

static void write_fpcr(uint64_t fpcr) { __asm__ volatile("msr fpcr, %0" : : "r"(fpcr)); }

static volatile sig_atomic_t handler_ran;

static void clobber_fpcr(int sig) {
    (void)sig;
    handler_ran = 1;
    write_fpcr(0);
}

int main(void) {
    unsigned long hwcap = getauxval(AT_HWCAP);
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    printf("hwcaps hwcap=%lu hwcap2=%lu\n", hwcap, hwcap2);

    uint64_t bits = FPCR_RMODE_RZ;
    if (hwcap & HWCAP_FPHP)
        bits |= FPCR_FZ16;
    if (hwcap2 & HWCAP2_AFP)
        bits |= FPCR_FIZ_AH_NEP;
    if (hwcap2 & HWCAP2_EBF16)
        bits |= FPCR_EBF;

    struct sigaction action = {.sa_handler = clobber_fpcr};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    uint64_t original = read_fpcr();
    uint64_t marked = original | bits;
    write_fpcr(marked);
    syscall(SYS_getppid);
    int syscall_ok = read_fpcr() == marked;
    write_fpcr(marked);
    int raised = raise(SIGUSR1) == 0;
    int signal_ok = raised && handler_ran && read_fpcr() == marked;
    write_fpcr(original);

    printf("fpcr bits=%#llx syscall=%d signal=%d\n", (unsigned long long)bits, syscall_ok,
           signal_ok);
    return 0;
}
