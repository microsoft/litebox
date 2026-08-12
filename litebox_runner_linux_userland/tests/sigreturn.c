// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// AArch64 glibc supplies no restorer, and LiteBox has no vDSO, so LiteBox
// supplies a trampoline that invokes rt_sigreturn to restore saved context.

#include "helpers.h"

#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t handler_runs = 0;
static volatile sig_atomic_t handler_signo = 0;

// Caller-saved x9/x10 are not compiler-restored, so only sigcontext can recover
// them. x19 is a weaker slot-validity check because the compiler restores it.
static void clobber_sentinel_registers(void) {
#ifdef __aarch64__
    long junk = (long)handler_runs * 0x5eed5eed5eed5eedL + 1;
    asm volatile("mov x9, %[j]\n\t"
                 "mov x10, %[j]\n\t"
                 "mov x19, %[j]"
                 :
                 : [j] "r"(junk)
                 : "x9", "x10", "x19");
#endif
}

static void handler(int signo, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    handler_runs++;
    handler_signo = signo;
    clobber_sentinel_registers();
}

static void install_handler(int signo) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(signo, &sa, NULL) == 0, "sigaction failed");
}

#ifdef __aarch64__

#define SENTINEL_X9 0x0909090909090909L
#define SENTINEL_X10 0x1010101010101010L
#define SENTINEL_X19 0x1919191919191919L

static long out_x9, out_x10, out_x19, out_sp_delta;

// SVC preserves x9/x10; after the handler clobbers them, only rt_sigreturn can.
static void raise_with_sentinels(int pid, int signo) {
    register long x8 asm("x8") = SYS_kill;
    register long x0 asm("x0") = pid;
    register long x1 asm("x1") = signo;
    register long x9 asm("x9") = SENTINEL_X9;
    register long x10 asm("x10") = SENTINEL_X10;
    register long x19 asm("x19") = SENTINEL_X19;
    long sp_before, sp_after;

    asm volatile("mov %[spb], sp\n\t"
                 "svc #0\n\t"
                 "mov %[spa], sp"
                 : "+r"(x0), "+r"(x9), "+r"(x10), "+r"(x19), [spb] "=&r"(sp_before),
                   [spa] "=&r"(sp_after)
                 : "r"(x8), "r"(x1)
                 : "memory");

    TEST_ASSERT(x0 == 0, "kill(getpid(), signo) should return 0");
    out_x9 = x9;
    out_x10 = x10;
    out_x19 = x19;
    out_sp_delta = sp_after - sp_before;
}

static void check_registers_survived(void) {
    TEST_ASSERT(out_x9 == SENTINEL_X9, "x9 clobbered across signal delivery");
    TEST_ASSERT(out_x10 == SENTINEL_X10, "x10 clobbered across signal delivery");
    TEST_ASSERT(out_x19 == SENTINEL_X19, "x19 clobbered across signal delivery");
    TEST_ASSERT(out_sp_delta == 0, "sp not restored across signal delivery");
}

#else // !__aarch64__

static void raise_with_sentinels(int pid, int signo) {
    TEST_ASSERT(kill(pid, signo) == 0, "kill failed");
}

static void check_registers_survived(void) {}

#endif // __aarch64__

int main(void) {
    int pid = (int)getpid();

    install_handler(SIGUSR1);

    volatile long counter = 0;

    for (int i = 0; i < 3; i++) {
        raise_with_sentinels(pid, SIGUSR1);
        check_registers_survived();
        counter++;
    }

    TEST_ASSERT(handler_runs == 3, "handler did not run exactly three times");
    TEST_ASSERT(handler_signo == SIGUSR1, "handler saw the wrong signal number");
    TEST_ASSERT(counter == 3, "execution did not resume after the handler returned");

    TEST_ASSERT(write(1, "sigreturn ok\n", 13) == 13, "write after sigreturn failed");

    return 0;
}
