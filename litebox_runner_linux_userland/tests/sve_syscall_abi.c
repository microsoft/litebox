// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The SVE syscall ABI. As on Linux, a syscall preserves V0-V31 and zeroes the
// rest of the Z registers, P0-P15 and FFR, also for getpid, which LiteBox
// answers without a host syscall, in both processes of a fork, and across a
// blocking read that an SA_RESTART handler interrupts: the handler's frame PC
// is the read's `svc`, where a restarted syscall resumes, and the read then
// returns the byte a handler writes. PR_SVE_GET_VL reports the vector length
// RDVL reads. PR_SVE_SET_VL with every valid flag returns that vector length
// and leaves RDVL unchanged, and with an unknown flag bit fails with EINVAL.
// Both report PR_SVE_VL_INHERIT from a PR_SVE_SET_VL that sets it until one
// without it, also in a fork child. Without SVE, both prctls fail with EINVAL.

#include "helpers.h"

#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#if defined(__aarch64__)

#include "sve.h"

#include <linux/prctl.h>

static struct sve_regs pattern, observed, expected;
static volatile uintptr_t svc_site;

static void expect_einval(long ret, const char *msg) {
    TEST_ASSERT(ret == -1 && errno == EINVAL, msg);
}

static long set_vl(unsigned long arg) { return prctl(PR_SVE_SET_VL, arg, 0, 0, 0); }

static long get_vl(void) { return prctl(PR_SVE_GET_VL, 0, 0, 0, 0); }

// Returns NULL if `observed` holds what a syscall leaves of `pattern`, or else
// what differs.
static const char *syscall_result_error(unsigned long vl) {
    memset(&expected, 0, sizeof(expected));
    for (int n = 0; n < 32; n++) {
        memcpy(&expected.z[n * vl], &pattern.z[n * vl], 16);
    }
    return sve_compare(&observed, &expected, vl);
}

// Makes syscall `nr` with `pattern` live and stores the registers after it to
// `observed`. Records the address of its `svc` in `svc_site` first.
static long svc_with_live_sve(long nr, long a0, long a1, long a2) {
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x8 asm("x8") = nr;
    asm volatile(".arch_extension sve\n\t"
                 "adr x9, 1f\n\t"
                 "str x9, [%[site]]\n\t" SVE_LOAD_ALL "1: svc #0\n\t" SVE_STORE_ALL
                 : "+r"(x0)
                 : "r"(x1), "r"(x2), "r"(x8), [site] "r"(&svc_site), SVE_LOAD_OPERANDS(&pattern),
                   SVE_STORE_OPERANDS(&observed)
                 : SVE_CLOBBERS, "x9");
    return x0;
}

// Forks with a raw `clone` while SVE state is live. The child reports through
// its exit status.
static void check_fork(unsigned long vl) {
    // Without CLONE_SETTLS and CLONE_CHILD_*TID, clone ignores its `tls` and
    // `child_tid` arguments in x3 and x4, which are left unset.
    pid_t pid = svc_with_live_sve(SYS_clone, SIGCHLD, 0, 0);
    const char *error = syscall_result_error(vl);
    if (pid == 0) {
        _exit(error == NULL ? 0 : 1);
    }
    TEST_ASSERT(pid > 0, "clone failed");
    int status;
    TEST_ASSERT(waitpid(pid, &status, 0) == pid, "waitpid failed");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "the fork child's registers differ from a syscall's result");
    TEST_ASSERT(error == NULL, error);
}

static int restart_pipe[2];
static volatile sig_atomic_t alarms, read_interrupted;

static const struct itimerval restart_timer = {.it_value = {.tv_usec = 20000}};

// Writes the byte only on the second alarm, so the first one can interrupt the
// blocked read. LiteBox has no periodic timers, so the first alarm re-arms the
// one-shot timer.
static void restart_alarm_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)info;
    const ucontext_t *uc = context;
    if (uc->uc_mcontext.pc == svc_site) {
        read_interrupted = 1;
    }
    if (++alarms == 2) {
        char byte = 'x';
        if (write(restart_pipe[1], &byte, 1) != 1) {
            _exit(2);
        }
    } else if (setitimer(ITIMER_REAL, &restart_timer, NULL) != 0) {
        _exit(2);
    }
    SVE_CLOBBER_SOME();
}

// A raw blocking read with live SVE state, interrupted by SA_RESTART SIGALRM
// handlers.
static void check_restart(unsigned long vl) {
    TEST_ASSERT(pipe(restart_pipe) == 0, "pipe failed");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = restart_alarm_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    TEST_ASSERT(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction failed");
    TEST_ASSERT(setitimer(ITIMER_REAL, &restart_timer, NULL) == 0, "setitimer failed");

    char byte = 0;
    long read_ret = svc_with_live_sve(SYS_read, restart_pipe[0], (long)&byte, 1);
    TEST_ASSERT(read_ret == 1 && byte == 'x',
                "the restarted read did not return the handler's byte");
    TEST_ASSERT(read_interrupted, "no alarm interrupted the read");
    const char *error = syscall_result_error(vl);
    TEST_ASSERT(error == NULL, error);
    close(restart_pipe[0]);
    close(restart_pipe[1]);
}

static void check_prctl(unsigned long vl) {
    const long inherit = (long)(vl | PR_SVE_VL_INHERIT);
    TEST_ASSERT(get_vl() == (long)vl, "PR_SVE_GET_VL differs from RDVL");
    TEST_ASSERT(set_vl(vl | PR_SVE_VL_INHERIT | PR_SVE_SET_VL_ONEXEC) == inherit,
                "PR_SVE_SET_VL did not report PR_SVE_VL_INHERIT");
    TEST_ASSERT(get_vl() == inherit, "PR_SVE_GET_VL did not report PR_SVE_VL_INHERIT");
    pid_t pid = fork();
    if (pid == 0) {
        _exit(get_vl() == inherit ? 0 : 1);
    }
    TEST_ASSERT(pid > 0, "fork failed");
    int status;
    TEST_ASSERT(waitpid(pid, &status, 0) == pid, "waitpid failed");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "the fork child lost PR_SVE_VL_INHERIT");
    expect_einval(set_vl(vl | (1UL << 16)), "PR_SVE_SET_VL accepted an unknown flag");
    expect_einval(set_vl(vl | (1UL << 19)), "PR_SVE_SET_VL accepted an unknown flag");
    TEST_ASSERT(set_vl(vl) == (long)vl, "PR_SVE_SET_VL reported a PR_SVE_VL_INHERIT it cleared");
    TEST_ASSERT(get_vl() == (long)vl, "PR_SVE_SET_VL did not clear PR_SVE_VL_INHERIT");
    TEST_ASSERT(sve_vl() == vl, "RDVL changed after PR_SVE_SET_VL");
}

int main(void) {
    if (!sve_available()) {
        expect_einval(get_vl(), "PR_SVE_GET_VL succeeded without SVE");
        expect_einval(set_vl(16), "PR_SVE_SET_VL succeeded without SVE");
        printf("sve unavailable\n");
        return 0;
    }
    unsigned long vl = sve_vl();
    TEST_ASSERT(vl % 16 == 0 && vl <= SVE_MAX_VL, "unexpected vector length");
    printf("sve vl %lu\n", vl);
    sve_fill_pattern(&pattern, 0);
    // LiteBox answers getpid without a host syscall, so the host kernel does not
    // zero the state for it.
    long pid = svc_with_live_sve(SYS_getpid, 0, 0, 0);
    TEST_ASSERT(pid == getpid(), "raw getpid returned the wrong value");
    const char *error = syscall_result_error(vl);
    TEST_ASSERT(error == NULL, error);
    check_fork(vl);
    check_restart(vl);
    check_prctl(vl);
    printf("sve syscall abi ok\n");
    return 0;
}

#else

int main(void) { return 0; }

#endif
