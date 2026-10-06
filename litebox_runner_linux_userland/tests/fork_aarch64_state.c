// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks AArch64 state across `fork` and `vfork`: d8 and FPCR survive in the fork child and the
// vfork parent, and return addresses signed before `fork` authenticate in the child.

#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "this test checks AArch64 floating-point and vector state"
#endif

#define D8_MARKER 0x0123456789abcdefULL
// Round toward zero with flush-to-zero.
#define FPCR_MARKER 0x01c00000ULL
#define CHILD_D8 0xfedcba9876543210ULL
// Round toward plus infinity.
#define CHILD_FPCR 0x00400000ULL

struct observed {
    long ret;
    uint64_t d8;
    uint64_t fpcr;
};

static uint64_t read_fpcr(void) {
    uint64_t fpcr;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    return fpcr;
}

static void write_fpcr(uint64_t fpcr) { __asm__ volatile("msr fpcr, %0" : : "r"(fpcr)); }

// Sets the markers, forks with a raw `clone`, and reads them back in whichever process returns.
static struct observed raw_fork(void) {
    register long x0 __asm__("x0") = SIGCHLD;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = SYS_clone;
    uint64_t d8, fpcr;
    __asm__ volatile("fmov d8, %[d8_marker]\n\t"
                     "msr fpcr, %[fpcr_marker]\n\t"
                     "svc #0\n\t"
                     "fmov %[d8], d8\n\t"
                     "mrs %[fpcr], fpcr"
                     : "+r"(x0), [d8] "=r"(d8), [fpcr] "=r"(fpcr)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8),
                       [d8_marker] "r"(D8_MARKER), [fpcr_marker] "r"(FPCR_MARKER)
                     : "v8", "memory");
    return (struct observed){x0, d8, fpcr};
}

// Sets the markers and vforks with a raw `clone`. The child clobbers them and exits; the parent
// reads them back after resuming.
static struct observed raw_vfork(void) {
    register long x0 __asm__("x0") = CLONE_VM | CLONE_VFORK | SIGCHLD;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = SYS_clone;
    uint64_t d8, fpcr;
    __asm__ volatile("fmov d8, %[d8_marker]\n\t"
                     "msr fpcr, %[fpcr_marker]\n\t"
                     "svc #0\n\t"
                     "cbnz x0, 1f\n\t"
                     "fmov d8, %[child_d8]\n\t"
                     "msr fpcr, %[child_fpcr]\n\t"
                     "mov x0, #0\n\t"
                     "mov x8, %[exit_group]\n\t"
                     "svc #0\n\t"
                     "1:\n\t"
                     "fmov %[d8], d8\n\t"
                     "mrs %[fpcr], fpcr"
                     : "+r"(x0), "+r"(x8), [d8] "=&r"(d8), [fpcr] "=&r"(fpcr)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), [d8_marker] "r"(D8_MARKER),
                       [fpcr_marker] "r"(FPCR_MARKER), [child_d8] "r"(CHILD_D8),
                       [child_fpcr] "r"(CHILD_FPCR), [exit_group] "i"(SYS_exit_group)
                     : "v8", "memory");
    return (struct observed){x0, d8, fpcr};
}

// Signs its return address before the fork and authenticates it after.
__attribute__((noinline, target("branch-protection=pac-ret+leaf"))) static long signed_fork(void) {
    long ret = syscall(SYS_clone, SIGCHLD, 0, NULL, NULL, 0);
    // Prevents a tail call.
    __asm__ volatile("" ::: "memory");
    return ret;
}

static int intact(const struct observed *observed) {
    return observed->d8 == D8_MARKER && observed->fpcr == FPCR_MARKER;
}

static int wait_exit_code(pid_t child) {
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(void) {
    uint64_t original_fpcr = read_fpcr();
    fflush(stdout);

    struct observed forked = raw_fork();
    if (forked.ret == 0) {
        _exit(intact(&forked) ? 0 : 1);
    }
    write_fpcr(original_fpcr);
    if (forked.ret < 0) {
        printf("fork-failed ret=%ld\n", forked.ret);
        return 2;
    }
    int child_code = wait_exit_code((pid_t)forked.ret);
    printf("fork parent=%d child=%d\n", intact(&forked), child_code == 0);

    struct observed vforked = raw_vfork();
    write_fpcr(original_fpcr);
    if (vforked.ret < 0) {
        printf("vfork-failed ret=%ld\n", vforked.ret);
        return 3;
    }
    printf("vfork parent=%d child=%d d8=%#llx fpcr=%#llx\n", intact(&vforked),
           wait_exit_code((pid_t)vforked.ret) == 0, (unsigned long long)vforked.d8,
           (unsigned long long)vforked.fpcr);

    fflush(stdout);
    long signed_child = signed_fork();
    if (signed_child == 0) {
        _exit(0);
    }
    if (signed_child < 0) {
        printf("signed-fork-failed ret=%ld\n", signed_child);
        return 4;
    }
    int status = 0;
    waitpid((pid_t)signed_child, &status, 0);
    printf("signed-fork exited=%d code=%d signal=%d\n", WIFEXITED(status), WEXITSTATUS(status),
           WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return 0;
}
