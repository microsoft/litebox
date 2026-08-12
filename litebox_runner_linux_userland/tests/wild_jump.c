// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// An unreadable fault PC must reach the guest handler after gate probing.
#include "helpers.h"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static void segv_handler(int signum, siginfo_t *info, void *ucontext)
{
    (void)signum;
    (void)info;
    (void)ucontext;
    static const char msg[] = "guest handled the wild jump\n";
    write(1, msg, sizeof(msg) - 1);
    _exit(0);
}

int main(void)
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    TEST_ASSERT(sigaction(SIGSEGV, &sa, NULL) == 0, "sigaction(SIGSEGV) failed");

    ((void (*)(void))0)();

    TEST_ASSERT(0, "the jump to an unmapped PC did not fault");
    return 1;
}
