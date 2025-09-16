#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void segv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext; // unused
    printf("Caught signal %d (%s)\n", sig, strsignal(sig));
    if (info) {
        printf("  Fault address: %p\n", info->si_addr);
        if (info->si_addr == 0xdeadbeef)
            _exit(0); // Exit immediately (async-signal-safe)
    }
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

    printf("About to trigger SIGSEGV...\n");

    // Deliberately cause a segmentation fault
    int *p = 0xdeadbeef;
    *p = 42;

    // We never reach here
    printf("This line will not be executed.\n");
    return 0;
}
