// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tests: an alarm reaches the process's remaining thread after its main thread
// exited with pthread_exit, as Linux delivers a process's signal to a thread
// still running.

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t alarmed;

static void on_alarm(int signal) {
    (void)signal;
    alarmed = 1;
}

static void *wait_for_alarm(void *arg) {
    (void)arg;
    // SIGALRM is unblocked only inside `sigsuspend`, so it cannot arrive between the check and the
    // wait.
    sigset_t unblocked;
    pthread_sigmask(SIG_SETMASK, NULL, &unblocked);
    sigdelset(&unblocked, SIGALRM);
    while (!alarmed) {
        sigsuspend(&unblocked);
    }
    printf("alarm_thread_exit: PASS\n");
    exit(0);
}

int main(void) {
    struct sigaction action = {.sa_handler = on_alarm};
    if (sigaction(SIGALRM, &action, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    // Blocked before the thread starts, which inherits the mask.
    sigset_t alarm_set;
    sigemptyset(&alarm_set);
    sigaddset(&alarm_set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &alarm_set, NULL);
    pthread_t thread;
    if (pthread_create(&thread, NULL, wait_for_alarm, NULL) != 0) {
        fprintf(stderr, "FAIL: pthread_create\n");
        return 1;
    }
    alarm(1);
    pthread_exit(NULL);
}
