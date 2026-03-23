// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t worker_got_sigpwr = 0;

static void sigpwr_handler(int sig) {
    if (sig == SIGPWR) {
        worker_got_sigpwr = 1;
    }
}

static void *worker_thread(void *arg) {
    (void)arg;

    struct sigaction sa = {0};
    sa.sa_handler = sigpwr_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPWR, &sa, NULL) != 0) {
        perror("sigaction");
        return (void *)1;
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPWR);
    if (pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
        perror("pthread_sigmask");
        return (void *)2;
    }

    for (int i = 0; i < 100; ++i) {
        if (worker_got_sigpwr) {
            return (void *)0;
        }

        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = 10 * 1000 * 1000,
        };
        nanosleep(&ts, NULL);
    }

    fprintf(stderr, "worker did not receive SIGPWR\n");
    return (void *)3;
}

int main(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPWR);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        perror("pthread_sigmask");
        return 1;
    }

    pthread_t thread;
    int rc = pthread_create(&thread, NULL, worker_thread, NULL);
    if (rc != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(rc));
        return 1;
    }

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 50 * 1000 * 1000,
    };
    nanosleep(&ts, NULL);

    rc = pthread_kill(thread, SIGPWR);
    if (rc != 0) {
        fprintf(stderr, "pthread_kill: %s\n", strerror(rc));
        return 1;
    }

    void *thread_result = NULL;
    rc = pthread_join(thread, &thread_result);
    if (rc != 0) {
        fprintf(stderr, "pthread_join: %s\n", strerror(rc));
        return 1;
    }

    return thread_result == 0 ? 0 : 1;
}
