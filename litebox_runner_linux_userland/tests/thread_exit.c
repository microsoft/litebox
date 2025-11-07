#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>

void* spin_thread(void* arg) {
    for (;;) {
        // TODO: remove this and replace with an interruptible sleep and/or a
        // spin loop once wakeups are implemented.
        sched_yield();
    }
}

void* exit_thread(void* arg) {
    usleep(100000);
    exit(0);
}

int main() {
    // Create a bunch of threads that just spin, to make sure they
    // get cleaned up properly when the process exits.
    for (int i = 0; i < 10; i++) {
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, spin_thread, NULL);
        if (rc) {
            errno = rc;
            perror("pthread_create");
            abort();
        }
        pthread_detach(thread);
    }

    // Create a thread to exit the process.
    {
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, exit_thread, NULL);
        if (rc) {
            errno = rc;
            perror("pthread_create");
            abort();
        }
        pthread_detach(thread);
    }

    // Exit this thread so that the non-primary thread is the one initiating the
    // exit.
    pthread_exit(NULL);
    abort();
}
