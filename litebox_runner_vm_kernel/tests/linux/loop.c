// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Spins forever without entering the kernel; only preemption can stop it. See
// sched.json.

#include <unistd.h>

int main(void) {
    static const char message[] = "loop: spinning\n";
    if (write(1, message, sizeof(message) - 1) < 0) {
        return 1;
    }
    volatile unsigned long n = 0;
    for (;;) {
        n++;
    }
}
