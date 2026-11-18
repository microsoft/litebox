// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Booted as litebox.init: exits leaving a child that waits and one that spins,
// which its exit must kill.

#include <unistd.h>

int main(void) {
    pid_t waiting = fork();
    if (waiting == 0) {
        for (;;) {
            pause();
        }
    }
    pid_t spinning = fork();
    if (spinning == 0) {
        for (;;) {
        }
    }
    return waiting > 0 && spinning > 0 ? 0 : 1;
}
