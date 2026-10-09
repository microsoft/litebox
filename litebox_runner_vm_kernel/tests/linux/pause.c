// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Waits for a signal that nothing can send. See sched.json.

#include <unistd.h>

int main(void) {
    pause();
    return 0;
}
