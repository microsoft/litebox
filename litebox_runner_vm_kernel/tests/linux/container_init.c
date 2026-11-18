// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The container's init of the guest service's tests (see
// dev_tools/guest_service_test_client): waits until killed.

#include <unistd.h>

int main(void) {
    for (;;) {
        pause();
    }
}
