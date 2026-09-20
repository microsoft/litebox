// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <stdio.h>

#ifdef EXECUTABLE_TLV
static __thread int value = 42;
#endif

// libc++abi's cached TLS must use the same TSD as guest pthread_setspecific.
// Executable-defined TLV initialization is a separate unsupported lifecycle path.
int main() {
#ifndef EXECUTABLE_TLV
    int value = 42;
#endif
    try {
        try { throw value; }
        catch (int caught) {
            if (caught != 42 || value != 42) return 11;
            throw;
        }
    } catch (int caught) {
        if (caught != 42 || value != 42) return 12;
    }
    printf("thread local and rethrow ok\n");
}
