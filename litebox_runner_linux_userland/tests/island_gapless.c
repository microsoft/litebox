// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    for (int i = 0; i < 3; ++i) {
        void *handle = dlopen("/lib/island_gapless.so", RTLD_NOW);
        if (!handle) {
            fprintf(stderr, "dlopen: %s\n", dlerror());
            return 1;
        }
        long (*get_pid)(void) = dlsym(handle, "island_getpid");
        assert(get_pid && get_pid() == getpid());
        assert(dlclose(handle) == 0);
    }
    return 0;
}
