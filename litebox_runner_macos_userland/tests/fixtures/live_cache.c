// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include <mach/mach.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    printf("argv0=%s\narg=%s\n", argv[0], argv[1]);
    fprintf(stderr, "guest stderr\n");
    // optind lives in libc's subcache data, not in the main cache metadata mapping.
    vm_size_t page_size = (vm_size_t)getpagesize();
    vm_address_t page = (vm_address_t)&optind & ~(page_size - 1);
    kern_return_t result = vm_protect(mach_task_self(), page, page_size, FALSE,
                                     VM_PROT_READ | VM_PROT_WRITE);
    printf("protect=%d", result);
    return result == KERN_SUCCESS ? 0 : 11;
}
