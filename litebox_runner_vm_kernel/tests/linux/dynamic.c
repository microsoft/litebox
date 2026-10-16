// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A dynamically linked program: the shim loads it with its interpreter
// (ld.so), which maps libc.so.6 from the root; the program then maps
// libgcc_s.so.1 itself (dlopen) and calls into it, to walk its own stack.
// Prints what it checked. Built only dynamically (see
// dev_tools/run_linux_on_vm_userland.sh); see dynamic.json.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unwind.h>

static int has_libc(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    const char *slash = strrchr(info->dlpi_name, '/');
    const char *name = slash != NULL ? slash + 1 : info->dlpi_name;
    if (strcmp(name, "libc.so.6") == 0) *(int *)data = 1;
    return 0;
}

static _Unwind_Reason_Code count_frame(struct _Unwind_Context *context, void *frames) {
    (void)context;
    ++*(int *)frames;
    return _URC_NO_REASON;
}

int main(void) {
    if (getauxval(AT_BASE) == 0) {
        fprintf(stderr, "no interpreter\n");
        return 1;
    }
    printf("interpreter: yes\n");

    int libc = 0;
    dl_iterate_phdr(has_libc, &libc);
    if (!libc) {
        fprintf(stderr, "libc.so.6 not loaded\n");
        return 1;
    }
    printf("libc: shared\n");

    void *libgcc_s = dlopen("libgcc_s.so.1", RTLD_NOW);
    if (libgcc_s == NULL) {
        fprintf(stderr, "dlopen libgcc_s.so.1: %s\n", dlerror());
        return 1;
    }
    _Unwind_Reason_Code (*backtrace)(_Unwind_Trace_Fn, void *) =
        (_Unwind_Reason_Code (*)(_Unwind_Trace_Fn, void *))dlsym(libgcc_s, "_Unwind_Backtrace");
    int frames = 0;
    if (backtrace == NULL || backtrace(count_frame, &frames) != _URC_END_OF_STACK ||
        frames < 2) {
        fprintf(stderr, "_Unwind_Backtrace from libgcc_s.so.1 (%d frames)\n", frames);
        return 1;
    }
    dlclose(libgcc_s);
    printf("dlopen: ok\n");

    if (dlopen("libmissing.so", RTLD_NOW) != NULL) {
        fprintf(stderr, "dlopen of a missing library succeeded\n");
        return 1;
    }
    printf("dlopen missing: ok\n");
    return 0;
}
