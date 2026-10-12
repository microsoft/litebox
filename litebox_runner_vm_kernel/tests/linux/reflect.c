// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Makes syscalls the shim cannot patch, so the kernel must reflect them: the
// shim patches only file-backed code, and this `syscall` is in anonymous
// memory, written at run time. See reflect.json.

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef long (*raw_syscall_fn)(long nr, long a, long b, long c);

int main(void) {
    // mov rax, rdi; mov rdi, rsi; mov rsi, rdx; mov rdx, rcx; syscall; ret
    static const unsigned char stub[] = {
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6,
        0x48, 0x89, 0xca, 0x0f, 0x05, 0xc3,
    };
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memcpy(page, stub, sizeof(stub));
    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return 1;
    }
    raw_syscall_fn raw_syscall = (raw_syscall_fn)page;

    static const char message[] = "reflected write\n";
    long written = raw_syscall(SYS_write, 1, (long)message, sizeof(message) - 1);
    long pid = raw_syscall(SYS_getpid, 0, 0, 0);
    long bad = raw_syscall(-1, 0, 0, 0);
    printf("written=%ld pid_matches=%d bad=%ld\n", written, pid == getpid(), bad);
    return written == sizeof(message) - 1 && pid == getpid() && bad == -38 ? 0 : 1;
}
