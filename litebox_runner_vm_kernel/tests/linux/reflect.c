// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Makes syscalls the shim cannot patch, so the kernel must reflect them: the
// shim patches only file-backed code, and this `syscall` is in anonymous
// memory, written at run time. With "unreturnable", forks children that each
// leave the kernel a stack pointer outside user memory to return to: one at
// such a `syscall`, one at a page fault the kernel resolves. That must kill
// each child's process (SIGKILL), and nothing else. See reflect.json.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

typedef long (*raw_syscall_fn)(long nr, long a, long b, long c);

// `code`, at most a page, executable in anonymous memory.
static void *map_code(const unsigned char *code, size_t len) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memcpy(page, code, len);
    if (mprotect(page, 4096, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        exit(1);
    }
    return page;
}

// Runs `code` in a child, with a page the child has not touched (so the
// kernel maps it at the first access), and prints how the child ended.
static int unreturnable(const char *name, const unsigned char *code, size_t len) {
    void (*run)(volatile char *) = (void (*)(volatile char *))map_code(code, len);
    volatile char *fresh = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fresh == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        run(fresh);
        _exit(1);
    }
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child) {
        perror("fork or waitpid");
        return 1;
    }
    if (WIFSIGNALED(status)) {
        printf("%s: killed %d\n", name, WTERMSIG(status));
    } else {
        printf("%s: exited %d\n", name, WEXITSTATUS(status));
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "unreturnable") == 0) {
        // xor esp, esp; syscall; ud2
        static const unsigned char at_syscall[] = {0x31, 0xe4, 0x0f, 0x05, 0x0f, 0x0b};
        // xor esp, esp; mov al, [rdi]; ud2
        static const unsigned char at_fault[] = {0x31, 0xe4, 0x8a, 0x07, 0x0f, 0x0b};
        return unreturnable("syscall", at_syscall, sizeof(at_syscall)) |
               unreturnable("fault", at_fault, sizeof(at_fault));
    }

    // mov rax, rdi; mov rdi, rsi; mov rsi, rdx; mov rdx, rcx; syscall; ret
    static const unsigned char stub[] = {
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6,
        0x48, 0x89, 0xca, 0x0f, 0x05, 0xc3,
    };
    raw_syscall_fn raw_syscall = (raw_syscall_fn)map_code(stub, sizeof(stub));

    static const char message[] = "reflected write\n";
    long written = raw_syscall(SYS_write, 1, (long)message, sizeof(message) - 1);
    long pid = raw_syscall(SYS_getpid, 0, 0, 0);
    long bad = raw_syscall(-1, 0, 0, 0);
    printf("written=%ld pid_matches=%d bad=%ld\n", written, pid == getpid(), bad);
    return written == sizeof(message) - 1 && pid == getpid() && bad == -38 ? 0 : 1;
}
