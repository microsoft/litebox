#define _GNU_SOURCE
#include <link.h>
#include <stdint.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define TARGET_SECTION_NAME ".trampolineLB0"
#define HEADER_MAGIC  ((uint64_t)0x584f42204554494c)  // "LITE BOX"
#define TRAMP_MAGIC   ((uint64_t)0x30584f424554494c)  // "LITEBOX0"

// Linux syscall numbers (x86_64)
#define SYS_openat     257
#define SYS_read       0
#define SYS_close      3
#define SYS_mmap       9
#define SYS_mprotect   10
#define SYS_fstat      5
#define AT_FDCWD      -100

typedef long (*syscall_stub_t)(void);
static syscall_stub_t syscall_entry = 0;

static long do_syscall(long num, long a1, long a2, long a3, long a4, long a5, long a6) {
    if (!syscall_entry) return -1;

    register long rax __asm__("rax") = num;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;

    __asm__ volatile (
        "call *%[entry]"
        : "+r"(rax)
        : [entry]"r"(syscall_entry), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return rax;
}

static uint64_t read_u64(const void *p) {
    uint64_t v;
    __builtin_memcpy(&v, p, 8);
    return v;
}

static size_t align_up(size_t val, size_t align) {
    return (val + align - 1) & ~(align - 1);
}

unsigned int la_version(unsigned int version) {
    printf("[audit] la_version called\n");

    const char *env = getenv("LITEBOX_SYSCALL_ENTRY");
    if (env) {
        syscall_entry = (syscall_stub_t)(uintptr_t)strtoull(env, NULL, 16);
        printf("[audit] syscall_entry from env = 0x%lx\n", (uint64_t)(uintptr_t)syscall_entry);
    }
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    printf("[audit] la_objopen: l_name=%s\n", map->l_name ? map->l_name : "<main>");

    if (!syscall_entry) {
        printf("[audit] syscall_entry is not set. Skipping.\n");
        return 0;
    }

    const char *path = map->l_name;

    if (!path || path[0] == '\0') {
        return 0; // main binary is patched by libOS
    }

    int fd = do_syscall(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    if (fd < 0) {
        printf("[audit] failed to open file %s\n", path);
        return 0;
    }

    struct stat st;
    if (do_syscall(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) {
        printf("[audit] fstat failed\n");
        do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
        return 0;
    }
    long file_size = st.st_size;

    void *map_base = (void *)do_syscall(SYS_mmap, 0, file_size, 1, 0x02, fd, 0);
    if ((uintptr_t)map_base >= (uintptr_t)-4096) {
        printf("[audit] mmap failed\n");
        do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
        return 0;
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)map_base;
    if (memcmp(eh->e_ident, "\x7f""ELF", 4) != 0) {
        do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
        return 0;
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)map_base + eh->e_shoff);
    Elf64_Shdr *shstr = &shdrs[eh->e_shstrndx];
    const char *shnames = (char *)map_base + shstr->sh_offset;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = shnames + shdrs[i].sh_name;
        if (strcmp(name, TARGET_SECTION_NAME) != 0) continue;

        printf("[audit] found section %s\n", name);
        if (shdrs[i].sh_size < 24) break;
        const uint8_t *sec = (uint8_t *)map_base + shdrs[i].sh_offset;
        if (read_u64(sec) != HEADER_MAGIC) {
            printf("[audit] invalid header magic\n");
            break;
        }

        uint64_t tramp_addr  = map->l_addr + read_u64(sec + 8);
        uint64_t tramp_size_raw = read_u64(sec + 16);
        uint64_t tramp_off  = file_size - tramp_size_raw;
        uint64_t tramp_size = align_up(tramp_size_raw, 0x1000);

        void *mapped = (void *)do_syscall(SYS_mmap,
            tramp_addr, tramp_size, 1 | 2, 0x10 | 2, fd, tramp_off);
        if ((uintptr_t)mapped >= (uintptr_t)-4096) {
            printf("[audit] mmap failed\n");
            break;
        }

        const uint64_t *tramp = (const uint64_t *)tramp_addr;
        printf("[audit] trampoline addr=0x%lx size=0x%lx\n", tramp_addr, tramp_size);

        if (tramp[0] != TRAMP_MAGIC) {
            printf("[audit] invalid trampoline magic: 0x%lx\n", tramp[0]);
            break;
        }

        __builtin_memcpy((char *)mapped + 8, &syscall_entry, 8);
        do_syscall(SYS_mprotect, (long)mapped, tramp_size, 1 | 4, 0, 0, 0);
        printf("[audit] trampoline patched and protected\n");
        break;
    }

    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
}