#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>

#define TARGET_SECTION_NAME ".trampolineLB0"
#define HEADER_MAGIC ((uint64_t)0x584f42204554494c) // "LITE BOX"
#define TRAMP_MAGIC ((uint64_t)0x30584f424554494c)  // "LITEBOX0"

#if !defined(__x86_64__)
# error "rtld_audit.c: build target must be x86_64"
#endif

// Linux syscall numbers (x86_64)
#define SYS_openat 257
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_fstat 5
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_exit_group 231
#define AT_FDCWD -100

// Linux flags
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

typedef long (*syscall_stub_t)(void);
static syscall_stub_t syscall_entry = 0;
static char interp[256] = {0}; // Buffer for interpreter path

#ifdef DEBUG
#define syscall_print(str, len)                                                \
  do_syscall(SYS_write, 1, (long)(str), len, 0, 0, 0)
#else
#define syscall_print(str, len)
#endif

static long do_syscall(long num, long a1, long a2, long a3, long a4, long a5,
                       long a6) {
  if (!syscall_entry)
    return -1;

  register long rax __asm__("rax") = num;
  register long rdi __asm__("rdi") = a1;
  register long rsi __asm__("rsi") = a2;
  register long rdx __asm__("rdx") = a3;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;

  __asm__ volatile("call *%[entry]"
                   : "+r"(rax)
                   : [entry] "r"(syscall_entry), "r"(rdi), "r"(rsi), "r"(rdx),
                     "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return rax;
}

/* Re-implement some utility functions and re-define the structures to avoid
 * dependency on libc. */

// Define the FileStat structure
struct FileStat {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned long st_nlink;

  unsigned int st_mode;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned int __pad0;
  unsigned long st_rdev;
  long st_size;
  long st_blksize;
  long st_blocks; /* Number 512-byte blocks allocated. */

  unsigned long st_atime;
  unsigned long st_atime_nsec;
  unsigned long st_mtime;
  unsigned long st_mtime_nsec;
  unsigned long st_ctime;
  unsigned long st_ctime_nsec;
  long __unused[3];
};

int memcmp(const void *s1, const void *s2, size_t n) {
  const unsigned char *p1 = s1;
  const unsigned char *p2 = s2;
  while (n--) {
    if (*p1 != *p2) {
      return *p1 - *p2;
    }
    p1++;
    p2++;
  }
  return 0;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *strncpy(char *dest, const char *src, size_t n) {
  char *d = dest;
  const char *s = src;
  while (n-- && *s) {
    *d++ = *s++;
  }
  while (n--) {
    *d++ = '\0';
  }
  return dest;
}

static uint64_t read_u64(const void *p) {
  uint64_t v;
  __builtin_memcpy(&v, p, 8);
  return v;
}

static size_t align_up(size_t val, size_t align) {
  return (val + align - 1) & ~(align - 1);
}

unsigned int la_version(unsigned int version __attribute__((unused))) {
  return LAV_CURRENT;
}

/// print value in hex
void print_hex(uint64_t data) {
#ifdef DEBUG
  for (int i = 15; i >= 0; i--) {
    unsigned char byte = (data >> (i * 4)) & 0xF;
    if (byte < 10) {
      syscall_print((&"0123456789"[byte]), 1);
    } else {
      syscall_print((&"abcdef"[byte - 10]), 1);
    }
  }
  syscall_print("\n", 1);
#endif
}

/// @brief Parse object to find the syscall entry point and the interpreter
/// path.
///
/// Different from the elf loader in the `litebox_shim_linux` crate, this
/// function does not read the trampoline section from the section headers
/// because they were overwritten after the binary was completely loaded.
/// Instead, since we know it's loaded right after the last loadable segment, we
/// can read the trampoline section from the end of the binary. The trampoline
/// section is expected to contain a magic number and the address of the syscall
/// entry point.
int parse_object(const struct link_map *map) {
  unsigned long max_addr = 0;
  Elf64_Ehdr *eh = (Elf64_Ehdr *)map->l_addr;
  if (memcmp(eh->e_ident,
             "\x7f"
             "ELF",
             4) != 0) {
    syscall_print("[audit] not an ELF file\n", 24);
    return 1;
  }
  Elf64_Phdr *phdrs = (Elf64_Phdr *)((char *)map->l_addr + eh->e_phoff);
  for (int i = 0; i < eh->e_phnum; i++) {
    if (phdrs[i].p_type == PT_LOAD) {
      unsigned long vaddr_end = (phdrs[i].p_vaddr + phdrs[i].p_memsz);
      if (vaddr_end > max_addr) {
        max_addr = vaddr_end;
      }
    } else if (phdrs[i].p_type == PT_INTERP) {
      strncpy(interp, (char *)map->l_addr + phdrs[i].p_vaddr,
              sizeof(interp) - 1);
      interp[sizeof(interp) - 1] = '\0'; // Ensure null termination
    }
  }
  max_addr = align_up(max_addr, 0x1000);
  void *trampoline_addr = (void *)map->l_addr + max_addr;
  if (read_u64(trampoline_addr) != TRAMP_MAGIC) {
    syscall_print("[audit] invalid trampoline magic\n", 30);
    return 1;
  }
  syscall_entry = (syscall_stub_t)read_u64(trampoline_addr + 8);
  print_hex((uint64_t)syscall_entry);
  return 0;
}

unsigned int la_objopen(struct link_map *map,
                        Lmid_t lmid __attribute__((unused)),
                        uintptr_t *cookie __attribute__((unused))) {
  syscall_print("[audit] la_objopen called\n", 26);
  const char *path = map->l_name;

  if (!path || path[0] == '\0') {
    // main binary should be called first.
    if (map->l_addr != 0) {
      // `map->l_addr` is zero for the main binary if it is not position
      // independent.
      assert(parse_object(map) == 0);
      syscall_print("[audit] main binary is patched by libOS\n", 40);
      syscall_print("[audit] interp=", 15);
      syscall_print(interp, sizeof(interp) - 1);
      syscall_print("\n", 1);
    }
    return 0; // main binary is patched by libOS
  }

  if (syscall_entry == 0) {
    // failed to get the syscall entry point from the main binary
    // fall back to get it from ld-*.so, which should be called next.
    assert(parse_object(map) == 0);
    syscall_print("[audit] ld is patched by libOS: \n", 33);
    syscall_print(path, 32);
    syscall_print("\n", 1);
    return 0; // ld.so is patched by libOS
  }

  if (interp[0] != '\0' && strcmp(path, interp) == 0) {
    // successfully get the entry point and interpreter from the main binary
    syscall_print("[audit] ld-*.so is patched by libOS\n", 36);
    return 0; // ld.so is patched by libOS
  }

  // Other shared libraries
  syscall_print("[audit] la_objopen: path=", 25);
  syscall_print(path, 32);
  syscall_print("\n", 1);

  if (!syscall_entry) {
    return 0;
  }

  int fd = do_syscall(SYS_openat, AT_FDCWD, (long)path, 0, 0, 0, 0);
  if (fd < 0) {
    syscall_print("[audit] failed to open file\n", 26);
    return 0;
  }

  struct FileStat st;
  if (do_syscall(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) {
    syscall_print("[audit] fstat failed\n", 21);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }
  long file_size = st.st_size;

  void *map_base =
      (void *)do_syscall(SYS_mmap, 0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((uintptr_t)map_base >= (uintptr_t)-4096) {
    syscall_print("[audit] mmap failed\n", 20);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  Elf64_Ehdr *eh = (Elf64_Ehdr *)map_base;
  if (memcmp(eh->e_ident,
             "\x7f"
             "ELF",
             4) != 0) {
    syscall_print("[audit] not an ELF file\n", 24);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)map_base + eh->e_shoff);
  Elf64_Shdr *shstr = &shdrs[eh->e_shstrndx];
  const char *shnames = (char *)map_base + shstr->sh_offset;

  for (int i = 0; i < eh->e_shnum; i++) {
    const char *name = shnames + shdrs[i].sh_name;
    if (strcmp(name, TARGET_SECTION_NAME) != 0)
      continue;

    syscall_print("[audit] found section\n", 22);
    if (shdrs[i].sh_size < 24)
      break;
    const uint8_t *sec = (uint8_t *)map_base + shdrs[i].sh_offset;
    if (read_u64(sec) != HEADER_MAGIC) {
      syscall_print("[audit] invalid header magic\n", 29);
      break;
    }

    uint64_t tramp_addr = map->l_addr + read_u64(sec + 8);
    uint64_t tramp_size_raw = read_u64(sec + 16);
    uint64_t tramp_off = file_size - tramp_size_raw;
    uint64_t tramp_size = align_up(tramp_size_raw, 0x1000);

    void *mapped =
        (void *)do_syscall(SYS_mmap, tramp_addr, tramp_size,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, tramp_off);
    if ((uintptr_t)mapped >= (uintptr_t)-4096) {
      syscall_print("[audit] mmap failed for trampoline\n", 35);
      break;
    }
    if ((uint64_t)mapped != tramp_addr) {
      syscall_print("[audit] mmap returned unexpected address\n", 40);
      print_hex((uint64_t)mapped);
      syscall_print("\n", 1);
      do_syscall(SYS_munmap, (long)mapped, tramp_size, 0, 0, 0, 0);
      break;
    }

    const uint64_t *tramp = (const uint64_t *)tramp_addr;
    if (tramp[0] != TRAMP_MAGIC) {
      syscall_print("[audit] invalid trampoline magic\n", 33);
      break;
    }

    __builtin_memcpy((char *)mapped + 8, (const void *)&syscall_entry, 8);
    do_syscall(SYS_mprotect, (long)mapped, tramp_size, PROT_READ | PROT_EXEC, 0,
               0, 0);
    syscall_print("[audit] trampoline patched and protected\n", 41);
    break;
  }

  do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
  do_syscall(SYS_munmap, (long)map_base, file_size, 0, 0, 0, 0);
  return 0;
}