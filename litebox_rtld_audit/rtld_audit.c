// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>

// The magic number used to identify the LiteBox trampoline.
// This must match `TRAMPOLINE_MAGIC` in `litebox_syscall_rewriter` and `litebox_common_linux`.
// Value 0x30584f424554494c is "LITEBOX0" in little-endian (bytes: 'L','I','T','E','B','O','X','0')
#define TRAMPOLINE_MAGIC ((uint64_t)0x30584f424554494c)

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

// Maximum number of pages to search for trampoline
#define MAX_SEARCH_PAGES 16
// Maximum allowed trampoline size (must match Rust loader)
#define MAX_TRAMP_SIZE (MAX_SEARCH_PAGES * 0x1000)
// Trampoline header size for x86_64: 8 (magic) + 8 (entry) + 8 (vaddr) + 8 (size)
#define TRAMP_HEADER_SIZE 32
// Maximum valid userspace address (48-bit address space)
#define MAX_USERSPACE_ADDR 0x7FFFFFFFFFFFUL

// Linux flags
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
// MAP_FIXED_NOREPLACE (Linux 4.17+): Like MAP_FIXED but fails if address is already mapped
// This prevents silently overwriting existing mappings
#define MAP_FIXED_NOREPLACE 0x100000

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

  __asm__ volatile("leaq 1f(%%rip), %%rcx\n"
                   "jmp *%[entry]\n"
                   "1:\n"
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
  size_t result = (val + align - 1) & ~(align - 1);
  // Check for overflow (result < val means we wrapped)
  if (result < val) return (size_t)-1;
  return result;
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
  if (read_u64(trampoline_addr) != TRAMPOLINE_MAGIC) {
    syscall_print("[audit] invalid trampoline magic\n", 34);
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
    syscall_print("[audit] failed to open file\n", 28);
    return 0;
  }

  struct FileStat st;
  if (do_syscall(SYS_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) {
    syscall_print("[audit] fstat failed\n", 21);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }
  long file_size = st.st_size;

  // File must be large enough to contain at least a trampoline header
  if (file_size < TRAMP_HEADER_SIZE) {
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Search for trampoline at page boundaries from the end of the file.
  // The trampoline data starts with TRAMPOLINE_MAGIC followed by:
  // - syscall entry point (8 bytes)
  // - trampoline virtual address (8 bytes)
  // - trampoline size (8 bytes for x86_64)
  // Use same formula as Rust: (file_size - 1) & ~(PAGE_SIZE - 1)
  long search_offset = (file_size - 1) & ~0xFFFUL;

  uint64_t tramp_vaddr = 0;
  uint64_t tramp_size_raw = 0;
  long tramp_file_offset = -1;

  for (int page = 0; page < MAX_SEARCH_PAGES && search_offset >= 0; page++) {
    // Must have enough bytes remaining to read the full header
    if (file_size - search_offset < TRAMP_HEADER_SIZE) {
      search_offset -= 0x1000;
      continue;
    }

    // Map just this page to read the header
    void *page_map = (void *)do_syscall(SYS_mmap, 0, 0x1000, PROT_READ, MAP_PRIVATE, fd, search_offset);
    if ((uintptr_t)page_map >= (uintptr_t)-4096) {
      search_offset -= 0x1000;
      continue;
    }

    // Read directly from mmap'd page
    uint64_t magic = read_u64(page_map);
    if (magic == TRAMPOLINE_MAGIC) {
      // Found trampoline header (x86_64)
      // [0..8]: magic, [8..16]: entry, [16..24]: vaddr, [24..32]: size
      tramp_vaddr = read_u64((char *)page_map + 16);
      tramp_size_raw = read_u64((char *)page_map + 24);
      tramp_file_offset = search_offset;
      do_syscall(SYS_munmap, (long)page_map, 0x1000, 0, 0, 0, 0);
      syscall_print("[audit] found trampoline at page boundary\n", 42);
      break;
    }

    do_syscall(SYS_munmap, (long)page_map, 0x1000, 0, 0, 0, 0);
    search_offset -= 0x1000;
  }

  // Validate trampoline was found and has reasonable parameters
  if (tramp_file_offset < 0 || tramp_size_raw == 0) {
    // No trampoline found
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Validate trampoline size upper bound (must match Rust loader)
  if (tramp_size_raw > MAX_TRAMP_SIZE) {
    syscall_print("[audit] trampoline size too large\n", 34);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Validate trampoline doesn't extend beyond file
  if (tramp_file_offset + tramp_size_raw > file_size) {
    syscall_print("[audit] trampoline extends beyond file\n", 39);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Validate tramp_vaddr is within reasonable userspace bounds
  if (tramp_vaddr > MAX_USERSPACE_ADDR) {
    syscall_print("[audit] trampoline vaddr out of bounds\n", 39);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  uint64_t tramp_addr = map->l_addr + tramp_vaddr;
  uint64_t tramp_size = align_up(tramp_size_raw, 0x1000);

  // Check for overflow in align_up or address calculation
  if (tramp_size == (size_t)-1 || tramp_addr < map->l_addr) {
    syscall_print("[audit] trampoline size/addr overflow\n", 38);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Use MAP_FIXED to place the trampoline at the exact required address.
  void *mapped =
      (void *)do_syscall(SYS_mmap, tramp_addr, tramp_size,
                         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, tramp_file_offset);
  if ((uintptr_t)mapped >= (uintptr_t)-4096) {
    syscall_print("[audit] mmap failed for trampoline\n", 35);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  // Re-validate magic after mapping to detect TOCTOU attacks
  const uint64_t *tramp = (const uint64_t *)tramp_addr;
  if (tramp[0] != TRAMPOLINE_MAGIC) {
    syscall_print("[audit] invalid trampoline magic after map\n", 43);
    do_syscall(SYS_munmap, (long)mapped, tramp_size, 0, 0, 0, 0);
    do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
  }

  __builtin_memcpy((char *)mapped + 8, (const void *)&syscall_entry, 8);
  do_syscall(SYS_mprotect, (long)mapped, tramp_size, PROT_READ | PROT_EXEC, 0,
             0, 0);
  syscall_print("[audit] trampoline patched and protected\n", 41);

  do_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
  return 0;
}