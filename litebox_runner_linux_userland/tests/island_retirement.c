// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ISLAND_MAPPING_PAGES
#define ISLAND_MAPPING_PAGES 3
#endif

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "island retirement line %d errno=%d\n", __LINE__, errno); return 1; } } while (0)
struct observed {
    long result;
    uintptr_t x16, x17, x30, nzcv, sp;
    unsigned char vector[16];
    uintptr_t original_sp;
};
typedef void (*entry_fn)(uintptr_t, uintptr_t, uintptr_t, long, atomic_int *, struct observed *);
static entry_fn entry;
static atomic_int entered;
static struct observed observed;
static int pipefd[2];
static char byte;
static unsigned char progress;
static atomic_int returned;
// Guest memory is filled by the shim's fallible assembly copy, not a C writer.
// Explicit acquire loads observe its one-byte progress without cached C reads.
static unsigned char read_progress(void) {
    unsigned int value;
    __asm__ volatile("ldarb %w0, [%1]" : "=r"(value) : "r"(&progress) : "memory");
    return (unsigned char)value;
}
static void *reader(void *unused) {
    (void)unused;
    struct iovec iov[] = {{&progress, 1}, {&byte, 1}};
    entry(pipefd[0], (uintptr_t)iov, 2, SYS_readv, &entered, &observed);
    atomic_store_explicit(&returned, 1, memory_order_release);
    return NULL;
}
// Every executed near page is a private allocation, reclaimed at the last source.
static int check_retired_near(uintptr_t near) {
    return mmap((void *)near, 4096, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0) == (void *)near;
}
int main(int argc, char **argv) {
    CHECK(argc == (ISLAND_MAPPING_PAGES == 4 ? 3 : 2));
    int fd = open("/lib/island_retirement.so", O_RDONLY);
    CHECK(fd >= 0);
    Elf64_Ehdr eh;
    CHECK(pread(fd, &eh, sizeof eh, 0) == sizeof eh);
    CHECK(eh.e_entry == 4096);
    char *base = mmap(NULL, ISLAND_MAPPING_PAGES * 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    CHECK(base != MAP_FAILED);
    entry = (entry_fn)(base + eh.e_entry);
    char *site_page = base + 4096;
    const uint32_t *site = (const uint32_t *)(base + 8192 - 4);
    CHECK((*site & 0xfc000000) == 0x14000000);
    uintptr_t near = ((uintptr_t)site + ((int64_t)(int32_t)(*site << 6) >> 4)) & ~4095UL;
    CHECK(near < (uintptr_t)base || near >= (uintptr_t)base + ISLAND_MAPPING_PAGES * 4096);
    if (ISLAND_MAPPING_PAGES == 4) {
        // The source was already a serialized branch, not an SVC rewritten here.
        // Its canonical page is occupied by this file mapping, so installation
        // must relocate the validated prebuilt pair to the executed near page.
        uint32_t serialized;
        CHECK(pread(fd, &serialized, 4, 8192 - 4) == 4);
        CHECK((serialized & 0xfc000000) == 0x14000000);
        uintptr_t canonical = (8192 - 4 + ((int64_t)(int32_t)(serialized << 6) >> 4)) & ~4095UL;
        CHECK(canonical == strtoull(argv[2], NULL, 0));
    }
    CHECK(close(fd) == 0);
    errno = 0;
    CHECK(madvise(site_page, 1, MADV_DONTNEED) == -1 && errno == EBUSY);
    errno = 0;
    CHECK(madvise((void *)near, 1, MADV_DONTNEED) == -1 && errno == EBUSY);
    CHECK(mprotect(base, 4096, PROT_READ) == 0);
    errno = 0;
    CHECK(madvise(base, 1, MADV_DONTNEED) == -1 && errno == EINVAL);
    CHECK(memcmp(base, ELFMAG, SELFMAG) == 0); // unsupported file reset is non-destructive
    if (strcmp(argv[1], "self") == 0) {
        entry((uintptr_t)site_page, 4096, 0, SYS_munmap, &entered, &observed);
        CHECK(observed.result == 0);
        CHECK(check_retired_near(near));
    } else {
        CHECK(strcmp(argv[1], "thread") == 0);
        CHECK(pipe(pipefd) == 0);
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, reader, NULL) == 0);
        // This tests the CURRENT shim's sequential read_from_iovec copy/wait,
        // not Linux readv semantics (native readv may return the first byte).
        // Seeing the first copy proves callback entry, unlike the pre-SVC marker.
        CHECK(write(pipefd[1], "p", 1) == 1);
        for (int retry = 0; read_progress() != 'p'; ++retry) {
            CHECK(retry < 1000 && !atomic_load_explicit(&returned, memory_order_acquire));
            usleep(1000);
        }
        CHECK(!atomic_load_explicit(&returned, memory_order_acquire));
        CHECK(munmap(site_page, 4096) == 0);
        // Verify reclaim, then close the page against stale returns.
        CHECK(check_retired_near(near));
        CHECK(write(pipefd[1], "x", 1) == 1);
        CHECK(pthread_join(thread, NULL) == 0);
        CHECK(atomic_load_explicit(&returned, memory_order_acquire));
        CHECK(observed.result == 2 && byte == 'x');
        CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    }
    CHECK(observed.x16 == 0x1616 && observed.x17 == 0x1717 && observed.x30 == 0x3030);
    CHECK(observed.nzcv == 0xa0000000 && observed.sp == observed.original_sp);
    for (unsigned int i = 0; i < sizeof observed.vector; ++i) CHECK(observed.vector[i] == 0xa5);
    CHECK(munmap((void *)near, 4096) == 0);
    CHECK(munmap(base, ISLAND_MAPPING_PAGES * 4096) == 0);
    puts("retired sole-site callback resumed with registers, SP, NZCV and SIMD intact");
    return 0;
}
