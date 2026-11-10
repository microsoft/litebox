// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// MAP_SHARED file mappings share the file's contents with reads, writes, and other mappings.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char path[] = "/tmp/lb_map_shared_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(write(fd, "hello", 5) == 5);
    long page = sysconf(_SC_PAGESIZE);

    char *first = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(first != MAP_FAILED);
    assert(memcmp(first, "hello", 5) == 0);

    // A store through the mapping reaches reads of the file.
    first[0] = 'j';
    char buf[5];
    assert(pread(fd, buf, 5, 0) == 5);
    assert(memcmp(buf, "jello", 5) == 0);

    // A write to the file reaches the mapping.
    assert(pwrite(fd, "y", 1, 1) == 1);
    assert(first[1] == 'y');

    // Another mapping of the file, through another open, shares the same bytes.
    int other_fd = open(path, O_RDONLY);
    assert(other_fd >= 0);
    char *second = mmap(NULL, page, PROT_READ, MAP_SHARED, other_fd, 0);
    assert(second != MAP_FAILED);
    first[2] = 'x';
    assert(second[2] == 'x');

    // A read-only descriptor cannot be mapped writable.
    assert(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, other_fd, 0) == MAP_FAILED);

    // Shared pages are never made executable, since syscall patching cannot rewrite them.
    assert(mprotect(second, page, PROT_READ | PROT_EXEC) == -1 && errno == EACCES);

    // MADV_FREE only applies to anonymous memory.
    assert(madvise(first, page, MADV_FREE) == -1 && errno == EINVAL);

    // A mapping that fails after the broker lent the memory leaves later mappings working.
    for (int i = 0; i < 1000; i++) {
        assert(mmap(second, page, PROT_READ, MAP_SHARED | MAP_FIXED_NOREPLACE, other_fd, 0) ==
               MAP_FAILED);
    }
    char *third = mmap(NULL, page, PROT_READ, MAP_SHARED, other_fd, 0);
    assert(third != MAP_FAILED && third[2] == 'x');
    assert(munmap(third, page) == 0);

    // Unlinking the file keeps it shared through descriptors still open on it.
    assert(unlink(path) == 0);
    char *after_unlink = mmap(NULL, page, PROT_READ, MAP_SHARED, other_fd, 0);
    assert(after_unlink != MAP_FAILED);
    first[3] = 'q';
    assert(after_unlink[3] == 'q');
    assert(munmap(after_unlink, page) == 0);
    first[3] = 'l';

    // The file's size follows the shared contents.
    assert(ftruncate(fd, 2 * page) == 0);
    struct stat st;
    assert(fstat(other_fd, &st) == 0);
    assert(st.st_size == 2 * page);

    assert(munmap(first, page) == 0);
    assert(munmap(second, page) == 0);
    assert(pread(other_fd, buf, 5, 0) == 5);
    assert(memcmp(buf, "jyxlo", 5) == 0);

    close(other_fd);
    close(fd);
    printf("map_shared_file: ok\n");
    return 0;
}
