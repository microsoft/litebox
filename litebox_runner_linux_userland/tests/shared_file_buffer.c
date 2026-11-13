// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"

#include <sys/mman.h>

int main(void) {
    const size_t length = 128 * 1024;
    char path[] = "/tmp/litebox-shared-buffer-XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "mkstemp");
    int reader = open(path, O_RDONLY);
    TEST_ASSERT(reader >= 0, "open reader");
    TEST_ASSERT(unlink(path) == 0, "unlink buffer");
    TEST_ASSERT(ftruncate(fd, length) == 0, "size buffer");

    char *buffer = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    TEST_ASSERT(buffer != MAP_FAILED, "map writable buffer");
    const char *view = mmap(NULL, length, PROT_READ, MAP_SHARED, reader, 0);
    TEST_ASSERT(view != MAP_FAILED, "map read-only buffer");

    buffer[0] = 'a';
    buffer[length - 1] = 'z';
    TEST_ASSERT(view[0] == 'a' && view[length - 1] == 'z', "mappings share buffer");
    char byte = 0;
    TEST_ASSERT(pread(reader, &byte, 1, length - 1) == 1 && byte == 'z', "read mapped buffer");
    TEST_ASSERT(pwrite(fd, "b", 1, 0) == 1 && buffer[0] == 'b' && view[0] == 'b',
                "write mapped buffer");

    TEST_ASSERT(close(reader) == 0, "close reader");
    TEST_ASSERT(close(fd) == 0, "close buffer");
    TEST_ASSERT(view[0] == 'b' && view[length - 1] == 'z', "mappings outlive descriptors");
    TEST_ASSERT(munmap((void *)view, length) == 0, "unmap read-only buffer");
    TEST_ASSERT(munmap(buffer, length) == 0, "unmap writable buffer");
    puts("shared file buffer ok");
    return 0;
}
