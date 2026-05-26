// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define SRC_PATH "/tmp/lb_sendfile_src"
#define DST_PATH "/tmp/lb_sendfile_dst"

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("FAIL: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

// Raw syscall — the shim intercepts SYS_sendfile.
static ssize_t sys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    return (ssize_t)syscall(SYS_sendfile, out_fd, in_fd, offset, count);
}

static int make_src_with_data(const char *data, size_t len) {
    int fd = open(SRC_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open SRC_PATH");
    if (write(fd, data, len) != (ssize_t)len) die("write src");
    if (lseek(fd, 0, SEEK_SET) < 0) die("lseek src");
    return fd;
}

static int make_dst_empty(void) {
    int fd = open(DST_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open DST_PATH");
    return fd;
}

static off_t fd_pos(int fd) {
    off_t p = lseek(fd, 0, SEEK_CUR);
    if (p < 0) die("lseek SEEK_CUR");
    return p;
}

static void read_full(int fd, char *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(fd, buf + got, want - got);
        if (n < 0) die("read");
        if (n == 0) fail("short read: got %zu of %zu", got, want);
        got += (size_t)n;
    }
}

static void test_happy_null_offset(void) {
    const char data[] = "abcdefghijklmnopqrstuvwxyz";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int dst = make_dst_empty();

    ssize_t r = sys_sendfile(dst, src, NULL, len);
    if (r != (ssize_t)len) fail("happy_null_offset: ret=%zd want=%zu", r, len);
    if (fd_pos(src) != (off_t)len)
        fail("happy_null_offset: src pos=%lld want=%zu", (long long)fd_pos(src), len);
    if (fd_pos(dst) != (off_t)len)
        fail("happy_null_offset: dst pos=%lld want=%zu", (long long)fd_pos(dst), len);

    if (lseek(dst, 0, SEEK_SET) < 0) die("lseek dst");
    char buf[64] = {0};
    read_full(dst, buf, len);
    if (memcmp(buf, data, len) != 0)
        fail("happy_null_offset: dst content mismatch");

    close(src);
    close(dst);
}

static void test_happy_with_offset(void) {
    const char data[] = "0123456789ABCDEF";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int dst = make_dst_empty();

    if (lseek(src, 3, SEEK_SET) < 0) die("lseek src to 3");
    off_t off = 5;
    ssize_t r = sys_sendfile(dst, src, &off, 4);
    if (r != 4) fail("happy_with_offset: ret=%zd want=4", r);
    if (off != 9) fail("happy_with_offset: *offset=%lld want=9", (long long)off);
    // src position must NOT have moved when an explicit offset was supplied.
    if (fd_pos(src) != 3)
        fail("happy_with_offset: src pos=%lld want=3 (must be unchanged)",
             (long long)fd_pos(src));
    if (fd_pos(dst) != 4)
        fail("happy_with_offset: dst pos=%lld want=4", (long long)fd_pos(dst));

    if (lseek(dst, 0, SEEK_SET) < 0) die("lseek dst");
    char buf[8] = {0};
    read_full(dst, buf, 4);
    if (memcmp(buf, "5678", 4) != 0)
        fail("happy_with_offset: dst content = '%.4s' want '5678'", buf);

    close(src);
    close(dst);
}

static void test_count_exceeds_remaining(void) {
    const char data[] = "12345678";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int dst = make_dst_empty();

    if (lseek(src, 5, SEEK_SET) < 0) die("lseek src to 5");
    ssize_t r = sys_sendfile(dst, src, NULL, 100);
    if (r != 3) fail("count_exceeds_remaining: ret=%zd want=3", r);
    if (fd_pos(src) != (off_t)len)
        fail("count_exceeds_remaining: src pos=%lld want=%zu",
             (long long)fd_pos(src), len);

    close(src);
    close(dst);
}

static void test_offset_past_eof(void) {
    const char data[] = "tiny";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();

    off_t off = 100;
    ssize_t r = sys_sendfile(dst, src, &off, 8);
    if (r != 0) fail("offset_past_eof: ret=%zd want=0", r);
    if (off != 100) fail("offset_past_eof: *offset=%lld want=100", (long long)off);
    if (fd_pos(dst) != 0) fail("offset_past_eof: dst pos=%lld want=0", (long long)fd_pos(dst));

    close(src);
    close(dst);
}

static void test_count_zero(void) {
    const char data[] = "anything";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();

    ssize_t r = sys_sendfile(dst, src, NULL, 0);
    if (r != 0) fail("count_zero_null_off: ret=%zd want=0", r);
    if (fd_pos(src) != 0)
        fail("count_zero_null_off: src pos=%lld want=0 (unchanged)",
             (long long)fd_pos(src));

    off_t off = 4;
    r = sys_sendfile(dst, src, &off, 0);
    if (r != 0) fail("count_zero_with_off: ret=%zd want=0", r);
    if (off != 4)
        fail("count_zero_with_off: *offset=%lld want=4 (unchanged)", (long long)off);
    if (fd_pos(src) != 0)
        fail("count_zero_with_off: src pos=%lld want=0 (unchanged)",
             (long long)fd_pos(src));

    close(src);
    close(dst);
}

static void test_bad_in_fd(void) {
    int dst = make_dst_empty();
    errno = 0;
    ssize_t r = sys_sendfile(dst, 9999, NULL, 4);
    if (r != -1 || errno != EBADF)
        fail("bad_in_fd: ret=%zd errno=%d want -1/EBADF", r, errno);
    close(dst);
}

static void test_bad_out_fd(void) {
    const char data[] = "data";
    int src = make_src_with_data(data, sizeof(data) - 1);
    errno = 0;
    ssize_t r = sys_sendfile(9999, src, NULL, 4);
    if (r != -1 || errno != EBADF)
        fail("bad_out_fd: ret=%zd errno=%d want -1/EBADF", r, errno);
    close(src);
}

static void test_negative_offset(void) {
    const char data[] = "data";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();
    off_t off = -1;
    errno = 0;
    ssize_t r = sys_sendfile(dst, src, &off, 4);
    if (r != -1 || errno != EINVAL)
        fail("negative_offset: ret=%zd errno=%d want -1/EINVAL", r, errno);
    close(src);
    close(dst);
}

static void test_file_to_pipe_null_offset(void) {
    const char data[] = "abcdefghij";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");

    if (lseek(src, 2, SEEK_SET) < 0) die("lseek src to 2");
    ssize_t r = sys_sendfile(pfd[1], src, NULL, 5);
    if (r != 5) fail("file_to_pipe_null_offset: ret=%zd want=5", r);
    if (fd_pos(src) != 7)
        fail("file_to_pipe_null_offset: src pos=%lld want=7", (long long)fd_pos(src));

    char buf[8] = {0};
    read_full(pfd[0], buf, 5);
    if (memcmp(buf, "cdefg", 5) != 0)
        fail("file_to_pipe_null_offset: read '%.5s' want 'cdefg'", buf);

    close(src);
    close(pfd[0]);
    close(pfd[1]);
}

static void test_file_to_pipe_with_offset(void) {
    const char data[] = "ABCDEFGHIJ";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");

    // Park src at a position that must NOT change after sendfile.
    if (lseek(src, 1, SEEK_SET) < 0) die("lseek src to 1");
    off_t off = 4;
    ssize_t r = sys_sendfile(pfd[1], src, &off, 3);
    if (r != 3) fail("file_to_pipe_with_offset: ret=%zd want=3", r);
    if (off != 7) fail("file_to_pipe_with_offset: *offset=%lld want=7", (long long)off);
    if (fd_pos(src) != 1)
        fail("file_to_pipe_with_offset: src pos=%lld want=1 (unchanged)",
             (long long)fd_pos(src));

    char buf[8] = {0};
    read_full(pfd[0], buf, 3);
    if (memcmp(buf, "EFG", 3) != 0)
        fail("file_to_pipe_with_offset: read '%.3s' want 'EFG'", buf);

    close(src);
    close(pfd[0]);
    close(pfd[1]);
}

// Linux returns EINVAL when a non-pread-capable in_fd is paired with a NULL
// offset, and ESPIPE when it is paired with an explicit offset (the
// FMODE_PREAD check fires first). Verify both branches for each non-regular
// fd type the shim can encounter as in_fd.
static void expect_einval_espipe_in_fd(int in_fd, const char *label) {
    int dst = make_dst_empty();

    errno = 0;
    ssize_t r = sys_sendfile(dst, in_fd, NULL, 4);
    if (r != -1 || errno != EINVAL)
        fail("%s: NULL offset got ret=%zd errno=%d want -1/EINVAL", label, r, errno);

    off_t off = 0;
    errno = 0;
    r = sys_sendfile(dst, in_fd, &off, 4);
    if (r != -1 || errno != ESPIPE)
        fail("%s: &offset got ret=%zd errno=%d want -1/ESPIPE", label, r, errno);

    close(dst);
}

static void test_pipe_in_fd(void) {
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");
    if (write(pfd[1], "data", 4) != 4) die("write pipe");
    expect_einval_espipe_in_fd(pfd[0], "pipe in_fd");
    close(pfd[0]);
    close(pfd[1]);
}

static void test_eventfd_in_fd(void) {
    int efd = eventfd(7, 0);
    if (efd < 0) die("eventfd");
    expect_einval_espipe_in_fd(efd, "eventfd in_fd");
    close(efd);
}

static void test_unix_stream_in_fd(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) die("socketpair stream");
    if (write(sv[1], "data", 4) != 4) die("write unix stream");
    expect_einval_espipe_in_fd(sv[0], "unix stream in_fd");
    close(sv[0]);
    close(sv[1]);
}

static void test_unix_dgram_in_fd(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) die("socketpair dgram");
    if (write(sv[1], "data", 4) != 4) die("write unix dgram");
    expect_einval_espipe_in_fd(sv[0], "unix dgram in_fd");
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    printf("== sendfile syscall tests ==\n");

    test_happy_null_offset();
    test_happy_with_offset();
    test_count_exceeds_remaining();
    test_offset_past_eof();
    test_count_zero();
    test_bad_in_fd();
    test_bad_out_fd();
    test_negative_offset();
    test_file_to_pipe_null_offset();
    test_file_to_pipe_with_offset();
    test_pipe_in_fd();
    test_eventfd_in_fd();
    test_unix_stream_in_fd();
    test_unix_dgram_in_fd();

    unlink(SRC_PATH);
    unlink(DST_PATH);

    printf("All sendfile tests passed.\n");
    return 0;
}
