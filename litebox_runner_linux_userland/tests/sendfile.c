// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include "helpers.h"

#include <fcntl.h>
#include <sys/eventfd.h>

#define SRC_PATH "/tmp/lb_sendfile_src"
#define DST_PATH "/tmp/lb_sendfile_dst"

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

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) die("fcntl F_GETFL");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) die("fcntl F_SETFL O_NONBLOCK");
}

static void fill_pipe_until_eagain(int write_fd) {
    char buf[4096];
    memset(buf, 'p', sizeof(buf));

    for (;;) {
        ssize_t n = write(write_fd, buf, sizeof(buf));
        if (n > 0) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n < 0) die("fill pipe");
        TEST_ASSERT(0, "fill pipe: zero-byte write");
    }
}

static void drain_pipe_exact(int read_fd, size_t want) {
    char buf[4096];

    while (want > 0) {
        size_t chunk = want < sizeof(buf) ? want : sizeof(buf);
        ssize_t n = read(read_fd, buf, chunk);
        if (n < 0) die("drain pipe");
        TEST_ASSERT(n != 0, "drain pipe: EOF before requested bytes");
        want -= (size_t)n;
    }
}

static void read_full(int fd, char *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(fd, buf + got, want - got);
        if (n < 0) die("read");
        TEST_ASSERT(n != 0, "short read");
        got += (size_t)n;
    }
}

static void test_happy_null_offset(void) {
    const char data[] = "abcdefghijklmnopqrstuvwxyz";
    const size_t len = sizeof(data) - 1;
    int src = make_src_with_data(data, len);
    int dst = make_dst_empty();

    ssize_t r = sys_sendfile(dst, src, NULL, len);
    TEST_ASSERT(r == (ssize_t)len, "happy_null_offset: return count");
    TEST_ASSERT(fd_pos(src) == (off_t)len, "happy_null_offset: source position");
    TEST_ASSERT(fd_pos(dst) == (off_t)len, "happy_null_offset: destination position");

    if (lseek(dst, 0, SEEK_SET) < 0) die("lseek dst");
    char buf[64] = {0};
    read_full(dst, buf, len);
    TEST_ASSERT(memcmp(buf, data, len) == 0, "happy_null_offset: dst content");

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
    TEST_ASSERT(r == 4, "happy_with_offset: return count");
    TEST_ASSERT(off == 9, "happy_with_offset: offset pointer");
    // src position must NOT have moved when an explicit offset was supplied.
    TEST_ASSERT(fd_pos(src) == 3, "happy_with_offset: source position unchanged");
    TEST_ASSERT(fd_pos(dst) == 4, "happy_with_offset: destination position");

    if (lseek(dst, 0, SEEK_SET) < 0) die("lseek dst");
    char buf[8] = {0};
    read_full(dst, buf, 4);
    TEST_ASSERT(memcmp(buf, "5678", 4) == 0, "happy_with_offset: dst content");

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
    TEST_ASSERT(r == 3, "count_exceeds_remaining: return count");
    TEST_ASSERT(fd_pos(src) == (off_t)len, "count_exceeds_remaining: source position");

    close(src);
    close(dst);
}

static void test_offset_past_eof(void) {
    const char data[] = "tiny";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();

    off_t off = 100;
    ssize_t r = sys_sendfile(dst, src, &off, 8);
    TEST_ASSERT(r == 0, "offset_past_eof: return count");
    TEST_ASSERT(off == 100, "offset_past_eof: offset pointer unchanged");
    TEST_ASSERT(fd_pos(dst) == 0, "offset_past_eof: destination position");

    close(src);
    close(dst);
}

static void test_count_zero(void) {
    const char data[] = "anything";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();

    ssize_t r = sys_sendfile(dst, src, NULL, 0);
    TEST_ASSERT(r == 0, "count_zero_null_off: return count");
    TEST_ASSERT(fd_pos(src) == 0, "count_zero_null_off: source position unchanged");

    off_t off = 4;
    r = sys_sendfile(dst, src, &off, 0);
    TEST_ASSERT(r == 0, "count_zero_with_off: return count");
    TEST_ASSERT(off == 4, "count_zero_with_off: offset pointer unchanged");
    TEST_ASSERT(fd_pos(src) == 0, "count_zero_with_off: source position unchanged");

    close(src);
    close(dst);
}

static void test_bad_in_fd(void) {
    int dst = make_dst_empty();
    errno = 0;
    ssize_t r = sys_sendfile(dst, 9999, NULL, 4);
    TEST_ASSERT(r == -1 && errno == EBADF, "bad_in_fd: EBADF");
    close(dst);
}

static void test_bad_out_fd(void) {
    const char data[] = "data";
    int src = make_src_with_data(data, sizeof(data) - 1);
    if (lseek(src, 2, SEEK_SET) < 0) die("lseek src to 2");
    errno = 0;
    ssize_t r = sys_sendfile(9999, src, NULL, 4);
    TEST_ASSERT(r == -1 && errno == EBADF, "bad_out_fd: EBADF");
    TEST_ASSERT(fd_pos(src) == 2, "bad_out_fd: source position unchanged");
    close(src);
}

static void test_bad_out_fd_checked_before_bad_in_fd_type(void) {
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");
    if (write(pfd[1], "data", 4) != 4) die("write pipe");

    errno = 0;
    ssize_t r = sys_sendfile(9999, pfd[0], NULL, 4);
    TEST_ASSERT(r == -1 && errno == EBADF, "bad_out_fd_before_bad_in_fd_type: EBADF");

    close(pfd[0]);
    close(pfd[1]);
}

static void test_negative_offset(void) {
    const char data[] = "data";
    int src = make_src_with_data(data, sizeof(data) - 1);
    int dst = make_dst_empty();
    off_t off = -1;
    errno = 0;
    ssize_t r = sys_sendfile(dst, src, &off, 4);
    TEST_ASSERT(r == -1 && errno == EINVAL, "negative_offset: EINVAL");
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
    TEST_ASSERT(r == 5, "file_to_pipe_null_offset: return count");
    TEST_ASSERT(fd_pos(src) == 7, "file_to_pipe_null_offset: source position");

    char buf[8] = {0};
    read_full(pfd[0], buf, 5);
    TEST_ASSERT(memcmp(buf, "cdefg", 5) == 0, "file_to_pipe_null_offset: pipe content");

    close(src);
    close(pfd[0]);
    close(pfd[1]);
}

static void test_full_nonblocking_pipe_keeps_null_offset_position(void) {
    char data[8192];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (char)('A' + (i % 26));

    int src = make_src_with_data(data, sizeof(data));
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");
    set_nonblocking(pfd[1]);
    fill_pipe_until_eagain(pfd[1]);

    if (lseek(src, 123, SEEK_SET) < 0) die("lseek src to 123");
    errno = 0;
    ssize_t r = sys_sendfile(pfd[1], src, NULL, sizeof(data));
    TEST_ASSERT(r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
                "full_nonblocking_pipe_null_offset: EAGAIN");
    TEST_ASSERT(fd_pos(src) == 123,
                "full_nonblocking_pipe_null_offset: source position unchanged");

    close(src);
    close(pfd[0]);
    close(pfd[1]);
}

static void test_partial_nonblocking_pipe_error_is_deferred(void) {
    char data[16384];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (char)('a' + (i % 26));

    int src = make_src_with_data(data, sizeof(data));
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");
    set_nonblocking(pfd[1]);
    fill_pipe_until_eagain(pfd[1]);
    drain_pipe_exact(pfd[0], 4096);

    if (lseek(src, 123, SEEK_SET) < 0) die("lseek src to 123");
    errno = 0;
    ssize_t r = sys_sendfile(pfd[1], src, NULL, sizeof(data));
    TEST_ASSERT(r > 0, "partial_nonblocking_pipe_error_deferred: partial success");
    off_t want_pos = 123 + r;
    TEST_ASSERT(fd_pos(src) == want_pos,
                "partial_nonblocking_pipe_error_deferred: source position");

    errno = 0;
    ssize_t retry = sys_sendfile(pfd[1], src, NULL, sizeof(data));
    TEST_ASSERT(retry == -1 && (errno == EAGAIN || errno == EWOULDBLOCK),
                "partial_nonblocking_pipe_error_deferred retry: EAGAIN");
    TEST_ASSERT(fd_pos(src) == want_pos,
                "partial_nonblocking_pipe_error_deferred retry: source position unchanged");

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
    TEST_ASSERT(r == 3, "file_to_pipe_with_offset: return count");
    TEST_ASSERT(off == 7, "file_to_pipe_with_offset: offset pointer");
    TEST_ASSERT(fd_pos(src) == 1, "file_to_pipe_with_offset: source position unchanged");

    char buf[8] = {0};
    read_full(pfd[0], buf, 3);
    TEST_ASSERT(memcmp(buf, "EFG", 3) == 0, "file_to_pipe_with_offset: pipe content");

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
    TEST_ASSERT(r == -1 && errno == EINVAL, label);

    off_t off = 0;
    errno = 0;
    r = sys_sendfile(dst, in_fd, &off, 4);
    TEST_ASSERT(r == -1 && errno == ESPIPE, label);

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
    test_bad_out_fd_checked_before_bad_in_fd_type();
    test_negative_offset();
    test_file_to_pipe_null_offset();
    test_full_nonblocking_pipe_keeps_null_offset_position();
    test_partial_nonblocking_pipe_error_is_deferred();
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
