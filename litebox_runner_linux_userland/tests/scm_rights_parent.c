// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks passing descriptors over Unix sockets with `SCM_RIGHTS`, within a process and between
// forked processes.

#define _GNU_SOURCE
#include "helpers.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FDS 4
#define MAX_DATA 31

// Sends `data` over `socket` with `count` descriptors from `fds`, returning `sendmsg`'s result.
static ssize_t send_fds(int socket, const char *data, const int *fds, int count) {
    union {
        char buffer[CMSG_SPACE(sizeof(int) * MAX_FDS)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = {.iov_base = (void *)data, .iov_len = strlen(data)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    if (count > 0) {
        msg.msg_control = control.buffer;
        msg.msg_controllen = CMSG_SPACE(sizeof(int) * count);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * count);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * count);
    }
    return sendmsg(socket, &msg, 0);
}

// A message received with `recv_fds`.
struct received {
    char data[MAX_DATA + 1];
    ssize_t length;
    int fds[MAX_FDS];
    int count;
    int flags;
    size_t controllen;
};

// Receives up to `size` bytes from `socket` with room for `room` control bytes, collecting the
// passed descriptors.
static struct received recv_some_fds(int socket, size_t size, size_t room, int flags) {
    union {
        char buffer[CMSG_SPACE(sizeof(int) * MAX_FDS)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct received received = {0};
    TEST_ASSERT(size <= MAX_DATA, "receive size");
    struct iovec iov = {.iov_base = received.data, .iov_len = size};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = room ? control.buffer : NULL,
                         .msg_controllen = room};
    received.length = recvmsg(socket, &msg, flags);
    TEST_ASSERT(received.length >= 0, "recvmsg");
    received.flags = msg.msg_flags;
    received.controllen = msg.msg_controllen;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        TEST_ASSERT(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS,
                    "unexpected control message");
        int count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        TEST_ASSERT(received.count + count <= MAX_FDS, "too many descriptors");
        memcpy(received.fds + received.count, CMSG_DATA(cmsg), sizeof(int) * count);
        received.count += count;
    }
    return received;
}

static struct received recv_fds(int socket, size_t room, int flags) {
    return recv_some_fds(socket, MAX_DATA, room, flags);
}

static void socket_pair(int type, int fds[2]) {
    TEST_ASSERT(socketpair(AF_UNIX, type, 0, fds) == 0, "socketpair");
}

// Reads a byte from `fd` without blocking, so that a pipe whose write end leaked fails with EAGAIN
// rather than hanging.
static ssize_t read_now(int fd) {
    char byte;
    TEST_ASSERT(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "set O_NONBLOCK");
    errno = 0;
    return read(fd, &byte, 1);
}

static int pipe_ends(int fd) { return read_now(fd) == 0; }

static int pipe_open(int fd) { return read_now(fd) == -1 && errno == EAGAIN; }

static void test_pass_between_processes(void) {
    int channel[2];
    socket_pair(SOCK_STREAM, channel);
    int peer[2];
    socket_pair(SOCK_SEQPACKET, peer);
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork");
    if (child == 0) {
        close(channel[0]);
        close(peer[0]);
        close(peer[1]);
        // Send a pipe's read end and a file, keeping only the pipe's write end.
        int pipe_fds[2];
        TEST_ASSERT(pipe(pipe_fds) == 0, "pipe");
        char *path = test_path("scm_rights_file");
        int file = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        TEST_ASSERT(file >= 0, "open");
        TEST_ASSERT(write(file, "0123456789", 10) == 10, "write file");
        TEST_ASSERT(lseek(file, 3, SEEK_SET) == 3, "lseek");
        int sent[2] = {pipe_fds[0], file};
        TEST_ASSERT(send_fds(channel[1], "fds", sent, 2) == 3, "send pipe and file");
        close(pipe_fds[0]);
        close(file);
        TEST_ASSERT(write(pipe_fds[1], "piped", 5) == 5, "write pipe");
        close(pipe_fds[1]);
        // Receive a socket from the parent and talk over it.
        struct received received = recv_fds(channel[1], CMSG_SPACE(sizeof(int)), 0);
        TEST_ASSERT(received.count == 1 && received.length == 4, "receive socket");
        TEST_ASSERT(send(received.fds[0], "hello", 5, 0) == 5, "send over received socket");
        _exit(0);
    }
    close(channel[1]);
    struct received received = recv_fds(channel[0], CMSG_SPACE(sizeof(int) * 2), 0);
    TEST_ASSERT(received.length == 3 && memcmp(received.data, "fds", 3) == 0, "data with fds");
    TEST_ASSERT(received.count == 2 && received.flags == 0, "two descriptors");
    TEST_ASSERT(received.controllen == CMSG_SPACE(sizeof(int) * 2), "control length");
    char buffer[16] = {0};
    TEST_ASSERT(read(received.fds[0], buffer, 5) == 5 && memcmp(buffer, "piped", 5) == 0,
                "read the passed pipe");
    // The passed file shares its open file description, and so its offset.
    TEST_ASSERT(read(received.fds[1], buffer, 2) == 2 && memcmp(buffer, "34", 2) == 0,
                "read the passed file at its offset");
    close(received.fds[1]);

    TEST_ASSERT(send_fds(channel[0], "sock", &peer[1], 1) == 4, "send socket");
    close(peer[1]);
    ssize_t n = recv(peer[0], buffer, sizeof(buffer), 0);
    TEST_ASSERT(n == 5 && memcmp(buffer, "hello", 5) == 0, "receive over the passed socket");
    int status;
    TEST_ASSERT(waitpid(child, &status, 0) == child, "waitpid");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child succeeded");
    TEST_ASSERT(pipe_ends(received.fds[0]), "the passed pipe ends");
    close(received.fds[0]);
    close(peer[0]);
    close(channel[0]);
}

static void test_short_control_truncates(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    int first[2], second[2];
    TEST_ASSERT(pipe(first) == 0 && pipe(second) == 0, "pipes");
    int sent[2] = {first[1], second[1]};
    TEST_ASSERT(send_fds(pair[0], "x", sent, 2) == 1, "send two descriptors");
    close(first[1]);
    close(second[1]);
    // Room for one descriptor installs the first and discards, so releases, the other.
    struct received received = recv_fds(pair[1], CMSG_LEN(sizeof(int)), 0);
    TEST_ASSERT(received.count == 1 && (received.flags & MSG_CTRUNC), "truncated to one");
    TEST_ASSERT(received.controllen == CMSG_LEN(sizeof(int)), "control length");
    TEST_ASSERT(pipe_open(first[0]), "the first is installed");
    TEST_ASSERT(pipe_ends(second[0]), "the second is released");
    close(received.fds[0]);
    TEST_ASSERT(pipe_ends(first[0]), "the installed one was the first");
    close(first[0]);
    close(second[0]);
    // No room installs none.
    TEST_ASSERT(send_fds(pair[0], "y", &pair[0], 1) == 1, "send one descriptor");
    received = recv_fds(pair[1], CMSG_LEN(0), 0);
    TEST_ASSERT(received.count == 0 && (received.flags & MSG_CTRUNC), "truncated to none");
    TEST_ASSERT(received.controllen == 0, "no control bytes");
    close(pair[0]);
    close(pair[1]);
}

static void test_plain_receives_discard_descriptors(void) {
    int pair[2];
    socket_pair(SOCK_STREAM, pair);
    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe");
    TEST_ASSERT(send_fds(pair[0], "x", &pipe_fds[1], 1) == 1, "send write end");
    close(pipe_fds[1]);
    char buffer[4];
    TEST_ASSERT(recv(pair[1], buffer, sizeof(buffer), 0) == 1, "recv");
    // The discarded write end was the last, so the pipe ends.
    TEST_ASSERT(pipe_ends(pipe_fds[0]), "pipe ends");
    close(pipe_fds[0]);
    close(pair[0]);
    close(pair[1]);
}

static void test_close_on_exec(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    TEST_ASSERT(send_fds(pair[0], "x", &pair[0], 1) == 1, "send");
    struct received received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), MSG_CMSG_CLOEXEC);
    TEST_ASSERT(received.count == 1, "received with MSG_CMSG_CLOEXEC");
    TEST_ASSERT(fcntl(received.fds[0], F_GETFD) == FD_CLOEXEC, "close-on-exec set");
    close(received.fds[0]);
    TEST_ASSERT(send_fds(pair[0], "x", &pair[0], 1) == 1, "send");
    received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), 0);
    TEST_ASSERT(received.count == 1, "received");
    TEST_ASSERT(fcntl(received.fds[0], F_GETFD) == 0, "close-on-exec clear");
    close(received.fds[0]);
    close(pair[0]);
    close(pair[1]);
}

static void test_stream_receives_stop_after_passed_descriptors(void) {
    int pair[2];
    socket_pair(SOCK_STREAM, pair);
    TEST_ASSERT(send_fds(pair[0], "ab", NULL, 0) == 2, "send plain");
    TEST_ASSERT(send_fds(pair[0], "cd", &pair[0], 1) == 2, "send with descriptor");
    TEST_ASSERT(send_fds(pair[0], "ef", NULL, 0) == 2, "send plain");
    // Peeking passes the descriptors too, and leaves them queued.
    struct received received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), MSG_PEEK);
    TEST_ASSERT(received.length == 4 && memcmp(received.data, "abcd", 4) == 0, "peek");
    TEST_ASSERT(received.count == 1, "peek passes the descriptor");
    close(received.fds[0]);
    received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), 0);
    TEST_ASSERT(received.length == 4 && memcmp(received.data, "abcd", 4) == 0,
                "stop after the passed bytes");
    TEST_ASSERT(received.count == 1, "descriptor with its bytes");
    close(received.fds[0]);
    received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), 0);
    TEST_ASSERT(received.length == 2 && received.count == 0 && received.controllen == 0,
                "rest without descriptors");

    // A byte before those that carry descriptors comes without them, and the first of those with.
    TEST_ASSERT(send_fds(pair[0], "ab", NULL, 0) == 2, "send plain");
    TEST_ASSERT(send_fds(pair[0], "cd", &pair[0], 1) == 2, "send with descriptor");
    const char *expected = "abc";
    for (int i = 0; i < 3; i++) {
        received = recv_some_fds(pair[1], 1, CMSG_SPACE(sizeof(int)), 0);
        TEST_ASSERT(received.length == 1 && received.data[0] == expected[i], "one byte");
        TEST_ASSERT(received.count == (i == 2), "descriptors with the first byte to carry them");
    }
    close(received.fds[0]);
    received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), 0);
    TEST_ASSERT(received.length == 1 && received.data[0] == 'd' && received.count == 0,
                "the rest of the chunk without descriptors");
    close(pair[0]);
    close(pair[1]);
}

static void test_zero_byte_sends(void) {
    int pair[2];
    socket_pair(SOCK_STREAM, pair);
    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe");
    // A stream queues nothing for no bytes, so releases the descriptor.
    TEST_ASSERT(send_fds(pair[0], "", &pipe_fds[1], 1) == 0, "send no bytes on a stream");
    close(pipe_fds[1]);
    char buffer[4];
    errno = 0;
    TEST_ASSERT(recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) == -1 && errno == EAGAIN,
                "nothing queued");
    TEST_ASSERT(pipe_ends(pipe_fds[0]), "the descriptor is released");
    close(pipe_fds[0]);
    close(pair[0]);
    close(pair[1]);

    // An empty datagram carries its descriptor.
    socket_pair(SOCK_DGRAM, pair);
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe");
    TEST_ASSERT(send_fds(pair[0], "", &pipe_fds[1], 1) == 0, "send an empty datagram");
    close(pipe_fds[1]);
    struct received received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), MSG_DONTWAIT);
    TEST_ASSERT(received.length == 0 && received.count == 1, "empty datagram with descriptor");
    TEST_ASSERT(pipe_open(pipe_fds[0]), "the descriptor is installed");
    close(received.fds[0]);
    TEST_ASSERT(pipe_ends(pipe_fds[0]), "the installed descriptor was the write end");
    close(pipe_fds[0]);
    close(pair[0]);
    close(pair[1]);
}

static void test_unwritable_control(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    int pipe_fds[2];
    TEST_ASSERT(pipe(pipe_fds) == 0, "pipe");
    TEST_ASSERT(send_fds(pair[0], "x", &pipe_fds[1], 1) == 1, "send write end");
    close(pipe_fds[1]);
    void *page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(page != MAP_FAILED, "mmap");
    char buffer[4];
    struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = page,
                         .msg_controllen = CMSG_SPACE(sizeof(int))};
    // Like Linux, the data still arrives, and the descriptor is discarded.
    TEST_ASSERT(recvmsg(pair[1], &msg, 0) == 1 && buffer[0] == 'x', "recvmsg");
    TEST_ASSERT(msg.msg_flags == MSG_CTRUNC && msg.msg_controllen == 0, "truncated");
    TEST_ASSERT(pipe_ends(pipe_fds[0]), "the descriptor is released");
    munmap(page, 4096);
    close(pipe_fds[0]);
    close(pair[0]);
    close(pair[1]);
}

static void test_descriptor_limit_truncates(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    int first[2], second[2];
    TEST_ASSERT(pipe(first) == 0 && pipe(second) == 0, "pipes");
    int sent[2] = {first[1], second[1]};
    TEST_ASSERT(send_fds(pair[0], "x", sent, 2) == 1, "send two descriptors");
    close(first[1]);
    close(second[1]);
    // Leave room under the limit for exactly one descriptor: the lowest free one.
    int lowest = dup(pair[0]);
    TEST_ASSERT(lowest >= 0, "dup");
    close(lowest);
    struct rlimit old;
    TEST_ASSERT(getrlimit(RLIMIT_NOFILE, &old) == 0, "getrlimit");
    struct rlimit limit = {.rlim_cur = (rlim_t)lowest + 1, .rlim_max = old.rlim_max};
    TEST_ASSERT(setrlimit(RLIMIT_NOFILE, &limit) == 0, "setrlimit");
    struct received received = recv_fds(pair[1], CMSG_SPACE(sizeof(int) * 2), 0);
    TEST_ASSERT(setrlimit(RLIMIT_NOFILE, &old) == 0, "restore the limit");
    TEST_ASSERT(received.length == 1 && received.count == 1 && received.fds[0] == lowest,
                "one installed");
    TEST_ASSERT(received.flags & MSG_CTRUNC, "truncated");
    TEST_ASSERT(pipe_open(first[0]), "the first is installed");
    TEST_ASSERT(pipe_ends(second[0]), "the second is released");
    close(received.fds[0]);
    close(first[0]);
    close(second[0]);
    close(pair[0]);
    close(pair[1]);
}

static unsigned char pattern(size_t i) { return (unsigned char)(i % 251); }

static void test_large_stream_send(void) {
    enum { SIZE = 3 * 212992 };
    int pair[2];
    socket_pair(SOCK_STREAM, pair);
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork");
    if (child == 0) {
        close(pair[1]);
        unsigned char *data = malloc(SIZE);
        TEST_ASSERT(data != NULL, "malloc");
        for (size_t i = 0; i < SIZE; i++) {
            data[i] = pattern(i);
        }
        union {
            char buffer[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } control;
        memset(&control, 0, sizeof(control));
        struct iovec iov = {.iov_base = data, .iov_len = SIZE};
        struct msghdr msg = {.msg_iov = &iov,
                             .msg_iovlen = 1,
                             .msg_control = control.buffer,
                             .msg_controllen = sizeof(control.buffer)};
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &pair[0], sizeof(int));
        TEST_ASSERT(sendmsg(pair[0], &msg, 0) == SIZE, "send it all at once");
        _exit(0);
    }
    close(pair[0]);
    static unsigned char buffer[65536];
    size_t total = 0;
    int count = 0;
    while (total < SIZE) {
        union {
            char buffer[CMSG_SPACE(sizeof(int) * MAX_FDS)];
            struct cmsghdr align;
        } control;
        struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};
        struct msghdr msg = {.msg_iov = &iov,
                             .msg_iovlen = 1,
                             .msg_control = control.buffer,
                             .msg_controllen = sizeof(control.buffer)};
        ssize_t n = recvmsg(pair[1], &msg, 0);
        TEST_ASSERT(n > 0, "recvmsg");
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            int fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (int i = 0; i < fds; i++) {
                close(((int *)CMSG_DATA(cmsg))[i]);
            }
            count += fds;
        }
        for (ssize_t i = 0; i < n; i++) {
            TEST_ASSERT(buffer[i] == pattern(total + i), "bytes in order");
        }
        total += n;
    }
    TEST_ASSERT(count == 1, "one descriptor in all");
    TEST_ASSERT(reap(child, 1) == 0, "child succeeded");
    close(pair[1]);
}

static void test_sockets_sent_over_themselves(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    TEST_ASSERT(send_fds(pair[0], "x", &pair[1], 1) == 1, "send receiver to itself");
    close(pair[1]);
    // Only the queued message reaches the receiver now, which the garbage collector reclaims.
    close(pair[0]);
}

static void test_invalid_control_messages(void) {
    int pair[2];
    socket_pair(SOCK_DGRAM, pair);
    int bad = 1000;
    errno = 0;
    TEST_ASSERT(send_fds(pair[0], "x", &bad, 1) == -1 && errno == EBADF, "EBADF");

    // More than `SCM_MAX_FD` (253) descriptors.
    enum { COUNT = 254 };
    union {
        char buffer[CMSG_SPACE(sizeof(int) * COUNT)];
        struct cmsghdr align;
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = {.iov_base = "x", .iov_len = 1};
    struct msghdr msg = {.msg_iov = &iov,
                         .msg_iovlen = 1,
                         .msg_control = control.buffer,
                         .msg_controllen = sizeof(control.buffer)};
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * COUNT);
    int *fds = (int *)CMSG_DATA(cmsg);
    for (int i = 0; i < COUNT; i++) {
        fds[i] = pair[0];
    }
    errno = 0;
    TEST_ASSERT(sendmsg(pair[0], &msg, 0) == -1 && errno == EINVAL, "too many descriptors");

    // A message longer than the control bytes.
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    msg.msg_controllen = CMSG_LEN(0);
    errno = 0;
    TEST_ASSERT(sendmsg(pair[0], &msg, 0) == -1 && errno == EINVAL, "overlong message");

    // Messages of other levels are ignored.
    cmsg->cmsg_level = IPPROTO_IP;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    TEST_ASSERT(sendmsg(pair[0], &msg, 0) == 1, "other levels are ignored");
    struct received received = recv_fds(pair[1], CMSG_SPACE(sizeof(int)), 0);
    TEST_ASSERT(received.count == 0 && received.flags == 0, "nothing passed");
    close(pair[0]);
    close(pair[1]);
}

int main(void) {
    printf("Testing SCM_RIGHTS\n");
    test_pass_between_processes();
    test_short_control_truncates();
    test_plain_receives_discard_descriptors();
    test_close_on_exec();
    test_stream_receives_stop_after_passed_descriptors();
    test_zero_byte_sends();
    test_unwritable_control();
    test_descriptor_limit_truncates();
    test_large_stream_send();
    test_sockets_sent_over_themselves();
    test_invalid_control_messages();
    printf("All SCM_RIGHTS tests passed.\n");
    return 0;
}
