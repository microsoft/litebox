// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <fcntl.h>
#include <sys/un.h>

static void make_dgram_pair(int sv[2]) {
    make_socket_pair(SOCK_DGRAM, sv);
}

static void make_addr(struct sockaddr_un *addr, const char *name) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path, sizeof(addr->sun_path), "/tmp/lb_dgram_%s_%d", name, getpid());
    unlink(addr->sun_path);
}

static int bind_dgram_addr(const struct sockaddr_un *addr, const char *op) {
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        die("socket(AF_UNIX, SOCK_DGRAM)");
    }
    if (bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) != 0) {
        die(op);
    }
    return fd;
}

// SHUT_RD on a connected datagram socket: queued datagrams remain readable; once the queue
// drains, a non-blocking recv returns EAGAIN (datagram quirk) while a blocking recv returns
// EOF, and the peer's send fails with EPIPE.
static void test_shutdown_read_keeps_queued_datagram(void) {
    int sv[2];
    const char *queued = "queued-before-read-shutdown";

    make_dgram_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("send queued datagram before SHUT_RD");
    }

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD)");

    // Local SHUT_RD on a dgram fd reports IN|OUT|RDHUP but NOT HUP (HUP only when
    // both sides are shut). Probed on host Linux.
    expect_poll_has(sv[0], POLLIN | POLLOUT | POLLRDHUP,
                    POLLIN | POLLOUT | POLLRDHUP, "poll(fd0) after SHUT_RD");
    expect_poll_lacks(sv[0], POLLIN | POLLOUT | POLLRDHUP, POLLHUP,
                      "poll(fd0) after SHUT_RD must not include HUP");

    expect_recv_string(sv[0], queued, "recv queued datagram after SHUT_RD");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RD");
    expect_recv_errno(sv[0], EAGAIN, "empty nonblocking recv after SHUT_RD");
    expect_recv_eof(sv[0], "empty blocking recv after SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_read_empty_blocking_recv_returns_eof(void) {
    int sv[2];

    make_dgram_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD) before recv");

    expect_recv_eof(sv[0], "blocking recv after empty SHUT_RD");
    expect_send_errno(sv[1], EPIPE, "peer send after empty SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_write_keeps_receive_side_open(void) {
    int sv[2];
    const char *inbound = "still-readable-after-write-shutdown";

    make_dgram_pair(sv);

    expect_sys_shutdown(sv[0], SHUT_WR, "shutdown(SHUT_WR)");

    // Local SHUT_WR alone on a dgram fd reports only OUT — no HUP, no RDHUP.
    // Probed on host Linux: HUP only fires when BOTH sides are shut.
    expect_poll_lacks(sv[0], POLLIN | POLLOUT | POLLRDHUP, POLLHUP | POLLRDHUP,
                      "poll(fd0) after SHUT_WR only must exclude HUP/RDHUP");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_WR");
    if (send(sv[1], inbound, strlen(inbound), MSG_NOSIGNAL) < 0) {
        die("peer send after SHUT_WR");
    }
    expect_recv_string(sv[0], inbound, "local recv after SHUT_WR");

    close_pair(sv);
}

static void test_shutdown_both_combines_read_and_write_rules(void) {
    int sv[2];
    const char *queued = "queued-before-rdwr-shutdown";

    make_dgram_pair(sv);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("send queued datagram before SHUT_RDWR");
    }

    expect_sys_shutdown(sv[0], SHUT_RDWR, "shutdown(SHUT_RDWR)");

    // SHUT_RDWR on a dgram fd reports IN|OUT|HUP|RDHUP (HUP appears now that both
    // sides are shut). Level-triggered: re-poll several times to confirm bits
    // stay set without consuming the queued datagram.
    for (int i = 0; i < 3; i++) {
        expect_poll_has(sv[0], POLLIN | POLLOUT | POLLRDHUP,
                        POLLIN | POLLOUT | POLLHUP | POLLRDHUP,
                        "poll(fd0) after SHUT_RDWR (level-triggered repeat)");
    }
    // Peer (fd1) of a dgram socket sees no change when fd0 shuts down both sides —
    // dgrams are connectionless. Probed on host Linux.
    expect_poll_lacks(sv[1], POLLIN | POLLOUT | POLLRDHUP, POLLHUP | POLLRDHUP,
                      "poll(fd1) peer of SHUT_RDWR dgram must exclude HUP/RDHUP");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_RDWR");
    expect_recv_string(sv[0], queued, "recv queued datagram after SHUT_RDWR");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RDWR");
    expect_recv_errno(sv[0], EAGAIN, "empty nonblocking recv after SHUT_RDWR");

    close_pair(sv);
}

// When the peer calls shutdown(SHUT_WR), Linux does NOT synthesize EOF on the local recv;
// unlike a local SHUT_RD, the socket is still connected and could in principle receive
// from another sender, so a blocking recv keeps blocking (we observe EAGAIN via RCVTIMEO).
// Queued datagrams must still drain first.
static void test_peer_shutdown_write_drains_then_blocks(void) {
    int sv[2];
    const char *queued = "dgram-before-peer-shut-wr";

    make_dgram_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("peer send before peer SHUT_WR");
    }
    expect_sys_shutdown(sv[1], SHUT_WR, "peer shutdown(SHUT_WR)");

    expect_recv_string(sv[0], queued, "recv queued datagram after peer SHUT_WR");
    expect_blocking_recv_eagain(sv[0], "blocking recv after peer SHUT_WR with empty queue");

    close_pair(sv);
}

static void test_pre_connect_shutdown_write_blocks_future_sends(void) {
    struct sockaddr_un server_addr;
    make_addr(&server_addr, "pre_wr_server");
    int server = bind_dgram_addr(&server_addr, "bind(server)");

    int sender = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sender < 0) {
        die("socket(sender)");
    }
    expect_sys_shutdown(sender, SHUT_WR, "pre-sendto shutdown(SHUT_WR)");

    errno = 0;
    ssize_t n = sendto(sender, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL,
                       (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (n != -1) {
        fprintf(stderr, "FAIL: sendto after pre-connect SHUT_WR expected failure, got %zd\n", n);
        exit(1);
    }
    if (errno != EPIPE) {
        fail_errno("sendto after pre-connect SHUT_WR", EPIPE);
    }

    if (connect(sender, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        die("connect after pre-connect SHUT_WR");
    }
    expect_send_errno(sender, EPIPE, "send after connect with pre-connect SHUT_WR");

    close(sender);
    close(server);
    unlink(server_addr.sun_path);
}

static void test_pre_bind_shutdown_read_blocks_future_recvs(void) {
    struct sockaddr_un receiver_addr;
    make_addr(&receiver_addr, "pre_rd_receiver");

    int receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (receiver < 0) {
        die("socket(receiver)");
    }
    set_recv_timeout(receiver);

    expect_sys_shutdown(receiver, SHUT_RD, "pre-bind shutdown(SHUT_RD)");
    if (bind(receiver, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) != 0) {
        die("bind(receiver) after pre-bind SHUT_RD");
    }

    expect_recv_eof(receiver, "blocking recv after bind with pre-bind SHUT_RD");

    close(receiver);
    unlink(receiver_addr.sun_path);
}

static void test_shutdown_invalid_how_returns_einval(void) {
    int sv[2];

    make_dgram_pair(sv);

    errno = 0;
    long ret = syscall(SYS_shutdown, sv[0], 99);
    if (ret != -1) {
        fprintf(stderr, "FAIL: shutdown(invalid how) expected failure, got %ld\n", ret);
        exit(1);
    }
    if (errno != EINVAL) {
        fail_errno("shutdown(invalid how)", EINVAL);
    }

    close_pair(sv);
}

// Linux validates the fd before `how`, so a bad fd combined with a bad `how`
// must surface EBADF / ENOTSOCK — not EINVAL. Probed on host Linux:
//   shutdown(-1, 99)              -> EBADF
//   shutdown(<closed_fd>, 99)     -> EBADF
//   shutdown(<regular_file>, 99)  -> ENOTSOCK
static void test_shutdown_fd_validated_before_how(void) {
    expect_sys_shutdown_errno(-1, 99, EBADF, "shutdown(-1, 99) must be EBADF");
    // Use a high-numbered fd that is unlikely to be opened by any test runner.
    expect_sys_shutdown_errno(99999, 99, EBADF, "shutdown(<closed_fd>, 99) must be EBADF");

    int regular = open("/dev/null", O_RDWR);
    if (regular < 0) {
        die("open(/dev/null)");
    }
    expect_sys_shutdown_errno(regular, 99, ENOTSOCK,
                              "shutdown(<regular_file>, 99) must be ENOTSOCK");
    close(regular);
}

int main(void) {
    printf("== unix datagram shutdown syscall tests ==\n");

    test_shutdown_read_keeps_queued_datagram();
    test_shutdown_read_empty_blocking_recv_returns_eof();
    test_shutdown_write_keeps_receive_side_open();
    test_shutdown_both_combines_read_and_write_rules();
    test_peer_shutdown_write_drains_then_blocks();
    test_pre_connect_shutdown_write_blocks_future_sends();
    test_pre_bind_shutdown_read_blocks_future_recvs();
    test_shutdown_invalid_how_returns_einval();
    test_shutdown_fd_validated_before_how();

    printf("All unix datagram shutdown tests passed.\n");
    return 0;
}
