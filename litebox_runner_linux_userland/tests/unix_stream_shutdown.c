// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "helpers.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/un.h>

static void make_stream_pair(int sv[2]) {
    make_socket_pair(SOCK_STREAM, sv);
}

static int make_listen_socket(struct sockaddr_un *sa, const char *name) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(listen)");
    }
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    snprintf(sa->sun_path, sizeof(sa->sun_path), "/tmp/lb_shut_%s_%d", name, getpid());
    unlink(sa->sun_path);
    if (bind(fd, (struct sockaddr *)sa, sizeof(*sa)) != 0) {
        die("bind(listen)");
    }
    if (listen(fd, 4) != 0) {
        die("listen()");
    }
    return fd;
}

static void test_shutdown_read_drains_then_returns_eof(void) {
    int sv[2];
    const char *queued = "before-shut-rd";

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("peer send before SHUT_RD");
    }

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD)");

    expect_recv_string(sv[0], queued, "recv queued bytes after SHUT_RD");
    expect_recv_eof(sv[0], "blocking recv after queue drained");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_read_empty_returns_eof(void) {
    int sv[2];

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RD, "shutdown(SHUT_RD) on empty queue");

    expect_recv_eof(sv[0], "blocking recv on empty SHUT_RD queue");
    expect_send_errno(sv[1], EPIPE, "peer send after empty SHUT_RD");

    close_pair(sv);
}

static void test_shutdown_write_keeps_receive_side_open(void) {
    int sv[2];
    const char *inbound = "still-readable-after-write-shutdown";

    make_stream_pair(sv);

    expect_sys_shutdown(sv[0], SHUT_WR, "shutdown(SHUT_WR)");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_WR");
    if (send(sv[1], inbound, strlen(inbound), MSG_NOSIGNAL) < 0) {
        die("peer send after SHUT_WR");
    }
    expect_recv_string(sv[0], inbound, "local recv after SHUT_WR");

    close_pair(sv);
}

static void test_shutdown_both_combines_read_and_write_rules(void) {
    int sv[2];

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    expect_sys_shutdown(sv[0], SHUT_RDWR, "shutdown(SHUT_RDWR)");

    expect_send_errno(sv[0], EPIPE, "local send after SHUT_RDWR");
    expect_recv_eof(sv[0], "blocking recv after SHUT_RDWR");
    expect_send_errno(sv[1], EPIPE, "peer send after SHUT_RDWR");

    close_pair(sv);
}

// shutdown() on an unconnected (Init) AF_UNIX stream socket succeeds silently on Linux;
// unlike inet sockets, unix_shutdown does not enforce ENOTCONN. Lock this in so the silent
// success path in UnixStream::shutdown stays honest.
static void test_shutdown_unconnected_succeeds(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(AF_UNIX, SOCK_STREAM)");
    }
    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(SHUT_RDWR) on unconnected unix stream");
    close(fd);
}

// Linux records pre-connect shutdown flags on the unix_sock structure and applies them once
// the socket transitions to Connected: a `shutdown(SHUT_WR)` on a freshly-created Init socket
// must cause the post-connect `send()` to fail with EPIPE.
static void test_init_shutdown_persists_to_connected(void) {
    struct sockaddr_un sa;
    int srv = make_listen_socket(&sa, "init");

    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (c < 0) {
        die("socket(client)");
    }
    expect_sys_shutdown(c, SHUT_WR, "pre-connect shutdown(SHUT_WR)");
    if (connect(c, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("connect after pre-connect shutdown");
    }
    expect_send_errno(c, EPIPE, "post-connect send must observe pre-connect SHUT_WR");

    close(c);
    close(srv);
    unlink(sa.sun_path);
}

// A fresh Init Unix-stream socket polls as OUT|HUP (HUP because it's not connected).
// After shutdown(SHUT_RD), even pre-connect, Linux additionally reports POLLIN because
// a recv would return EOF immediately. SHUT_WR alone leaves the poll output unchanged.
static void test_init_shutdown_read_makes_poll_in_ready(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket(AF_UNIX, SOCK_STREAM)");
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };
    int r = poll(&pfd, 1, 0);
    if (r != 1 || (pfd.revents & POLLIN)) {
        fprintf(stderr,
                "FAIL: fresh Init poll expected !POLLIN, got r=%d revents=0x%x\n",
                r, pfd.revents);
        exit(1);
    }

    expect_sys_shutdown(fd, SHUT_RD, "shutdown(SHUT_RD) on Init");
    // POLLIN must be level-triggered: every subsequent poll on the same socket should keep
    // reporting it until the state changes. Probe three iterations to lock that in.
    for (int i = 0; i < 3; i++) {
        pfd.revents = 0;
        r = poll(&pfd, 1, 0);
        if (r != 1 || !(pfd.revents & POLLIN) || !(pfd.revents & POLLHUP)) {
            fprintf(stderr,
                    "FAIL: Init+SHUT_RD poll #%d expected POLLIN|POLLHUP, got r=%d revents=0x%x\n",
                    i, r, pfd.revents);
            exit(1);
        }
    }
    close(fd);
}

// Linux's `shutdown(SHUT_RDWR)` on a listening socket is observable two ways: a blocking
// accept returns EINVAL (not tested here to avoid pthreads), and poll reports both POLLIN
// and POLLHUP.
static void test_listen_shutdown_signals_in_and_hup(void) {
    struct sockaddr_un sa;
    int fd = make_listen_socket(&sa, "listen");
    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(listen, SHUT_RDWR)");

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, 100);
    if (r != 1) {
        fprintf(stderr, "FAIL: poll after listen-shutdown expected 1, got %d (errno=%d)\n",
                r, errno);
        exit(1);
    }
    if (!(pfd.revents & POLLIN) || !(pfd.revents & POLLHUP)) {
        fprintf(stderr,
                "FAIL: poll after listen-shutdown expected POLLIN|POLLHUP, got revents=0x%x\n",
                pfd.revents);
        exit(1);
    }

    close(fd);
    unlink(sa.sun_path);
}

// Non-blocking accept on a shut-down listen socket returns EAGAIN on Linux (not EINVAL;
// the empty-queue fast path runs before the shutdown check kicks in).
static void test_listen_shutdown_nonblocking_accept_returns_eagain(void) {
    struct sockaddr_un sa;
    int fd = make_listen_socket(&sa, "nbacc");
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) {
        die("fcntl O_NONBLOCK");
    }
    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(listen, SHUT_RDWR)");

    errno = 0;
    int a = accept(fd, NULL, NULL);
    if (a != -1) {
        fprintf(stderr, "FAIL: nonblocking accept on shut-down listen expected -1, got %d\n", a);
        exit(1);
    }
    if (errno != EAGAIN) {
        fail_errno("nonblocking accept on shut-down listen", EAGAIN);
    }

    close(fd);
    unlink(sa.sun_path);
}

// Blocking accept on a shut-down listen socket returns EINVAL. We start a thread that
// enters blocking accept, then shut the listen socket down from the main thread and
// observe the thread's return code.
struct blocking_accept_ctx {
    int fd;
    int ret;
    int err;
};

static void *blocking_accept_thread(void *arg) {
    struct blocking_accept_ctx *ctx = arg;
    errno = 0;
    ctx->ret = accept(ctx->fd, NULL, NULL);
    ctx->err = errno;
    return NULL;
}

static void test_listen_shutdown_blocking_accept_returns_einval(void) {
    struct sockaddr_un sa;
    int fd = make_listen_socket(&sa, "blkacc");

    struct blocking_accept_ctx ctx = { .fd = fd, .ret = 0, .err = 0 };
    pthread_t t;
    if (pthread_create(&t, NULL, blocking_accept_thread, &ctx) != 0) {
        die("pthread_create");
    }
    // Give the thread a moment to enter blocking accept().
    usleep(100 * 1000);

    expect_sys_shutdown(fd, SHUT_RDWR, "shutdown(listen, SHUT_RDWR)");

    pthread_join(t, NULL);
    if (ctx.ret != -1) {
        fprintf(stderr, "FAIL: blocking accept on shut-down listen expected -1, got %d\n",
                ctx.ret);
        exit(1);
    }
    if (ctx.err != EINVAL) {
        fprintf(stderr,
                "FAIL: blocking accept on shut-down listen expected errno=%d (EINVAL), got %d (%s)\n",
                EINVAL, ctx.err, strerror(ctx.err));
        exit(1);
    }

    close(fd);
    unlink(sa.sun_path);
}

static void test_listen_shutdown_write_keeps_accepting(void) {
    struct sockaddr_un sa;
    int fd = make_listen_socket(&sa, "listen_wr");

    expect_sys_shutdown(fd, SHUT_WR, "shutdown(listen, SHUT_WR)");

    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client < 0) {
        die("socket(client)");
    }
    if (connect(client, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("connect after listen SHUT_WR");
    }
    int accepted = accept(fd, NULL, NULL);
    if (accepted < 0) {
        die("accept after listen SHUT_WR");
    }

    close(accepted);
    close(client);
    close(fd);
    unlink(sa.sun_path);
}

static void test_listen_shutdown_read_preserves_queued_connections(void) {
    struct sockaddr_un sa;
    int fd = make_listen_socket(&sa, "listen_rd");
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) {
        die("fcntl O_NONBLOCK");
    }

    int queued_client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (queued_client < 0) {
        die("socket(queued client)");
    }
    if (connect(queued_client, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        die("queued connect before listen SHUT_RD");
    }

    expect_sys_shutdown(fd, SHUT_RD, "shutdown(listen, SHUT_RD)");

    int refused_client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (refused_client < 0) {
        die("socket(refused client)");
    }
    errno = 0;
    if (connect(refused_client, (struct sockaddr *)&sa, sizeof(sa)) != -1) {
        fprintf(stderr, "FAIL: connect after listen SHUT_RD expected failure\n");
        exit(1);
    }
    if (errno != ECONNREFUSED) {
        fail_errno("connect after listen SHUT_RD", ECONNREFUSED);
    }

    int accepted = accept(fd, NULL, NULL);
    if (accepted < 0) {
        die("accept queued connection after listen SHUT_RD");
    }

    errno = 0;
    int drained = accept(fd, NULL, NULL);
    if (drained != -1) {
        fprintf(stderr, "FAIL: drained accept after listen SHUT_RD expected -1, got %d\n", drained);
        exit(1);
    }
    if (errno != EAGAIN) {
        fail_errno("drained accept after listen SHUT_RD", EAGAIN);
    }

    close(accepted);
    close(refused_client);
    close(queued_client);
    close(fd);
    unlink(sa.sun_path);
}

// When the *peer* calls shutdown(SHUT_WR), the local recv side must drain any queued bytes
// first, then observe EOF on a subsequent recv: same behavior as a local SHUT_RD, just
// triggered from the other side. Locks in the channel-layer "peer shutdown" drain path.
static void test_peer_shutdown_write_drains_then_returns_eof(void) {
    int sv[2];
    const char *queued = "bytes-before-peer-shut-wr";

    make_stream_pair(sv);
    set_recv_timeout(sv[0]);

    if (send(sv[1], queued, strlen(queued), MSG_NOSIGNAL) < 0) {
        die("peer send before peer SHUT_WR");
    }
    expect_sys_shutdown(sv[1], SHUT_WR, "peer shutdown(SHUT_WR)");

    expect_recv_string(sv[0], queued, "recv queued bytes after peer SHUT_WR");
    expect_recv_eof(sv[0], "blocking recv after peer SHUT_WR queue drained");

    close_pair(sv);
}

static void test_peer_shutdown_write_reports_read_ready(void) {
    int sv[2];

    make_stream_pair(sv);

    expect_sys_shutdown(sv[1], SHUT_WR, "peer shutdown(SHUT_WR)");

    struct pollfd pfd = { .fd = sv[0], .events = POLLIN | POLLRDHUP };
    int r = poll(&pfd, 1, 0);
    if (r != 1) {
        fprintf(stderr, "FAIL: poll after peer SHUT_WR expected 1, got %d (errno=%d)\n",
                r, errno);
        exit(1);
    }
    if (!(pfd.revents & POLLIN) || !(pfd.revents & POLLRDHUP)) {
        fprintf(stderr,
                "FAIL: poll after peer SHUT_WR expected POLLIN|POLLRDHUP, got revents=0x%x\n",
                pfd.revents);
        exit(1);
    }
    expect_recv_eof(sv[0], "recv after peer SHUT_WR readiness");

    close_pair(sv);
}

static void test_shutdown_invalid_how_returns_einval(void) {
    int sv[2];

    make_stream_pair(sv);

    expect_sys_shutdown_errno(sv[0], 99, EINVAL, "shutdown(invalid how)");

    close_pair(sv);
}

int main(void) {
    printf("== unix stream shutdown syscall tests ==\n");

    test_shutdown_read_drains_then_returns_eof();
    test_shutdown_read_empty_returns_eof();
    test_shutdown_write_keeps_receive_side_open();
    test_shutdown_both_combines_read_and_write_rules();
    test_shutdown_unconnected_succeeds();
    test_init_shutdown_persists_to_connected();
    test_init_shutdown_read_makes_poll_in_ready();
    test_listen_shutdown_signals_in_and_hup();
    test_listen_shutdown_nonblocking_accept_returns_eagain();
    test_listen_shutdown_blocking_accept_returns_einval();
    test_listen_shutdown_write_keeps_accepting();
    test_listen_shutdown_read_preserves_queued_connections();
    test_peer_shutdown_write_drains_then_returns_eof();
    test_peer_shutdown_write_reports_read_ready();
    test_shutdown_invalid_how_returns_einval();

    printf("All unix stream shutdown tests passed.\n");
    return 0;
}
