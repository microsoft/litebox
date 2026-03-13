// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// WinSock TCP Socket Tests
//
// Tests a full TCP client-server exchange over the loopback interface in a
// single thread by using a non-blocking client socket together with select(2):
//
//   1. Create a TCP server socket, bind to 127.0.0.1:0, listen.
//   2. Query the assigned port with getsockname.
//   3. Create a non-blocking TCP client socket.
//   4. connect() – expected to return WSAEWOULDBLOCK immediately.
//   5. select() on the server's listen socket for readability
//      (OS finishes the three-way handshake on loopback).
//   6. accept() to obtain the server-side connected socket.
//   7. select() on the client socket for writability (connect completed).
//   8. Restore the client socket to blocking mode.
//   9. send() a message from the client; recv() it on the server side.
//  10. send() a reply from the server side; recv() it on the client.
//  11. shutdown() and closesocket() every socket; WSACleanup().

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

static int g_failures = 0;

static void report(bool ok, const char *desc)
{
    if (ok) {
        printf("  [PASS] %s\n", desc);
    } else {
        printf("  [FAIL] %s  (WSAError=%d)\n", desc, WSAGetLastError());
        g_failures++;
    }
}

// Helper: run select() on a single socket and return true if the expected
// condition (read or write) is set within `timeout_ms` milliseconds.
static bool wait_socket(SOCKET s, bool want_read, int timeout_ms)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);

    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int n = select(0 /* ignored on Windows */,
                   want_read  ? &fds : nullptr,
                   want_read  ? nullptr : &fds,
                   nullptr, &tv);
    return n > 0 && FD_ISSET(s, &fds);
}

int main(void)
{
    printf("=== WinSock TCP Socket Tests ===\n\n");

    // ── WSAStartup ────────────────────────────────────────────────────────
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "WSAStartup failed (%d), aborting.\n",
                    WSAGetLastError());
            return 1;
        }
        printf("WSAStartup succeeded (version %d.%d)\n\n",
               LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
    }

    // ── Test 1: Create server socket ─────────────────────────────────────
    printf("Test 1: Create and configure TCP server socket\n");
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    report(srv != INVALID_SOCKET, "socket(AF_INET, SOCK_STREAM) succeeds");
    if (srv == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    {
        int opt = 1;
        report(setsockopt(srv, SOL_SOCKET, SO_REUSEADDR,
                          reinterpret_cast<const char *>(&opt), sizeof(opt)) == 0,
               "setsockopt(SO_REUSEADDR) on server socket succeeds");
    }

    // ── Test 2: Bind server to 127.0.0.1:0 ───────────────────────────────
    printf("\nTest 2: Bind server socket to 127.0.0.1:0\n");
    sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port        = 0;

    report(bind(srv, reinterpret_cast<sockaddr *>(&srv_addr), sizeof(srv_addr)) == 0,
           "bind(127.0.0.1:0) succeeds");

    sockaddr_in bound;
    memset(&bound, 0, sizeof(bound));
    int bound_len = static_cast<int>(sizeof(bound));
    report(getsockname(srv, reinterpret_cast<sockaddr *>(&bound), &bound_len) == 0,
           "getsockname after bind succeeds");

    u_short port = ntohs(bound.sin_port);
    report(port != 0, "server is assigned a non-zero port by the OS");
    printf("  [INFO] server port = %u\n", static_cast<unsigned>(port));

    // ── Test 3: Listen ────────────────────────────────────────────────────
    printf("\nTest 3: listen()\n");
    report(listen(srv, 1) == 0, "listen(backlog=1) succeeds");

    // ── Test 4: Non-blocking connect ──────────────────────────────────────
    printf("\nTest 4: Non-blocking client connect\n");
    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    report(cli != INVALID_SOCKET, "client socket() succeeds");

    if (cli == INVALID_SOCKET) {
        closesocket(srv);
        WSACleanup();
        return 1;
    }

    // Set client to non-blocking so connect() returns immediately.
    u_long nb = 1;
    report(ioctlsocket(cli, FIONBIO, &nb) == 0,
           "ioctlsocket(FIONBIO, 1) sets client non-blocking");

    sockaddr_in cli_target;
    memset(&cli_target, 0, sizeof(cli_target));
    cli_target.sin_family      = AF_INET;
    cli_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cli_target.sin_port        = htons(port);

    int conn_rc = connect(cli,
                          reinterpret_cast<sockaddr *>(&cli_target),
                          sizeof(cli_target));
    bool connect_in_progress =
        (conn_rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
        || conn_rc == 0; // may succeed immediately on loopback
    report(connect_in_progress,
           "connect() returns 0 or WSAEWOULDBLOCK on non-blocking socket");

    // ── Test 5: select – server readable (incoming connection) ────────────
    printf("\nTest 5: select() – server socket becomes readable\n");
    bool srv_readable = wait_socket(srv, /*want_read=*/true, /*timeout_ms=*/2000);
    report(srv_readable, "server socket is readable (incoming connection) within 2 s");

    // ── Test 6: accept ────────────────────────────────────────────────────
    printf("\nTest 6: accept()\n");
    sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    int peer_len = static_cast<int>(sizeof(peer_addr));
    SOCKET conn = accept(srv,
                         reinterpret_cast<sockaddr *>(&peer_addr),
                         &peer_len);
    report(conn != INVALID_SOCKET, "accept() returns a valid socket");

    if (conn == INVALID_SOCKET) {
        closesocket(cli);
        closesocket(srv);
        WSACleanup();
        return 1;
    }

    // ── Test 7: select – client writable (connect completed) ─────────────
    printf("\nTest 7: select() – client socket becomes writable\n");
    bool cli_writable = wait_socket(cli, /*want_read=*/false, /*timeout_ms=*/2000);
    report(cli_writable,
           "client socket is writable (connect completed) within 2 s");

    // Restore client to blocking mode for simpler send/recv below.
    u_long blk = 0;
    report(ioctlsocket(cli, FIONBIO, &blk) == 0,
           "ioctlsocket(FIONBIO, 0) restores client to blocking mode");

    // ── Test 8: getpeername on accepted socket ────────────────────────────
    printf("\nTest 8: getpeername on accepted socket\n");
    {
        sockaddr_in remote;
        memset(&remote, 0, sizeof(remote));
        int rlen = static_cast<int>(sizeof(remote));
        report(getpeername(conn, reinterpret_cast<sockaddr *>(&remote), &rlen) == 0,
               "getpeername on accepted socket succeeds");
        report(remote.sin_family == AF_INET,
               "peer address family is AF_INET");
    }

    // ── Test 9: send / recv data exchange ────────────────────────────────
    printf("\nTest 9: send / recv data exchange\n");
    {
        const char msg[]   = "Hello from WinSock TCP client!";
        const char reply[] = "Reply from WinSock TCP server!";
        char buf[128];

        // Client → Server
        int sent = send(cli, msg, static_cast<int>(strlen(msg)), 0);
        report(sent == static_cast<int>(strlen(msg)),
               "client send() transmits all bytes");

        memset(buf, 0, sizeof(buf));
        int recvd = recv(conn, buf, sizeof(buf) - 1, 0);
        report(recvd == static_cast<int>(strlen(msg)),
               "server recv() receives all bytes");
        report(memcmp(buf, msg, strlen(msg)) == 0,
               "server received data matches sent message");

        // Server → Client
        sent = send(conn, reply, static_cast<int>(strlen(reply)), 0);
        report(sent == static_cast<int>(strlen(reply)),
               "server send() transmits all reply bytes");

        memset(buf, 0, sizeof(buf));
        recvd = recv(cli, buf, sizeof(buf) - 1, 0);
        report(recvd == static_cast<int>(strlen(reply)),
               "client recv() receives all reply bytes");
        report(memcmp(buf, reply, strlen(reply)) == 0,
               "client received data matches reply message");
    }

    // ── Test 10: shutdown ─────────────────────────────────────────────────
    printf("\nTest 10: shutdown()\n");
    report(shutdown(conn, SD_BOTH) == 0, "shutdown(conn, SD_BOTH) succeeds");
    report(shutdown(cli,  SD_BOTH) == 0, "shutdown(cli,  SD_BOTH) succeeds");

    // ── Cleanup ───────────────────────────────────────────────────────────
    closesocket(conn);
    closesocket(cli);
    closesocket(srv);
    WSACleanup();

    // ── Summary ───────────────────────────────────────────────────────────
    printf("\n=== WinSock TCP Socket Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
