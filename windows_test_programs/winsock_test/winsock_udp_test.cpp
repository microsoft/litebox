// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// WinSock UDP Socket Tests
//
// Tests UDP socket operations over the loopback interface in a single thread
// by using non-blocking sockets together with select(2):
//
//   1. Create a UDP server socket, bind to 127.0.0.1:0.
//   2. Query the assigned port with getsockname.
//   3. Create a UDP client socket (no bind needed).
//   4. sendto() a datagram from client to server address.
//   5. select() on the server socket for readability.
//   6. recvfrom() on the server – verify data and sender address.
//   7. sendto() a reply from server back to the client's address.
//   8. select() on the client socket for readability.
//   9. recvfrom() on the client – verify reply data.
//  10. closesocket() both sockets; WSACleanup().

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

// Helper: run select() on a single socket for readability within
// `timeout_ms` milliseconds.  Returns true when data is available.
static bool wait_readable(SOCKET s, int timeout_ms)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);

    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int n = select(0 /* ignored on Windows */, &fds, nullptr, nullptr, &tv);
    return n > 0 && FD_ISSET(s, &fds);
}

int main(void)
{
    printf("=== WinSock UDP Socket Tests ===\n\n");

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

    // ── Test 1: Create UDP server socket and bind ─────────────────────────
    printf("Test 1: Create UDP server socket\n");
    SOCKET srv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    report(srv != INVALID_SOCKET, "socket(AF_INET, SOCK_DGRAM) for server succeeds");
    if (srv == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    {
        int opt = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char *>(&opt), sizeof(opt));
    }

    // ── Test 2: Bind server to 127.0.0.1:0 ───────────────────────────────
    printf("\nTest 2: Bind server UDP socket to 127.0.0.1:0\n");
    sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port        = 0;

    report(bind(srv, reinterpret_cast<sockaddr *>(&srv_addr), sizeof(srv_addr)) == 0,
           "bind(127.0.0.1:0) on server socket succeeds");

    sockaddr_in bound;
    memset(&bound, 0, sizeof(bound));
    int bound_len = static_cast<int>(sizeof(bound));
    report(getsockname(srv, reinterpret_cast<sockaddr *>(&bound), &bound_len) == 0,
           "getsockname after bind succeeds");

    u_short port = ntohs(bound.sin_port);
    report(port != 0, "server is assigned a non-zero port by the OS");
    printf("  [INFO] server UDP port = %u\n", static_cast<unsigned>(port));

    // ── Test 3: Create UDP client socket ─────────────────────────────────
    printf("\nTest 3: Create UDP client socket\n");
    SOCKET cli = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    report(cli != INVALID_SOCKET, "socket(AF_INET, SOCK_DGRAM) for client succeeds");
    if (cli == INVALID_SOCKET) {
        closesocket(srv);
        WSACleanup();
        return 1;
    }

    // Bind client to an OS-assigned port so the server can reply to it.
    sockaddr_in cli_addr;
    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family      = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cli_addr.sin_port        = 0;
    report(bind(cli, reinterpret_cast<sockaddr *>(&cli_addr), sizeof(cli_addr)) == 0,
           "bind(127.0.0.1:0) on client socket succeeds");

    // ── Test 4: Client sendto server ──────────────────────────────────────
    printf("\nTest 4: Client sendto() server\n");
    const char msg[] = "Hello from WinSock UDP client!";

    sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port        = htons(port);

    int sent = sendto(cli, msg, static_cast<int>(strlen(msg)), 0,
                      reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    report(sent == static_cast<int>(strlen(msg)),
           "sendto() transmits all datagram bytes");

    // ── Test 5: Server select() for readability ───────────────────────────
    printf("\nTest 5: select() – server socket becomes readable\n");
    report(wait_readable(srv, /*timeout_ms=*/2000),
           "server socket is readable within 2 s after sendto");

    // ── Test 6: Server recvfrom ───────────────────────────────────────────
    printf("\nTest 6: Server recvfrom()\n");
    char buf[256];
    sockaddr_in sender;
    memset(&sender, 0, sizeof(sender));
    int sender_len = static_cast<int>(sizeof(sender));

    int recvd = recvfrom(srv, buf, sizeof(buf) - 1, 0,
                         reinterpret_cast<sockaddr *>(&sender), &sender_len);
    report(recvd == static_cast<int>(strlen(msg)),
           "recvfrom() receives the full datagram");
    buf[recvd > 0 ? recvd : 0] = '\0';
    report(strcmp(buf, msg) == 0,
           "received datagram contents match sent message");
    report(sender.sin_family == AF_INET,
           "sender address family is AF_INET");
    report(sender.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
           "sender address is 127.0.0.1");

    // ── Test 7: Server replies back to client ─────────────────────────────
    printf("\nTest 7: Server sendto() reply to client\n");
    const char reply[] = "Reply from WinSock UDP server!";
    sent = sendto(srv, reply, static_cast<int>(strlen(reply)), 0,
                  reinterpret_cast<sockaddr *>(&sender), sender_len);
    report(sent == static_cast<int>(strlen(reply)),
           "server sendto() reply transmits all bytes");

    // ── Test 8: Client select() for readability ───────────────────────────
    printf("\nTest 8: select() – client socket becomes readable\n");
    report(wait_readable(cli, /*timeout_ms=*/2000),
           "client socket is readable within 2 s after server reply");

    // ── Test 9: Client recvfrom ───────────────────────────────────────────
    printf("\nTest 9: Client recvfrom() reply\n");
    sockaddr_in srv_sender;
    memset(&srv_sender, 0, sizeof(srv_sender));
    int srv_sender_len = static_cast<int>(sizeof(srv_sender));

    memset(buf, 0, sizeof(buf));
    recvd = recvfrom(cli, buf, sizeof(buf) - 1, 0,
                     reinterpret_cast<sockaddr *>(&srv_sender), &srv_sender_len);
    report(recvd == static_cast<int>(strlen(reply)),
           "client recvfrom() receives full reply datagram");
    buf[recvd > 0 ? recvd : 0] = '\0';
    report(strcmp(buf, reply) == 0,
           "client received reply contents match server reply message");

    // ── Cleanup ───────────────────────────────────────────────────────────
    closesocket(cli);
    closesocket(srv);
    WSACleanup();

    // ── Summary ───────────────────────────────────────────────────────────
    printf("\n=== WinSock UDP Socket Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
