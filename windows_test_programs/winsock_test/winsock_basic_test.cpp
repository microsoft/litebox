// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// WinSock Basic API Tests
//
// Tests:
//   WSAStartup / WSACleanup
//   htons / ntohs / htonl / ntohl
//   WSAGetLastError / WSASetLastError
//   socket() + closesocket() – TCP and UDP
//   setsockopt / getsockopt (SO_REUSEADDR, SO_SNDBUF, SO_RCVBUF)
//   ioctlsocket – FIONBIO non-blocking mode
//   bind to 127.0.0.1:0 + getsockname
//   getaddrinfo / freeaddrinfo

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

// Link with ws2_32 on MSVC; MinGW uses -lws2_32 linker flag.
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

int main(void)
{
    printf("=== WinSock Basic API Tests ===\n\n");

    // ── Test 1: WSAStartup ──────────────────────────────────────────────
    printf("Test 1: WSAStartup\n");
    {
        WSADATA wsa;
        int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
        report(rc == 0, "WSAStartup(2,2) returns 0");
        report(LOBYTE(wsa.wVersion) == 2, "negotiated version major == 2");
        report(HIBYTE(wsa.wVersion) == 2, "negotiated version minor == 2");
    }

    // ── Test 2: Byte-order helpers ────────────────────────────────────────
    printf("\nTest 2: Byte-order helpers\n");
    {
        u_short h16 = 0x1234u;
        u_long  h32 = 0x12345678ul;
        u_short n16 = htons(h16);
        u_long  n32 = htonl(h32);

        report(ntohs(n16) == h16, "htons / ntohs round-trip");
        report(ntohl(n32) == h32, "htonl / ntohl round-trip");
    }

    // ── Test 3: WSAGetLastError / WSASetLastError ─────────────────────────
    printf("\nTest 3: WSAGetLastError / WSASetLastError\n");
    {
        WSASetLastError(WSAETIMEDOUT);
        report(WSAGetLastError() == WSAETIMEDOUT,
               "WSASetLastError(WSAETIMEDOUT) -> WSAGetLastError returns WSAETIMEDOUT");
        WSASetLastError(0);
        report(WSAGetLastError() == 0, "WSASetLastError(0) clears last error");
    }

    // ── Test 4: TCP socket create / close ─────────────────────────────────
    printf("\nTest 4: TCP socket creation\n");
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        report(s != INVALID_SOCKET, "socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) succeeds");
        if (s != INVALID_SOCKET) {
            report(closesocket(s) == 0, "closesocket() succeeds");
        }
    }

    // ── Test 5: UDP socket create / close ────────────────────────────────
    printf("\nTest 5: UDP socket creation\n");
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        report(s != INVALID_SOCKET, "socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) succeeds");
        if (s != INVALID_SOCKET) {
            report(closesocket(s) == 0, "closesocket() succeeds");
        }
    }

    // ── Test 6: setsockopt / getsockopt ──────────────────────────────────
    printf("\nTest 6: setsockopt / getsockopt\n");
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            printf("  [SKIP] socket creation failed, skipping setsockopt tests\n");
            g_failures += 5;
        } else {
            // SO_REUSEADDR
            int opt = 1;
            report(setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                              reinterpret_cast<const char *>(&opt), sizeof(opt)) == 0,
                   "setsockopt(SO_REUSEADDR, 1) succeeds");

            int val = 0;
            int len = static_cast<int>(sizeof(val));
            report(getsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                              reinterpret_cast<char *>(&val), &len) == 0 && val != 0,
                   "getsockopt(SO_REUSEADDR) returns non-zero after set");

            // SO_SNDBUF
            int sndbuf = 65536;
            report(setsockopt(s, SOL_SOCKET, SO_SNDBUF,
                              reinterpret_cast<const char *>(&sndbuf), sizeof(sndbuf)) == 0,
                   "setsockopt(SO_SNDBUF, 65536) succeeds");

            // SO_RCVBUF
            int rcvbuf = 65536;
            report(setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                              reinterpret_cast<const char *>(&rcvbuf), sizeof(rcvbuf)) == 0,
                   "setsockopt(SO_RCVBUF, 65536) succeeds");

            // SO_KEEPALIVE
            int keepalive = 1;
            report(setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                              reinterpret_cast<const char *>(&keepalive), sizeof(keepalive)) == 0,
                   "setsockopt(SO_KEEPALIVE, 1) succeeds");

            closesocket(s);
        }
    }

    // ── Test 7: ioctlsocket (FIONBIO) ─────────────────────────────────────
    printf("\nTest 7: ioctlsocket – non-blocking mode (FIONBIO)\n");
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            printf("  [SKIP] socket creation failed, skipping ioctlsocket tests\n");
            g_failures += 2;
        } else {
            u_long nonblocking = 1;
            report(ioctlsocket(s, FIONBIO, &nonblocking) == 0,
                   "ioctlsocket(FIONBIO, 1) sets non-blocking mode");
            u_long blocking = 0;
            report(ioctlsocket(s, FIONBIO, &blocking) == 0,
                   "ioctlsocket(FIONBIO, 0) restores blocking mode");
            closesocket(s);
        }
    }

    // ── Test 8: bind to port 0 + getsockname ─────────────────────────────
    printf("\nTest 8: bind to 127.0.0.1:0 and getsockname\n");
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            printf("  [SKIP] socket creation failed, skipping bind tests\n");
            g_failures += 3;
        } else {
            int opt = 1;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char *>(&opt), sizeof(opt));

            sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port        = 0; // ask OS to assign a free port

            report(bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0,
                   "bind(127.0.0.1:0) succeeds");

            sockaddr_in bound;
            memset(&bound, 0, sizeof(bound));
            int len = static_cast<int>(sizeof(bound));
            report(getsockname(s, reinterpret_cast<sockaddr *>(&bound), &len) == 0,
                   "getsockname after bind succeeds");
            report(ntohs(bound.sin_port) != 0,
                   "getsockname returns a non-zero assigned port");

            closesocket(s);
        }
    }

    // ── Test 9: getaddrinfo / freeaddrinfo ───────────────────────────────
    printf("\nTest 9: getaddrinfo / freeaddrinfo\n");
    {
        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo *res = nullptr;
        int rc = getaddrinfo("127.0.0.1", "80", &hints, &res);
        report(rc == 0 && res != nullptr,
               "getaddrinfo(\"127.0.0.1\", \"80\") returns 0 with results");
        if (res != nullptr) {
            freeaddrinfo(res);
            // If freeaddrinfo crashes, we never reach the next line.
            report(true, "freeaddrinfo completes without crash");
        }
    }

    // ── Test 10: WSACleanup ──────────────────────────────────────────────
    printf("\nTest 10: WSACleanup\n");
    {
        report(WSACleanup() == 0, "WSACleanup() returns 0");
    }

    // ── Summary ───────────────────────────────────────────────────────────
    printf("\n=== WinSock Basic API Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
