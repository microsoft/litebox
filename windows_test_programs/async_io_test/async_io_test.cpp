// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Async I/O Test Program
//
// Tests the following Windows asynchronous I/O APIs as supported by the
// LiteBox Windows-on-Linux platform:
//
//   1. IOCP creation               (CreateIoCompletionPort)
//   2. Custom completion posting   (PostQueuedCompletionStatus)
//   3. Completion dequeue          (GetQueuedCompletionStatus)
//   4. Zero-timeout dequeue        (timeout with empty port)
//   5. Batch dequeue               (GetQueuedCompletionStatusEx)
//   6. IOCP-backed ReadFile        (file associated with IOCP + ReadFile with overlapped)
//   7. IOCP-backed WriteFile       (file associated with IOCP + WriteFile with overlapped)
//   8. APC-based ReadFileEx        (ReadFileEx + SleepEx alertable)
//   9. APC-based WriteFileEx       (WriteFileEx + SleepEx alertable)
//  10. GetOverlappedResult         (read result from OVERLAPPED after ReadFileEx)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ── helpers ───────────────────────────────────────────────────────────────

static int g_failures = 0;

static void pass(const char *desc)
{
    printf("  [PASS] %s\n", desc);
}

static void fail(const char *desc, DWORD err = 0)
{
    if (err == 0) err = GetLastError();
    printf("  [FAIL] %s  (error=%lu)\n", desc, (unsigned long)err);
    ++g_failures;
}

static void check(bool ok, const char *desc)
{
    if (ok) pass(desc); else fail(desc);
}

// Unique temp-file name based on process ID.
static void make_temp_path(char *buf, size_t sz, const char *suffix)
{
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    _snprintf_s(buf, sz, _TRUNCATE, "%slitebox_async_%lu%s",
                tmp, (unsigned long)GetCurrentProcessId(), suffix);
}

// Create a file, write `data` to it, and close it.  Returns FALSE on error.
static BOOL create_file_with_content(const char *path, const void *data, DWORD len)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data, len, &written, NULL);
    CloseHandle(h);
    return ok && written == len;
}

// ── APC state ─────────────────────────────────────────────────────────────

static volatile DWORD g_apc_error   = 0xFFFFFFFFUL;
static volatile DWORD g_apc_bytes   = 0xFFFFFFFFUL;
static volatile BOOL  g_apc_called  = FALSE;

static void WINAPI apc_completion(DWORD errCode, DWORD bytesTransferred,
                                   LPOVERLAPPED /*lpOv*/)
{
    g_apc_error  = errCode;
    g_apc_bytes  = bytesTransferred;
    g_apc_called = TRUE;
}

static volatile DWORD g_apc2_bytes  = 0xFFFFFFFFUL;
static volatile BOOL  g_apc2_called = FALSE;

static void WINAPI apc2_completion(DWORD /*err*/, DWORD bytes, LPOVERLAPPED /*ov*/)
{
    g_apc2_bytes  = bytes;
    g_apc2_called = TRUE;
}

// ── Test 1: Create an I/O Completion Port ─────────────────────────────────

static void test_create_iocp(HANDLE *out_port)
{
    printf("\nTest 1: Create I/O Completion Port\n");
    HANDLE port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    check(port != NULL && port != INVALID_HANDLE_VALUE,
          "CreateIoCompletionPort returns a valid handle");
    *out_port = port;
}

// ── Test 2: Post a custom completion packet ────────────────────────────────

static void test_post_completion(HANDLE port)
{
    printf("\nTest 2: PostQueuedCompletionStatus\n");
    BOOL ok = PostQueuedCompletionStatus(port, 123, (ULONG_PTR)0xABCD, NULL);
    check(ok != FALSE, "PostQueuedCompletionStatus returns TRUE");
}

// ── Test 3: Dequeue the packet ────────────────────────────────────────────

static void test_get_completion(HANDLE port)
{
    printf("\nTest 3: GetQueuedCompletionStatus – dequeue packet\n");
    DWORD       bytes  = 0xDEAD;
    ULONG_PTR   key    = 0;
    LPOVERLAPPED ov    = (LPOVERLAPPED)1; // non-null sentinel
    BOOL ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov,
                                        0 /* non-blocking */);
    check(ok != FALSE,           "GetQueuedCompletionStatus returns TRUE");
    check(bytes == 123,          "bytes_transferred == 123");
    check(key   == 0xABCD,       "completion_key == 0xABCD");
    check(ov    == NULL,         "overlapped == NULL (as posted)");
}

// ── Test 4: Dequeue from empty port – expect timeout ──────────────────────

static void test_timeout(HANDLE port)
{
    printf("\nTest 4: GetQueuedCompletionStatus – timeout on empty port\n");
    DWORD bytes = 0; ULONG_PTR key = 0; LPOVERLAPPED ov = NULL;
    BOOL ok = GetQueuedCompletionStatus(port, &bytes, &key, &ov, 0);
    check(ok == FALSE,              "Returns FALSE when queue empty");
    check(GetLastError() == WAIT_TIMEOUT,
          "Last error is WAIT_TIMEOUT (258)");
}

// ── Test 5: GetQueuedCompletionStatusEx – batch dequeue ───────────────────

static void test_get_ex(HANDLE port)
{
    printf("\nTest 5: GetQueuedCompletionStatusEx – batch dequeue\n");

    // Post three packets.
    PostQueuedCompletionStatus(port, 10, 1, NULL);
    PostQueuedCompletionStatus(port, 20, 2, NULL);
    PostQueuedCompletionStatus(port, 30, 3, NULL);

    // Dequeue up to 8 at once.
    OVERLAPPED_ENTRY entries[8];
    memset(entries, 0, sizeof(entries));
    ULONG removed = 0;
    BOOL ok = GetQueuedCompletionStatusEx(port, entries, 8, &removed,
                                           0 /* non-blocking */, FALSE);
    check(ok != FALSE,       "GetQueuedCompletionStatusEx returns TRUE");
    check(removed == 3,      "3 packets dequeued");
    if (removed >= 1) check(entries[0].dwNumberOfBytesTransferred == 10, "entry[0].bytes == 10");
    if (removed >= 2) check(entries[1].dwNumberOfBytesTransferred == 20, "entry[1].bytes == 20");
    if (removed >= 3) check(entries[2].dwNumberOfBytesTransferred == 30, "entry[2].bytes == 30");
}

// ── Test 6: IOCP-backed ReadFile ──────────────────────────────────────────

static void test_iocp_read_file(HANDLE port)
{
    printf("\nTest 6: IOCP-backed ReadFile\n");

    char path[MAX_PATH];
    make_temp_path(path, sizeof(path), "_read.tmp");

    const char *content = "iocp read test";
    DWORD clen = (DWORD)strlen(content);

    if (!create_file_with_content(path, content, clen)) {
        fail("Setup: create temp file"); return;
    }

    HANDLE fh = CreateFileA(path, GENERIC_READ, 0, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) { fail("Open temp file"); return; }

    // Associate with IOCP using key 0xBEEF.
    HANDLE assoc = CreateIoCompletionPort(fh, port, (ULONG_PTR)0xBEEF, 0);
    check(assoc == port, "File associated with IOCP");

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    char buf[64] = {};
    DWORD bread = 0;
    BOOL ok = ReadFile(fh, buf, sizeof(buf), &bread, &ov);
    check(ok != FALSE, "ReadFile (IOCP-associated) returns TRUE");
    check(bread == clen, "ReadFile returned correct byte count");
    check(memcmp(buf, content, clen) == 0, "ReadFile content matches");

    // Completion should have been posted automatically.
    DWORD       cbytes = 0;
    ULONG_PTR   ckey   = 0;
    LPOVERLAPPED cov   = NULL;
    BOOL got = GetQueuedCompletionStatus(port, &cbytes, &ckey, &cov, 0);
    check(got != FALSE,       "Completion packet posted after ReadFile");
    check(ckey == 0xBEEF,    "completion_key == 0xBEEF");
    check(cbytes == clen,    "bytes in completion == bytes read");

    CloseHandle(fh);
    DeleteFileA(path);
}

// ── Test 7: IOCP-backed WriteFile ─────────────────────────────────────────

static void test_iocp_write_file(HANDLE port)
{
    printf("\nTest 7: IOCP-backed WriteFile\n");

    char path[MAX_PATH];
    make_temp_path(path, sizeof(path), "_write.tmp");

    HANDLE fh = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) { fail("Create temp file"); return; }

    // Associate with IOCP using key 0xCAFE.
    HANDLE assoc = CreateIoCompletionPort(fh, port, (ULONG_PTR)0xCAFE, 0);
    check(assoc == port, "File associated with IOCP");

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    const char *data = "iocp write test";
    DWORD dlen = (DWORD)strlen(data);
    DWORD written = 0;
    BOOL ok = WriteFile(fh, data, dlen, &written, &ov);
    check(ok != FALSE, "WriteFile (IOCP-associated) returns TRUE");
    check(written == dlen, "WriteFile wrote correct byte count");

    // Completion should have been posted.
    DWORD     cbytes = 0;
    ULONG_PTR ckey   = 0;
    LPOVERLAPPED cov = NULL;
    BOOL got = GetQueuedCompletionStatus(port, &cbytes, &ckey, &cov, 0);
    check(got != FALSE,    "Completion packet posted after WriteFile");
    check(ckey == 0xCAFE, "completion_key == 0xCAFE");
    check(cbytes == dlen, "bytes in completion == bytes written");

    CloseHandle(fh);
    DeleteFileA(path);
}

// ── Test 8: ReadFileEx + SleepEx alertable ────────────────────────────────

static void test_read_file_ex(void)
{
    printf("\nTest 8: ReadFileEx + SleepEx (alertable)\n");

    char path[MAX_PATH];
    make_temp_path(path, sizeof(path), "_rfex.tmp");

    const char *content = "async read ex";
    DWORD clen = (DWORD)strlen(content);
    if (!create_file_with_content(path, content, clen)) {
        fail("Setup: create temp file"); return;
    }

    HANDLE fh = CreateFileA(path, GENERIC_READ, 0, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) { fail("Open temp file"); return; }

    // Reset APC state.
    g_apc_called = FALSE;
    g_apc_bytes  = 0xFFFFFFFFUL;
    g_apc_error  = 0xFFFFFFFFUL;

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    char buf[64] = {};
    BOOL ok = ReadFileEx(fh, buf, sizeof(buf), &ov, apc_completion);
    check(ok != FALSE, "ReadFileEx returns TRUE");
    check(g_apc_called == FALSE, "APC not yet invoked before alertable wait");

    // Drain the APC queue.
    DWORD sr = SleepEx(0, TRUE /* alertable */);
    check(sr == WAIT_IO_COMPLETION, "SleepEx returns WAIT_IO_COMPLETION");
    check(g_apc_called != FALSE,    "APC callback was invoked");
    check(g_apc_bytes  == clen,     "APC reports correct byte count");
    check(g_apc_error  == 0,        "APC reports no error");
    check(memcmp(buf, content, clen) == 0, "Buffer contains expected data");

    // GetOverlappedResult should confirm success.
    DWORD transferred = 0;
    BOOL gor = GetOverlappedResult(fh, &ov, &transferred, FALSE);
    check(gor != FALSE,          "GetOverlappedResult returns TRUE");
    check(transferred == clen,   "GetOverlappedResult reports correct bytes");

    CloseHandle(fh);
    DeleteFileA(path);
}

// ── Test 9: WriteFileEx + SleepEx alertable ───────────────────────────────

static void test_write_file_ex(void)
{
    printf("\nTest 9: WriteFileEx + SleepEx (alertable)\n");

    char path[MAX_PATH];
    make_temp_path(path, sizeof(path), "_wfex.tmp");

    HANDLE fh = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) { fail("Create temp file"); return; }

    // Reset APC state.
    g_apc2_called = FALSE;
    g_apc2_bytes  = 0xFFFFFFFFUL;

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    const char *data = "async write ex";
    DWORD dlen = (DWORD)strlen(data);
    BOOL ok = WriteFileEx(fh, data, dlen, &ov, apc2_completion);
    check(ok != FALSE,             "WriteFileEx returns TRUE");
    check(g_apc2_called == FALSE,  "APC not yet invoked before alertable wait");

    DWORD sr = SleepEx(0, TRUE);
    check(sr == WAIT_IO_COMPLETION,  "SleepEx returns WAIT_IO_COMPLETION");
    check(g_apc2_called != FALSE,    "APC callback was invoked");
    check(g_apc2_bytes == dlen,      "APC reports correct byte count");

    CloseHandle(fh);
    DeleteFileA(path);
}

// ── Test 10: GetOverlappedResult on a synchronous ReadFileEx ──────────────

static void test_get_overlapped_result(void)
{
    printf("\nTest 10: GetOverlappedResult after ReadFileEx\n");

    char path[MAX_PATH];
    make_temp_path(path, sizeof(path), "_gor.tmp");

    const char *content = "overlapped result";
    DWORD clen = (DWORD)strlen(content);
    if (!create_file_with_content(path, content, clen)) {
        fail("Setup: create temp file"); return;
    }

    HANDLE fh = CreateFileA(path, GENERIC_READ, 0, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) { fail("Open temp file"); return; }

    g_apc_called = FALSE;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    char buf[64] = {};

    ReadFileEx(fh, buf, sizeof(buf), &ov, apc_completion);

    // Drain the APC so the OVERLAPPED result is written.
    SleepEx(0, TRUE);

    DWORD transferred = 0xDEAD;
    BOOL gor = GetOverlappedResult(fh, &ov, &transferred, FALSE);
    check(gor != FALSE,           "GetOverlappedResult returns TRUE");
    check(transferred == clen,    "GetOverlappedResult bytes == content length");

    CloseHandle(fh);
    DeleteFileA(path);
}

// ── main ──────────────────────────────────────────────────────────────────

int main(void)
{
    printf("=== Async I/O Test Suite ===\n");

    HANDLE port = NULL;
    test_create_iocp(&port);
    if (port == NULL || port == INVALID_HANDLE_VALUE) {
        printf("\nFATAL: Could not create IOCP – aborting remaining IOCP tests.\n");
        g_failures++;
    } else {
        test_post_completion(port);
        test_get_completion(port);
        test_timeout(port);
        test_get_ex(port);
        test_iocp_read_file(port);
        test_iocp_write_file(port);
        CloseHandle(port);
    }

    test_read_file_ex();
    test_write_file_ex();
    test_get_overlapped_result();

    printf("\n=== Async I/O Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
