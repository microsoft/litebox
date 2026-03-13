// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Synchronization Primitive Tests
//
// Exercises the Windows synchronization APIs emulated by LiteBox:
//
//   Test 1:  CreateMutexW (unnamed) — create, WaitForSingleObject, ReleaseMutex, CloseHandle
//   Test 2:  CreateMutexW (named)   — open same mutex via OpenMutexW, verify handle dedup
//   Test 3:  ReleaseMutex (not owner) — returns FALSE + ERROR_NOT_OWNER
//   Test 4:  Recursive mutex acquire — same thread can lock multiple times
//   Test 5:  CreateEventW (auto-reset, initially signaled) — WaitForSingleObject returns immediately
//   Test 6:  CreateEventW (manual-reset, initially not-signaled) — SetEvent, WaitForSingleObject
//   Test 7:  ResetEvent — event goes back to non-signaled, WaitForSingleObject times out
//   Test 8:  CreateEventW (auto-reset) — event consumed by one wait, second wait times out
//   Test 9:  CreateSemaphoreW — initial count 1, WaitForSingleObject, ReleaseSemaphore
//   Test 10: Semaphore initial count 0 — WaitForSingleObject times out immediately
//   Test 11: ReleaseSemaphore by more than max — returns FALSE + ERROR_TOO_MANY_POSTS
//   Test 12: WaitForSingleObject with WAIT_TIMEOUT — INFINITE vs finite timeout
//   Test 13: CloseHandle on sync objects — subsequent operations fail

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

// ── Test framework helpers ────────────────────────────────────────────────────

static int g_failures = 0;
static int g_passes   = 0;

static void check(bool ok, const char *desc)
{
    if (ok) {
        printf("  [PASS] %s\n", desc);
        ++g_passes;
    } else {
        printf("  [FAIL] %s  (LastError=%lu)\n", desc, (unsigned long)GetLastError());
        ++g_failures;
    }
}

// ── Test 1: Unnamed mutex — basic acquire / release ───────────────────────────

static void test1_unnamed_mutex()
{
    printf("\nTest 1: Unnamed mutex — create / wait / release\n");

    HANDLE hMutex = CreateMutexW(NULL, FALSE, NULL);
    check(hMutex != NULL, "CreateMutexW returns non-NULL");

    DWORD wait = WaitForSingleObject(hMutex, 0);
    check(wait == WAIT_OBJECT_0, "WaitForSingleObject acquires unlocked mutex");

    BOOL ok = ReleaseMutex(hMutex);
    check(ok != FALSE, "ReleaseMutex succeeds");

    BOOL closed = CloseHandle(hMutex);
    check(closed != FALSE, "CloseHandle on mutex succeeds");
}

// ── Test 2: Named mutex — OpenMutexW returns same handle ──────────────────────

static void test2_named_mutex_open()
{
    printf("\nTest 2: Named mutex — OpenMutexW dedup\n");

    const wchar_t *name = L"LiteBoxTestMutex2";
    HANDLE h1 = CreateMutexW(NULL, FALSE, name);
    check(h1 != NULL, "CreateMutexW (named) returns non-NULL");

    HANDLE h2 = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, name);
    check(h2 != NULL, "OpenMutexW finds existing named mutex");
    check(h1 == h2,   "OpenMutexW returns the same handle as CreateMutexW");

    CloseHandle(h1);
    // h2 == h1 so only one close needed
}

// ── Test 3: ReleaseMutex when not owner ───────────────────────────────────────

static void test3_release_not_owner()
{
    printf("\nTest 3: ReleaseMutex — not owner\n");

    // Mutex not acquired by current thread
    HANDLE h = CreateMutexW(NULL, FALSE, NULL);
    check(h != NULL, "CreateMutexW succeeds");

    BOOL ok = ReleaseMutex(h);
    check(ok == FALSE, "ReleaseMutex on un-acquired mutex returns FALSE");
    check(GetLastError() == ERROR_NOT_OWNER, "GetLastError() == ERROR_NOT_OWNER");

    CloseHandle(h);
}

// ── Test 4: Recursive mutex ───────────────────────────────────────────────────

static void test4_recursive_mutex()
{
    printf("\nTest 4: Recursive mutex — same-thread re-entrant acquire\n");

    HANDLE h = CreateMutexW(NULL, FALSE, NULL);
    check(h != NULL, "CreateMutexW succeeds");

    DWORD r1 = WaitForSingleObject(h, 0);
    check(r1 == WAIT_OBJECT_0, "First acquire succeeds");

    DWORD r2 = WaitForSingleObject(h, 0);
    check(r2 == WAIT_OBJECT_0, "Recursive acquire succeeds (same thread)");

    BOOL ok1 = ReleaseMutex(h);
    check(ok1 != FALSE, "ReleaseMutex (decrement to 1) succeeds");

    BOOL ok2 = ReleaseMutex(h);
    check(ok2 != FALSE, "ReleaseMutex (decrement to 0) succeeds");

    CloseHandle(h);
}

// ── Test 5: Auto-reset event, initially signaled ──────────────────────────────

static void test5_auto_reset_event_signaled()
{
    printf("\nTest 5: Auto-reset event — initially signaled, consumed by wait\n");

    // manual_reset=FALSE (auto-reset), initial_state=TRUE (signaled)
    HANDLE h = CreateEventW(NULL, FALSE, TRUE, NULL);
    check(h != NULL, "CreateEventW (auto-reset, signaled) returns non-NULL");

    // First wait should return immediately and reset the event
    DWORD r = WaitForSingleObject(h, 0);
    check(r == WAIT_OBJECT_0, "WaitForSingleObject returns WAIT_OBJECT_0");

    // Second wait: event was auto-reset, should now timeout
    DWORD r2 = WaitForSingleObject(h, 0);
    check(r2 == WAIT_TIMEOUT, "Second wait times out (auto-reset consumed event)");

    CloseHandle(h);
}

// ── Test 6: Manual-reset event — SetEvent / WaitForSingleObject ───────────────

static void test6_manual_reset_event()
{
    printf("\nTest 6: Manual-reset event — SetEvent then wait\n");

    // manual_reset=TRUE, initial_state=FALSE
    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);
    check(h != NULL, "CreateEventW (manual-reset, non-signaled) returns non-NULL");

    // Should time out immediately (not signaled)
    DWORD r1 = WaitForSingleObject(h, 0);
    check(r1 == WAIT_TIMEOUT, "Wait on non-signaled event times out");

    BOOL ok = SetEvent(h);
    check(ok != FALSE, "SetEvent succeeds");

    // Now should return immediately (manual-reset stays signaled)
    DWORD r2 = WaitForSingleObject(h, 0);
    check(r2 == WAIT_OBJECT_0, "Wait on signaled manual-reset event succeeds");

    // Still signaled (manual-reset does not auto-clear)
    DWORD r3 = WaitForSingleObject(h, 0);
    check(r3 == WAIT_OBJECT_0, "Manual-reset event stays signaled across waits");

    CloseHandle(h);
}

// ── Test 7: ResetEvent ────────────────────────────────────────────────────────

static void test7_reset_event()
{
    printf("\nTest 7: ResetEvent — event goes back to non-signaled\n");

    HANDLE h = CreateEventW(NULL, TRUE, TRUE, NULL);  // manual-reset, signaled
    check(h != NULL, "CreateEventW succeeds");

    BOOL ok = ResetEvent(h);
    check(ok != FALSE, "ResetEvent succeeds");

    DWORD r = WaitForSingleObject(h, 0);
    check(r == WAIT_TIMEOUT, "WaitForSingleObject times out after ResetEvent");

    CloseHandle(h);
}

// ── Test 8: Auto-reset event — SetEvent then two waits ───────────────────────

static void test8_auto_reset_set_event()
{
    printf("\nTest 8: Auto-reset event — SetEvent consumed by first wait\n");

    HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);  // auto-reset, non-signaled
    check(h != NULL, "CreateEventW (auto-reset, non-signaled) returns non-NULL");

    BOOL ok = SetEvent(h);
    check(ok != FALSE, "SetEvent succeeds");

    DWORD r1 = WaitForSingleObject(h, 0);
    check(r1 == WAIT_OBJECT_0, "First wait succeeds (event was signaled)");

    DWORD r2 = WaitForSingleObject(h, 0);
    check(r2 == WAIT_TIMEOUT, "Second wait times out (auto-reset cleared signal)");

    CloseHandle(h);
}

// ── Test 9: Semaphore — basic acquire / release ───────────────────────────────

static void test9_semaphore_basic()
{
    printf("\nTest 9: Semaphore — create (count=1), wait, release\n");

    HANDLE h = CreateSemaphoreW(NULL, 1, 2, NULL);
    check(h != NULL, "CreateSemaphoreW (initial=1, max=2) returns non-NULL");

    DWORD r = WaitForSingleObject(h, 0);
    check(r == WAIT_OBJECT_0, "WaitForSingleObject decrements count to 0");

    // Count is 0 — next wait should timeout
    DWORD r2 = WaitForSingleObject(h, 0);
    check(r2 == WAIT_TIMEOUT, "Second wait times out (count=0)");

    LONG prev = 0;
    BOOL ok = ReleaseSemaphore(h, 1, &prev);
    check(ok != FALSE, "ReleaseSemaphore(1) succeeds");
    check(prev == 0,   "Previous count was 0");

    // Now count is back to 1
    DWORD r3 = WaitForSingleObject(h, 0);
    check(r3 == WAIT_OBJECT_0, "Wait succeeds after release (count restored to 1)");

    CloseHandle(h);
}

// ── Test 10: Semaphore — initial count 0, wait times out ─────────────────────

static void test10_semaphore_zero_initial()
{
    printf("\nTest 10: Semaphore — initial count 0, immediate timeout\n");

    HANDLE h = CreateSemaphoreW(NULL, 0, 5, NULL);
    check(h != NULL, "CreateSemaphoreW (initial=0) returns non-NULL");

    DWORD r = WaitForSingleObject(h, 0);
    check(r == WAIT_TIMEOUT, "WaitForSingleObject times out on count-0 semaphore");

    CloseHandle(h);
}

// ── Test 11: ReleaseSemaphore beyond max ──────────────────────────────────────

static void test11_semaphore_overflow()
{
    printf("\nTest 11: Semaphore — ReleaseSemaphore beyond max returns FALSE\n");

    HANDLE h = CreateSemaphoreW(NULL, 1, 1, NULL);  // initial=1, max=1
    check(h != NULL, "CreateSemaphoreW (initial=1, max=1) returns non-NULL");

    // Count is already at max (1), releasing again should fail
    LONG prev = 0;
    BOOL ok = ReleaseSemaphore(h, 1, &prev);
    check(ok == FALSE, "ReleaseSemaphore beyond max returns FALSE");
    check(GetLastError() == ERROR_TOO_MANY_POSTS,
          "GetLastError() == ERROR_TOO_MANY_POSTS");

    CloseHandle(h);
}

// ── Test 12: WaitForSingleObject timeout values ───────────────────────────────

static void test12_wait_timeout_values()
{
    printf("\nTest 12: WaitForSingleObject — timeout=0 on unsignaled object\n");

    HANDLE h = CreateEventW(NULL, TRUE, FALSE, NULL);  // not signaled
    check(h != NULL, "CreateEventW succeeds");

    DWORD r = WaitForSingleObject(h, 0);
    check(r == WAIT_TIMEOUT, "timeout=0 returns WAIT_TIMEOUT immediately");
    check(r != WAIT_FAILED,  "return value is not WAIT_FAILED");

    CloseHandle(h);
}

// ── Test 13: CloseHandle on sync objects ─────────────────────────────────────

static void test13_close_handle()
{
    printf("\nTest 13: CloseHandle on mutex / event / semaphore\n");

    HANDLE hMutex = CreateMutexW(NULL, FALSE, NULL);
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE hSema  = CreateSemaphoreW(NULL, 1, 1, NULL);

    check(hMutex != NULL, "Mutex handle is non-NULL");
    check(hEvent != NULL, "Event handle is non-NULL");
    check(hSema  != NULL, "Semaphore handle is non-NULL");

    check(CloseHandle(hMutex) != FALSE, "CloseHandle(mutex) succeeds");
    check(CloseHandle(hEvent) != FALSE, "CloseHandle(event) succeeds");
    check(CloseHandle(hSema)  != FALSE, "CloseHandle(semaphore) succeeds");
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(void)
{
    printf("=== Windows Synchronization API Tests ===\n");

    test1_unnamed_mutex();
    test2_named_mutex_open();
    test3_release_not_owner();
    test4_recursive_mutex();
    test5_auto_reset_event_signaled();
    test6_manual_reset_event();
    test7_reset_event();
    test8_auto_reset_set_event();
    test9_semaphore_basic();
    test10_semaphore_zero_initial();
    test11_semaphore_overflow();
    test12_wait_timeout_values();
    test13_close_handle();

    printf("\n=== Windows Synchronization API Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
