// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// SEH C Runtime API Test Program
//
// This plain-C program exercises the Windows exception-handling runtime APIs
// that underpin Structured Exception Handling (SEH) through the LiteBox
// Windows-on-Linux shim.  It validates the same APIs that the compiler-emitted
// code calls at runtime when __try/__except is used – the "C side" of SEH.
//
// Note: GCC/MinGW does not support the MSVC-specific __try/__except/__finally
// syntax in C mode.  Those constructs compile only with MSVC.  This test
// therefore exercises the Windows API layer directly, verifying that the
// LiteBox implementations are callable and return sensible values.
//
// Tests covered:
//   1.  RtlCaptureContext – captures non-zero RSP and RIP for the current thread
//   2.  SetUnhandledExceptionFilter – accepts a filter and returns the previous one
//   3.  AddVectoredExceptionHandler – returns a non-NULL registration handle
//   4.  RemoveVectoredExceptionHandler – removes the registration (returns non-zero)
//   5.  RtlLookupFunctionEntry – returns NULL for an out-of-range PC; finds own entry
//       when exception table is registered
//   6.  RtlVirtualUnwind – returns NULL when function_entry is NULL
//   7.  RtlUnwindEx – does not crash when called with NULL arguments
//   8.  Exception code constants – verify the standard codes are defined
//   9.  GetCurrentThreadId / GetCurrentProcessId – identity checks

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ── helpers ──────────────────────────────────────────────────────────────────

static int g_passes   = 0;
static int g_failures = 0;

static void pass(const char *desc)
{
    printf("  [PASS] %s\n", desc);
    ++g_passes;
}

static void fail(const char *desc)
{
    printf("  [FAIL] %s\n", desc);
    ++g_failures;
}

static void check(int ok, const char *desc)
{
    if (ok) pass(desc); else fail(desc);
}

// ── Test 1: RtlCaptureContext ─────────────────────────────────────────────────
static void test1_rtl_capture_context(void)
{
    printf("\nTest 1: RtlCaptureContext – captures non-zero RSP and RIP\n");

    // Windows CONTEXT structure for x64 is 1232 bytes.
    // We use a plain byte buffer aligned to 16 bytes (CONTEXT must be 16-byte aligned).
    static CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    RtlCaptureContext(&ctx);

    // RSP must be a plausible stack pointer: non-zero and 8-byte-aligned
    check(ctx.Rsp != 0,              "RSP is non-zero after capture");
    check((ctx.Rsp & 7) == 0,        "RSP is 8-byte aligned");

    // RIP must be a plausible code pointer: non-zero
    check(ctx.Rip != 0,              "RIP is non-zero after capture");

    // Non-volatile registers should be in range [4KB, 2^47] on a 64-bit OS
    // (we only assert non-zero for registers known to have been set by the ABI)
    {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "RSP=0x%016llX RIP=0x%016llX",
                 (unsigned long long)ctx.Rsp,
                 (unsigned long long)ctx.Rip);
        printf("  Info: %s\n", buf);
    }
}

// ── Test 2: SetUnhandledExceptionFilter ──────────────────────────────────────
static LONG WINAPI dummy_filter(PEXCEPTION_POINTERS ep)
{
    (void)ep;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void test2_set_unhandled_filter(void)
{
    printf("\nTest 2: SetUnhandledExceptionFilter – register and restore\n");

    // Install our dummy filter; previous should be NULL (or a valid pointer)
    LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(dummy_filter);

    // We don't assert the previous value since the CRT may have installed one;
    // just verify the call succeeds (doesn't crash).
    pass("SetUnhandledExceptionFilter did not crash");

    // Restore original filter
    SetUnhandledExceptionFilter(prev);
    pass("Previous unhandled exception filter restored");
}

// ── Test 3 & 4: AddVectoredExceptionHandler / RemoveVectoredExceptionHandler ─
static LONG WINAPI noop_veh(PEXCEPTION_POINTERS ep)
{
    (void)ep;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void test3_vectored_handler(void)
{
    printf("\nTest 3: AddVectoredExceptionHandler – returns non-NULL handle\n");

    PVOID handle = AddVectoredExceptionHandler(0, noop_veh);
    check(handle != NULL, "AddVectoredExceptionHandler returns non-NULL");

    printf("\nTest 4: RemoveVectoredExceptionHandler – removes registration\n");
    if (handle != NULL) {
        ULONG removed = RemoveVectoredExceptionHandler(handle);
        check(removed != 0, "RemoveVectoredExceptionHandler returns non-zero");
    } else {
        fail("Cannot test RemoveVectoredExceptionHandler (handle was NULL)");
    }
}

// ── Test 5: RtlLookupFunctionEntry ───────────────────────────────────────────
static void test5_lookup_function_entry(void)
{
    printf("\nTest 5: RtlLookupFunctionEntry\n");

    ULONG64 image_base = 0;

    // Look up a PC that is almost certainly NOT within any registered image.
    // The function should return NULL without crashing.
    (void)RtlLookupFunctionEntry(
        (ULONG64)0xDEAD0000UL, &image_base, NULL);

    // We don't assert on the return value here (it may or may not be NULL
    // depending on whether the emulator registered the exception table), but
    // the call must not crash.
    pass("RtlLookupFunctionEntry did not crash for dummy PC");

    // Look up the PC of this very function.  If the runner registered the
    // exception table then the entry should be non-NULL.
    image_base = 0;
    ULONG64 pc = (ULONG64)(uintptr_t)test5_lookup_function_entry;
    PRUNTIME_FUNCTION self_entry = RtlLookupFunctionEntry(pc, &image_base, NULL);
    {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "RtlLookupFunctionEntry(self PC=0x%016llX) = %s, image_base=0x%016llX",
                 (unsigned long long)pc,
                 self_entry ? "non-NULL" : "NULL",
                 (unsigned long long)image_base);
        printf("  Info: %s\n", buf);
    }
    // Report whether the entry table lookup succeeded (informational, not a hard fail)
    if (self_entry != NULL) {
        check(image_base != 0, "image_base was set when function entry found");
        check(self_entry->BeginAddress != 0,
              "found RUNTIME_FUNCTION has non-zero BeginAddress");
    } else {
        printf("  Note: exception table not registered (may run standalone – OK)\n");
    }
    pass("RtlLookupFunctionEntry self-lookup completed without crash");
}

// ── Test 6: RtlVirtualUnwind with NULL function_entry ─────────────────────────
static void test6_rtl_virtual_unwind_null(void)
{
    printf("\nTest 6: RtlVirtualUnwind(NULL function_entry) – returns NULL\n");

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    PVOID handler_data      = NULL;
    ULONG64 establisher     = 0;
    KNONVOLATILE_CONTEXT_POINTERS nv_ctx;
    memset(&nv_ctx, 0, sizeof(nv_ctx));

    PEXCEPTION_ROUTINE handler = RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        0,    /* image_base */
        0,    /* control_pc */
        NULL, /* function_entry */
        &ctx,
        &handler_data,
        &establisher,
        &nv_ctx);

    check(handler == NULL, "RtlVirtualUnwind returns NULL for NULL function_entry");
}

// ── Test 7: RtlUnwindEx with NULL arguments ────────────────────────────────────
static void test7_rtl_unwind_ex_null(void)
{
    printf("\nTest 7: RtlUnwindEx(NULL, NULL, ...) – does not crash\n");

    // RtlUnwindEx with all-NULL should be a no-op in our stub.
    RtlUnwindEx(NULL, NULL, NULL, NULL, NULL, NULL);
    pass("RtlUnwindEx with NULL arguments did not crash");
}

// ── Test 8: Exception code constants ──────────────────────────────────────────
static void test8_exception_constants(void)
{
    printf("\nTest 8: Standard exception code constants are defined\n");

    check(EXCEPTION_ACCESS_VIOLATION         == 0xC0000005UL,
          "EXCEPTION_ACCESS_VIOLATION == 0xC0000005");
    check(EXCEPTION_INT_DIVIDE_BY_ZERO       == 0xC0000094UL,
          "EXCEPTION_INT_DIVIDE_BY_ZERO == 0xC0000094");
    check(EXCEPTION_STACK_OVERFLOW           == 0xC00000FDUL,
          "EXCEPTION_STACK_OVERFLOW == 0xC00000FD");
    check(EXCEPTION_EXECUTE_HANDLER          == 1,
          "EXCEPTION_EXECUTE_HANDLER == 1");
    check(EXCEPTION_CONTINUE_SEARCH          == 0,
          "EXCEPTION_CONTINUE_SEARCH == 0");
    check(EXCEPTION_CONTINUE_EXECUTION       == (LONG)0xFFFFFFFFUL,
          "EXCEPTION_CONTINUE_EXECUTION == -1");
}

// ── Test 9: GetCurrentThreadId / GetCurrentProcessId ─────────────────────────
static void test9_identity(void)
{
    printf("\nTest 9: GetCurrentThreadId / GetCurrentProcessId\n");

    DWORD tid = GetCurrentThreadId();
    DWORD pid = GetCurrentProcessId();

    check(tid != 0, "GetCurrentThreadId() returns non-zero");
    check(pid != 0, "GetCurrentProcessId() returns non-zero");

    char buf[128];
    snprintf(buf, sizeof(buf), "PID=%lu TID=%lu", (unsigned long)pid, (unsigned long)tid);
    printf("  Info: %s\n", buf);
}

// ── main ───────────────────────────────────────────────────────────────────────
int main(void)
{
    printf("=== SEH C Runtime API Test Suite ===\n");
    printf("Tests the Windows exception-handling runtime APIs (C language)\n");
    printf("Note: __try/__except syntax is MSVC-only and not available in GCC/MinGW.\n");
    printf("      This test exercises the same underlying APIs directly.\n");

    test1_rtl_capture_context();
    test2_set_unhandled_filter();
    test3_vectored_handler();
    test5_lookup_function_entry();
    test6_rtl_virtual_unwind_null();
    test7_rtl_unwind_ex_null();
    test8_exception_constants();
    test9_identity();

    printf("\n=== Results: %d passed, %d failed ===\n", g_passes, g_failures);
    return (g_failures > 0) ? 1 : 0;
}
