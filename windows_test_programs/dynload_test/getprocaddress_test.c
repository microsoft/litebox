// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// GetProcAddress Test Program
//
// This C program exercises the dynamic-loading Windows APIs through the LiteBox
// Windows-on-Linux shim.  It is intentionally written in plain C (not C++) so
// that it exercises the C calling convention and uses the MinGW C runtime.
//
// Tests covered:
//   1. GetModuleHandleA(NULL)          -> non-NULL (main module pseudo-handle)
//   2. GetModuleHandleA("kernel32.dll") -> non-NULL HMODULE
//   3. GetProcAddress – known function  -> non-NULL function pointer
//   4. Call the resolved function       -> executes correctly
//   5. GetProcAddress – unknown name    -> NULL, GetLastError() == 127
//   6. GetProcAddress – ordinal (<0x10000) -> NULL, GetLastError() == 127
//   7. GetModuleHandleW(NULL)          -> non-NULL (main module)
//   8. LoadLibraryA + GetProcAddress   -> round-trip succeeds

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;
static int g_passes   = 0;

static void check(int ok, const char *desc)
{
    if (ok) {
        printf("  [PASS] %s\n", desc);
        g_passes++;
    } else {
        printf("  [FAIL] %s  (GetLastError=%lu)\n", desc, (unsigned long)GetLastError());
        g_failures++;
    }
}

int main(void)
{
    printf("=== GetProcAddress Test Suite ===\n\n");

    /* ── Test 1: GetModuleHandleA(NULL) returns non-NULL ─────────────── */
    printf("Test 1: GetModuleHandleA(NULL) – main module handle\n");
    {
        HMODULE h = GetModuleHandleA(NULL);
        check(h != NULL, "GetModuleHandleA(NULL) returns non-NULL");
    }

    /* ── Test 2: GetModuleHandleA("kernel32.dll") ────────────────────── */
    printf("\nTest 2: GetModuleHandleA(\"kernel32.dll\")\n");
    {
        HMODULE hk32 = GetModuleHandleA("kernel32.dll");
        check(hk32 != NULL, "GetModuleHandleA(\"kernel32.dll\") returns non-NULL");

        if (hk32 != NULL) {
            /* ── Test 3: GetProcAddress – known function ─────────────── */
            printf("\nTest 3: GetProcAddress – known function (GetLastError)\n");
            FARPROC fn = GetProcAddress(hk32, "GetLastError");
            check(fn != NULL,
                  "GetProcAddress(kernel32, \"GetLastError\") returns non-NULL");

            /* ── Test 4: Call the resolved function ──────────────────── */
            if (fn != NULL) {
                printf("\nTest 4: Call the resolved GetLastError function\n");
                typedef DWORD (WINAPI *PFN_GetLastError)(void);
                PFN_GetLastError p = (PFN_GetLastError)(void *)fn;
                SetLastError(0);
                DWORD err = p();
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "Resolved GetLastError() == 0 (got %lu)", (unsigned long)err);
                check(err == 0, buf);
            }

            /* ── Test 5: GetProcAddress – unknown function name ──────── */
            printf("\nTest 5: GetProcAddress – unknown function name\n");
            SetLastError(0);
            FARPROC bad = GetProcAddress(hk32, "NonExistentFunction_XYZ_42");
            check(bad == NULL,
                  "GetProcAddress(kernel32, unknown) returns NULL");
            {
                DWORD ec = GetLastError();
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "GetLastError() == ERROR_PROC_NOT_FOUND(127), got %lu",
                         (unsigned long)ec);
                check(ec == 127, buf);
            }

            /* ── Test 6: GetProcAddress – ordinal lookup ─────────────── */
            printf("\nTest 6: GetProcAddress – ordinal (unsupported)\n");
            SetLastError(0);
            /*
             * On Windows, passing a value < 0x10000 as proc_name is an
             * ordinal.  The LiteBox shim does not support ordinal lookup and
             * must return NULL with ERROR_PROC_NOT_FOUND.
             */
            FARPROC ord = GetProcAddress(hk32, (LPCSTR)(ULONG_PTR)1);
            check(ord == NULL,
                  "GetProcAddress with ordinal 1 returns NULL");
            {
                DWORD ec = GetLastError();
                char buf[128];
                snprintf(buf, sizeof(buf),
                         "GetLastError() == ERROR_PROC_NOT_FOUND(127) for ordinal, got %lu",
                         (unsigned long)ec);
                check(ec == 127, buf);
            }
        }
    }

    /* ── Test 7: GetModuleHandleW(NULL) ─────────────────────────────── */
    printf("\nTest 7: GetModuleHandleW(NULL) – wide variant\n");
    {
        HMODULE h = GetModuleHandleW(NULL);
        check(h != NULL, "GetModuleHandleW(NULL) returns non-NULL");
    }

    /* ── Test 8: LoadLibraryA round-trip ─────────────────────────────── */
    printf("\nTest 8: LoadLibraryA + GetProcAddress round-trip\n");
    {
        HMODULE h = LoadLibraryA("kernel32.dll");
        check(h != NULL, "LoadLibraryA(\"kernel32.dll\") returns non-NULL");

        if (h != NULL) {
            FARPROC fn = GetProcAddress(h, "ExitProcess");
            check(fn != NULL,
                  "GetProcAddress(LoadLibraryA handle, \"ExitProcess\") returns non-NULL");

            BOOL freed = FreeLibrary(h);
            check(freed, "FreeLibrary succeeds after LoadLibraryA");
        }
    }

    /* ── Results ──────────────────────────────────────────────────────── */
    printf("\n=== Results: %d passed, %d failed ===\n", g_passes, g_failures);
    return (g_failures > 0) ? 1 : 0;
}
