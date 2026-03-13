// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Phase 27 API Tests
//
// Exercises the Windows APIs added in Phase 27 of the LiteBox Windows-on-Linux
// emulation layer.  Each test group covers a distinct Phase 27 area:
//
//   Group A — Thread Management
//     A1: SetThreadPriority / GetThreadPriority
//     A2: SuspendThread / ResumeThread
//     A3: OpenThread / GetExitCodeThread (creates a real thread)
//
//   Group B — Process Management
//     B1: OpenProcess — current PID succeeds
//     B2: OpenProcess — unknown PID fails
//     B3: GetProcessTimes — returns non-zero creation time
//
//   Group C — File Time APIs
//     C1: GetFileTime — reads timestamps from a real file
//     C2: CompareFileTime — ordering correctness
//     C3: FileTimeToLocalFileTime — round-trips non-zero
//
//   Group D — System Directory / Temp File Name
//     D1: GetSystemDirectoryW — returns path containing "System32"
//     D2: GetWindowsDirectoryW — returns path containing "Windows"
//     D3: GetTempFileNameW — returns name ending with ".tmp"
//
//   Group E — Character Conversion (USER32)
//     E1: CharUpperW / CharLowerW — single-character mode
//     E2: CharUpperW / CharLowerW — string mode (in-place)
//     E3: CharUpperA / CharLowerA — single-character mode
//
//   Group F — Character Classification (USER32)
//     F1: IsCharAlphaW
//     F2: IsCharAlphaNumericW
//     F3: IsCharUpperW / IsCharLowerW
//
//   Group G — Window Utilities (USER32, headless)
//     G1: IsWindow / IsWindowEnabled / IsWindowVisible
//     G2: EnableWindow
//     G3: GetWindowTextW / SetWindowTextW
//     G4: GetParent

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

// ── Group A: Thread Management ────────────────────────────────────────────────

static void testA1_set_get_thread_priority()
{
    printf("\nTest A1: SetThreadPriority / GetThreadPriority\n");
    HANDLE hThread = GetCurrentThread();

    BOOL ok = SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
    check(ok != FALSE, "SetThreadPriority(THREAD_PRIORITY_NORMAL) returns TRUE");

    int prio = GetThreadPriority(hThread);
    check(prio == THREAD_PRIORITY_NORMAL, "GetThreadPriority returns THREAD_PRIORITY_NORMAL (0)");
}

static void testA2_suspend_resume()
{
    printf("\nTest A2: SuspendThread / ResumeThread\n");
    HANDLE hThread = GetCurrentThread();

    DWORD prev_suspend = SuspendThread(hThread);
    check(prev_suspend == 0, "SuspendThread returns previous suspend count (0)");

    DWORD prev_resume = ResumeThread(hThread);
    check(prev_resume == 0, "ResumeThread returns previous suspend count (0)");
}

// Thread function used by A3
static DWORD WINAPI thread_func_a3(LPVOID /*param*/)
{
    Sleep(50);
    return 42;
}

static void testA3_open_thread_exit_code()
{
    printf("\nTest A3: OpenThread / GetExitCodeThread\n");

    DWORD tid = 0;
    HANDLE hThread = CreateThread(NULL, 0, thread_func_a3, NULL, 0, &tid);
    check(hThread != NULL, "CreateThread succeeds");

    if (hThread == NULL) return;

    // GetExitCodeThread while running should return STILL_ACTIVE
    DWORD code = 0;
    BOOL ok = GetExitCodeThread(hThread, &code);
    check(ok != FALSE, "GetExitCodeThread returns TRUE");
    // code may be STILL_ACTIVE (259) or 42 if the thread already finished
    check(code == STILL_ACTIVE || code == 42,
          "GetExitCodeThread gives STILL_ACTIVE or final code");

    WaitForSingleObject(hThread, 1000);

    ok = GetExitCodeThread(hThread, &code);
    check(ok != FALSE,  "GetExitCodeThread after join returns TRUE");
    check(code == 42,   "GetExitCodeThread returns thread exit value (42)");

    CloseHandle(hThread);
}

// ── Group B: Process Management ───────────────────────────────────────────────

static void testB1_open_process_current()
{
    printf("\nTest B1: OpenProcess — current PID\n");
    DWORD pid = GetCurrentProcessId();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    check(hProc != NULL, "OpenProcess for current PID returns non-NULL");
    if (hProc && hProc != INVALID_HANDLE_VALUE) CloseHandle(hProc);
}

static void testB2_open_process_unknown()
{
    printf("\nTest B2: OpenProcess — unknown PID\n");
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 0xDEADBEEFU);
    check(hProc == NULL, "OpenProcess for unknown PID returns NULL");
}

static void testB3_get_process_times()
{
    printf("\nTest B3: GetProcessTimes\n");
    HANDLE hProc = GetCurrentProcess();
    FILETIME creation = {}, exit_t = {}, kernel_t = {}, user_t = {};
    BOOL ok = GetProcessTimes(hProc, &creation, &exit_t, &kernel_t, &user_t);
    check(ok != FALSE, "GetProcessTimes returns TRUE");
    ULONGLONG ct = ((ULONGLONG)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
    check(ct > 0, "creation time is non-zero");
}

// ── Group C: File Time APIs ────────────────────────────────────────────────────

// Helper: create a temp file and return its handle (must be CloseHandle'd by caller)
static HANDLE create_temp_file(wchar_t *out_path, DWORD /*out_len*/)
{
    wchar_t temp_dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_dir);
    GetTempFileNameW(temp_dir, L"p27", 0, out_path);
    return CreateFileW(out_path, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

static void testC1_get_file_time()
{
    printf("\nTest C1: GetFileTime\n");
    wchar_t path[MAX_PATH] = {};
    HANDLE h = create_temp_file(path, MAX_PATH);
    check(h != INVALID_HANDLE_VALUE, "CreateFileW succeeds for temp file");
    if (h == INVALID_HANDLE_VALUE) return;

    // Write something so mtime is set
    DWORD written = 0;
    WriteFile(h, "test", 4, &written, NULL);

    FILETIME ctime = {}, atime = {}, wtime = {};
    BOOL ok = GetFileTime(h, &ctime, &atime, &wtime);
    check(ok != FALSE, "GetFileTime returns TRUE");

    ULONGLONG wt = ((ULONGLONG)wtime.dwHighDateTime << 32) | wtime.dwLowDateTime;
    check(wt > 0, "write time is non-zero");

    CloseHandle(h);
    DeleteFileW(path);
}

static void testC2_compare_file_time()
{
    printf("\nTest C2: CompareFileTime\n");
    FILETIME earlier = {100, 0};
    FILETIME later   = {200, 0};
    FILETIME same    = {100, 0};

    check(CompareFileTime(&earlier, &later)  == -1, "earlier < later returns -1");
    check(CompareFileTime(&later,  &earlier) ==  1, "later > earlier returns +1");
    check(CompareFileTime(&earlier, &same)   ==  0, "equal times returns 0");
}

static void testC3_file_time_to_local()
{
    printf("\nTest C3: FileTimeToLocalFileTime\n");
    // Use a known UTC time (2024-01-01 00:00:00 UTC)
    // FILETIME = 100-ns intervals since 1601-01-01
    // 2024-01-01 00:00:00 UTC ≈ 133,484,736,000,000,000 (100-ns intervals)
    FILETIME utc = {};
    utc.dwLowDateTime  = 0x4E740000U;
    utc.dwHighDateTime = 0x01DA74B5U;

    FILETIME local = {};
    BOOL ok = FileTimeToLocalFileTime(&utc, &local);
    check(ok != FALSE, "FileTimeToLocalFileTime returns TRUE");

    ULONGLONG lv = ((ULONGLONG)local.dwHighDateTime << 32) | local.dwLowDateTime;
    check(lv > 0, "local file time is non-zero");
}

// ── Group D: System Directory / Temp File Name ────────────────────────────────

static void testD1_get_system_directory()
{
    printf("\nTest D1: GetSystemDirectoryW\n");
    wchar_t buf[MAX_PATH] = {};
    UINT len = GetSystemDirectoryW(buf, MAX_PATH);
    check(len > 0, "GetSystemDirectoryW returns non-zero length");
    // Should contain "System32" (any case)
    bool found = (wcsstr(buf, L"System32") != NULL ||
                  wcsstr(buf, L"system32") != NULL);
    check(found, "path contains 'System32'");
}

static void testD2_get_windows_directory()
{
    printf("\nTest D2: GetWindowsDirectoryW\n");
    wchar_t buf[MAX_PATH] = {};
    UINT len = GetWindowsDirectoryW(buf, MAX_PATH);
    check(len > 0, "GetWindowsDirectoryW returns non-zero length");
    bool found = (wcsstr(buf, L"Windows") != NULL ||
                  wcsstr(buf, L"windows") != NULL);
    check(found, "path contains 'Windows'");
}

static void testD3_get_temp_file_name()
{
    printf("\nTest D3: GetTempFileNameW\n");
    wchar_t temp_dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_dir);

    wchar_t out[MAX_PATH] = {};
    UINT result = GetTempFileNameW(temp_dir, L"p27", 0, out);
    check(result != 0, "GetTempFileNameW returns non-zero");

    // Name must end with ".tmp"
    size_t wlen = wcslen(out);
    bool ends_tmp = (wlen >= 4 &&
                     out[wlen-4] == L'.' &&
                     (out[wlen-3] == L't' || out[wlen-3] == L'T') &&
                     (out[wlen-2] == L'm' || out[wlen-2] == L'M') &&
                     (out[wlen-1] == L'p' || out[wlen-1] == L'P'));
    check(ends_tmp, "generated name ends with '.tmp'");

    // Clean up the file if it was created
    DeleteFileW(out);
}

// ── Group E: Character Conversion (USER32) ────────────────────────────────────

static void testE1_char_upper_lower_w_single()
{
    printf("\nTest E1: CharUpperW / CharLowerW — single-character mode\n");

    // Pass character as low word of a pointer (high word = 0)
    WCHAR upper_a = (WCHAR)(ULONG_PTR)CharUpperW((LPWSTR)(ULONG_PTR)L'a');
    check(upper_a == L'A', "CharUpperW('a') == 'A'");

    WCHAR lower_z = (WCHAR)(ULONG_PTR)CharLowerW((LPWSTR)(ULONG_PTR)L'Z');
    check(lower_z == L'z', "CharLowerW('Z') == 'z'");

    // Non-alpha characters unchanged
    WCHAR upper_digit = (WCHAR)(ULONG_PTR)CharUpperW((LPWSTR)(ULONG_PTR)L'3');
    check(upper_digit == L'3', "CharUpperW('3') == '3' (unchanged)");
}

static void testE2_char_upper_lower_w_string()
{
    printf("\nTest E2: CharUpperW / CharLowerW — string mode (in-place)\n");

    wchar_t hello[] = L"hello";
    LPWSTR ret = CharUpperW(hello);
    check(ret == hello, "CharUpperW returns the same pointer");
    check(wcscmp(hello, L"HELLO") == 0, "CharUpperW converts string to uppercase");

    wchar_t world[] = L"WORLD";
    ret = CharLowerW(world);
    check(ret == world, "CharLowerW returns the same pointer");
    check(wcscmp(world, L"world") == 0, "CharLowerW converts string to lowercase");
}

static void testE3_char_upper_lower_a_single()
{
    printf("\nTest E3: CharUpperA / CharLowerA — single-character mode\n");

    CHAR upper_a = (CHAR)(ULONG_PTR)CharUpperA((LPSTR)(ULONG_PTR)'a');
    check(upper_a == 'A', "CharUpperA('a') == 'A'");

    CHAR lower_z = (CHAR)(ULONG_PTR)CharLowerA((LPSTR)(ULONG_PTR)'Z');
    check(lower_z == 'z', "CharLowerA('Z') == 'z'");
}

// ── Group F: Character Classification (USER32) ───────────────────────────────

static void testF1_is_char_alpha()
{
    printf("\nTest F1: IsCharAlphaW\n");
    check(IsCharAlphaW(L'A') != FALSE, "IsCharAlphaW('A') is TRUE");
    check(IsCharAlphaW(L'z') != FALSE, "IsCharAlphaW('z') is TRUE");
    check(IsCharAlphaW(L'0') == FALSE, "IsCharAlphaW('0') is FALSE");
    check(IsCharAlphaW(L'!') == FALSE, "IsCharAlphaW('!') is FALSE");
}

static void testF2_is_char_alphanumeric()
{
    printf("\nTest F2: IsCharAlphaNumericW\n");
    check(IsCharAlphaNumericW(L'A') != FALSE, "IsCharAlphaNumericW('A') is TRUE");
    check(IsCharAlphaNumericW(L'5') != FALSE, "IsCharAlphaNumericW('5') is TRUE");
    check(IsCharAlphaNumericW(L'!') == FALSE, "IsCharAlphaNumericW('!') is FALSE");
}

static void testF3_is_char_case()
{
    printf("\nTest F3: IsCharUpperW / IsCharLowerW\n");
    check(IsCharUpperW(L'A') != FALSE, "IsCharUpperW('A') is TRUE");
    check(IsCharUpperW(L'a') == FALSE, "IsCharUpperW('a') is FALSE");
    check(IsCharLowerW(L'a') != FALSE, "IsCharLowerW('a') is TRUE");
    check(IsCharLowerW(L'A') == FALSE, "IsCharLowerW('A') is FALSE");
    check(IsCharUpperW(L'5') == FALSE, "IsCharUpperW('5') is FALSE (digit is not upper)");
    check(IsCharLowerW(L'5') == FALSE, "IsCharLowerW('5') is FALSE (digit is not lower)");
}

// ── Group G: Window Utilities (USER32 headless) ───────────────────────────────

static void testG1_is_window_queries()
{
    printf("\nTest G1: IsWindow / IsWindowEnabled / IsWindowVisible\n");
    HWND fake = (HWND)(ULONG_PTR)0x1234;

    // In headless mode all three return FALSE
    check(IsWindow(fake) == FALSE,        "IsWindow(fake) is FALSE (headless)");
    check(IsWindowEnabled(fake) == FALSE,  "IsWindowEnabled(fake) is FALSE (headless)");
    check(IsWindowVisible(fake) == FALSE,  "IsWindowVisible(fake) is FALSE (headless)");
}

static void testG2_enable_window()
{
    printf("\nTest G2: EnableWindow\n");
    HWND fake = (HWND)(ULONG_PTR)0x1234;
    BOOL prev = EnableWindow(fake, TRUE);
    check(prev == FALSE, "EnableWindow returns FALSE (headless: window was 'disabled')");
}

static void testG3_window_text()
{
    printf("\nTest G3: GetWindowTextW / SetWindowTextW\n");
    HWND fake = (HWND)(ULONG_PTR)0x1234;

    BOOL ok = SetWindowTextW(fake, L"Hello");
    check(ok == FALSE, "SetWindowTextW returns FALSE (headless: no real window)");

    wchar_t buf[64] = {};
    int len = GetWindowTextW(fake, buf, 64);
    check(len == 0, "GetWindowTextW returns 0 (no window text in headless mode)");
    check(buf[0] == L'\0', "GetWindowTextW null-terminates buffer");
}

static void testG4_get_parent()
{
    printf("\nTest G4: GetParent\n");
    HWND fake = (HWND)(ULONG_PTR)0x1234;
    HWND parent = GetParent(fake);
    check(parent == NULL, "GetParent returns NULL (headless: no parent)");
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(void)
{
    printf("=== Phase 27 Windows API Tests ===\n");

    // Group A: Thread Management
    testA1_set_get_thread_priority();
    testA2_suspend_resume();
    testA3_open_thread_exit_code();

    // Group B: Process Management
    testB1_open_process_current();
    testB2_open_process_unknown();
    testB3_get_process_times();

    // Group C: File Time APIs
    testC1_get_file_time();
    testC2_compare_file_time();
    testC3_file_time_to_local();

    // Group D: System Directory / Temp File Name
    testD1_get_system_directory();
    testD2_get_windows_directory();
    testD3_get_temp_file_name();

    // Group E: Character Conversion
    testE1_char_upper_lower_w_single();
    testE2_char_upper_lower_w_string();
    testE3_char_upper_lower_a_single();

    // Group F: Character Classification
    testF1_is_char_alpha();
    testF2_is_char_alphanumeric();
    testF3_is_char_case();

    // Group G: Window Utilities (headless)
    testG1_is_window_queries();
    testG2_enable_window();
    testG3_window_text();
    testG4_get_parent();

    printf("\n=== Phase 27 Windows API Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
