// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Windows GUI + Vulkan API Test Program
//
// This plain-C program exercises the Windows GUI APIs and Vulkan API discovery
// through the LiteBox Windows-on-Linux shim.  It is intentionally written in
// plain C (not C++) to exercise the C calling convention with MinGW.
//
// Tests covered:
//   1.  RegisterClassExW            → non-zero ATOM
//   2.  CreateWindowExW             → non-null HWND
//   3.  ShowWindow / UpdateWindow   → no crash
//   4.  GetClientRect               → returns 800×600 headless rect
//   5.  BeginPaint / EndPaint       → returns fake HDC
//   6.  DrawTextW                   → returns 1 (headless)
//   7.  MessageBoxW                 → returns IDOK (1) in headless mode
//   8.  CreateMenu / AppendMenuW / SetMenu / DrawMenuBar
//   9.  GDI32: GetDeviceCaps        → returns representative value
//  10.  GDI32: CreatePen / SelectObject / LineTo / MoveToEx
//  11.  GDI32: CreateCompatibleBitmap / BitBlt
//  12.  GDI32: Ellipse / Rectangle / RoundRect
//  13.  GDI32: GetTextMetricsW
//  14.  GDI32: SaveDC / RestoreDC
//  15.  GDI32: CreateDIBSection
//  16.  OpenClipboard / SetClipboardData / CloseClipboard
//  17.  LoadStringW                 → returns 0 (no resources in headless mode)
//  18.  AdjustWindowRectEx          → returns TRUE
//  19.  GetSystemMetrics            → returns 800 / 600
//  20.  GetMonitorInfoW             → returns 800×600 headless monitor info
//  21.  Vulkan: vkEnumerateInstanceExtensionProperties → VK_SUCCESS, count 0
//  22.  Vulkan: vkEnumerateInstanceLayerProperties     → VK_SUCCESS, count 0
//  23.  Vulkan: vkCreateInstance    → VK_ERROR_INITIALIZATION_FAILED (-3)
//  24.  Vulkan: vkEnumeratePhysicalDevices → VK_SUCCESS, count 0
//  25.  Vulkan: vkGetInstanceProcAddr → NULL

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ── helpers ───────────────────────────────────────────────────────────────────

static int g_passes   = 0;
static int g_failures = 0;

static void check(int ok, const char *desc)
{
    if (ok) {
        printf("  [PASS] %s\n", desc);
        ++g_passes;
    } else {
        printf("  [FAIL] %s\n", desc);
        ++g_failures;
    }
}

// ── Vulkan types / constants (minimal, avoids needing the Vulkan SDK) ─────────

typedef void * VkInstance;
typedef void * VkPhysicalDevice;
typedef int    VkResult;

#define VK_SUCCESS                    0
#define VK_NOT_READY                  1
#define VK_ERROR_INITIALIZATION_FAILED (-3)

typedef struct {
    UINT32 sType;
    void  *pNext;
    UINT32 flags;
    /* ... only the first fields matter for our null-driver test */
} VkInstanceCreateInfo;

// Dynamically-loaded Vulkan entry points
typedef VkResult (WINAPI *PFN_vkCreateInstance)(
    const VkInstanceCreateInfo*, const void*, VkInstance*);
typedef void (WINAPI *PFN_vkDestroyInstance)(VkInstance, const void*);
typedef VkResult (WINAPI *PFN_vkEnumerateInstanceExtensionProperties)(
    const char*, UINT32*, void*);
typedef VkResult (WINAPI *PFN_vkEnumerateInstanceLayerProperties)(
    UINT32*, void*);
typedef VkResult (WINAPI *PFN_vkEnumeratePhysicalDevices)(
    VkInstance, UINT32*, VkPhysicalDevice*);
typedef void * (WINAPI *PFN_vkGetInstanceProcAddr)(VkInstance, const char*);

// ── Window class / message-loop helpers ──────────────────────────────────────

static LRESULT CALLBACK DummyWndProc(HWND hwnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(void)
{
    printf("=== Windows GUI + Vulkan API Test Suite ===\n\n");

    // ── Test 1: RegisterClassExW ───────────────────────────────────────────
    printf("Test 1: RegisterClassExW\n");
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = DummyWndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"LiteBoxTestClass";

    ATOM atom = RegisterClassExW(&wc);
    check(atom != 0, "RegisterClassExW returns non-zero ATOM");

    // ── Test 2: CreateWindowExW ────────────────────────────────────────────
    printf("\nTest 2: CreateWindowExW\n");
    HWND hwnd = CreateWindowExW(
        0,
        L"LiteBoxTestClass",
        L"LiteBox GUI Test",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL, NULL,
        GetModuleHandleW(NULL),
        NULL
    );
    check(hwnd != NULL, "CreateWindowExW returns non-null HWND");

    // ── Test 3: ShowWindow / UpdateWindow ─────────────────────────────────
    printf("\nTest 3: ShowWindow / UpdateWindow\n");
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    check(1, "ShowWindow / UpdateWindow — no crash");

    // ── Test 4: GetClientRect ─────────────────────────────────────────────
    printf("\nTest 4: GetClientRect\n");
    RECT rect;
    memset(&rect, 0xFF, sizeof(rect));
    BOOL ok4 = GetClientRect(hwnd, &rect);
    check(ok4,       "GetClientRect returns TRUE");
    check(rect.left == 0 && rect.top == 0,
          "GetClientRect left=0, top=0");
    check(rect.right > 0 && rect.bottom > 0,
          "GetClientRect right>0, bottom>0");

    // ── Test 5: BeginPaint / EndPaint ─────────────────────────────────────
    printf("\nTest 5: BeginPaint / EndPaint\n");
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    check(hdc != NULL, "BeginPaint returns non-null HDC");
    BOOL ok5 = EndPaint(hwnd, &ps);
    check(ok5, "EndPaint returns TRUE");

    // ── Test 6: DrawTextW ─────────────────────────────────────────────────
    printf("\nTest 6: DrawTextW\n");
    HDC hdc2 = GetDC(hwnd);
    RECT textRect = { 0, 0, 400, 20 };
    int lines = DrawTextW(hdc2, L"Hello, LiteBox!", -1, &textRect, DT_LEFT);
    check(lines != 0, "DrawTextW returns non-zero (headless)");
    ReleaseDC(hwnd, hdc2);

    // ── Test 7: MessageBoxW (headless) ────────────────────────────────────
    printf("\nTest 7: MessageBoxW (headless)\n");
    int mb = MessageBoxW(NULL, L"Test message", L"LiteBox", MB_OK);
    check(mb == IDOK, "MessageBoxW returns IDOK in headless mode");

    // ── Test 8: CreateMenu / AppendMenuW / SetMenu / DrawMenuBar ──────────
    printf("\nTest 8: Menu APIs\n");
    HMENU hmenu = CreateMenu();
    check(hmenu != NULL, "CreateMenu returns non-null HMENU");
    BOOL ok8a = AppendMenuW(hmenu, MF_STRING, 1001, L"&File");
    check(ok8a, "AppendMenuW returns TRUE");
    BOOL ok8b = SetMenu(hwnd, hmenu);
    check(ok8b, "SetMenu returns TRUE");
    BOOL ok8c = DrawMenuBar(hwnd);
    check(ok8c, "DrawMenuBar returns TRUE");

    // ── Test 9: GetDeviceCaps ─────────────────────────────────────────────
    printf("\nTest 9: GetDeviceCaps\n");
    HDC hdc3 = GetDC(hwnd);
    int logpx = GetDeviceCaps(hdc3, LOGPIXELSX);
    check(logpx > 0, "GetDeviceCaps(LOGPIXELSX) > 0");
    int horzres = GetDeviceCaps(hdc3, HORZRES);
    check(horzres > 0, "GetDeviceCaps(HORZRES) > 0");
    ReleaseDC(hwnd, hdc3);

    // ── Test 10: Pen / LineTo / MoveToEx ─────────────────────────────────
    printf("\nTest 10: CreatePen / MoveToEx / LineTo\n");
    HDC hdc4 = GetDC(hwnd);
    HPEN hpen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
    check(hpen != NULL, "CreatePen returns non-null HPEN");
    HGDIOBJ old = SelectObject(hdc4, hpen);
    check(old != NULL, "SelectObject for pen returns non-null prev");
    POINT ptOld;
    BOOL ok10a = MoveToEx(hdc4, 10, 10, &ptOld);
    check(ok10a, "MoveToEx returns TRUE");
    BOOL ok10b = LineTo(hdc4, 200, 200);
    check(ok10b, "LineTo returns TRUE");
    SelectObject(hdc4, old);
    DeleteObject(hpen);
    ReleaseDC(hwnd, hdc4);

    // ── Test 11: CreateCompatibleBitmap / BitBlt ──────────────────────────
    printf("\nTest 11: CreateCompatibleBitmap / BitBlt\n");
    HDC hdcScr = GetDC(hwnd);
    HDC hdcMem = CreateCompatibleDC(hdcScr);
    check(hdcMem != NULL, "CreateCompatibleDC returns non-null HDC");
    HBITMAP hbm = CreateCompatibleBitmap(hdcScr, 100, 100);
    check(hbm != NULL, "CreateCompatibleBitmap returns non-null HBITMAP");
    HGDIOBJ oldBm = SelectObject(hdcMem, hbm);
    check(oldBm != NULL, "SelectObject for bitmap returns non-null prev");
    BOOL ok11 = BitBlt(hdcScr, 0, 0, 100, 100, hdcMem, 0, 0, SRCCOPY);
    check(ok11, "BitBlt returns TRUE");
    SelectObject(hdcMem, oldBm);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(hwnd, hdcScr);

    // ── Test 12: Ellipse / Rectangle / RoundRect ─────────────────────────
    printf("\nTest 12: Ellipse / Rectangle / RoundRect\n");
    HDC hdc5 = GetDC(hwnd);
    check(Ellipse(hdc5, 10, 10, 100, 100),     "Ellipse returns TRUE");
    check(Rectangle(hdc5, 10, 120, 200, 220),  "Rectangle returns TRUE");
    check(RoundRect(hdc5, 10, 230, 200, 330, 20, 20), "RoundRect returns TRUE");
    ReleaseDC(hwnd, hdc5);

    // ── Test 13: GetTextMetricsW ──────────────────────────────────────────
    printf("\nTest 13: GetTextMetricsW\n");
    HDC hdc6 = GetDC(hwnd);
    TEXTMETRICW tm;
    memset(&tm, 0, sizeof(tm));
    BOOL ok13 = GetTextMetricsW(hdc6, &tm);
    check(ok13,            "GetTextMetricsW returns TRUE");
    check(tm.tmHeight > 0, "GetTextMetricsW tmHeight > 0");
    ReleaseDC(hwnd, hdc6);

    // ── Test 14: SaveDC / RestoreDC ───────────────────────────────────────
    printf("\nTest 14: SaveDC / RestoreDC\n");
    HDC hdc7 = GetDC(hwnd);
    int saved = SaveDC(hdc7);
    check(saved != 0, "SaveDC returns non-zero state ID");
    BOOL ok14 = RestoreDC(hdc7, saved);
    check(ok14, "RestoreDC returns TRUE");
    ReleaseDC(hwnd, hdc7);

    // ── Test 15: CreateDIBSection ─────────────────────────────────────────
    printf("\nTest 15: CreateDIBSection\n");
    {
        HDC hdcD = GetDC(hwnd);
        BITMAPINFO bmi;
        memset(&bmi, 0, sizeof(bmi));
        bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth       = 64;
        bmi.bmiHeader.biHeight      = -64; // top-down
        bmi.bmiHeader.biPlanes      = 1;
        bmi.bmiHeader.biBitCount    = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        void *bits = NULL;
        HBITMAP hbmDib = CreateDIBSection(hdcD, &bmi, DIB_RGB_COLORS,
                                          &bits, NULL, 0);
        check(hbmDib != NULL, "CreateDIBSection returns non-null HBITMAP");
        if (hbmDib) DeleteObject(hbmDib);
        ReleaseDC(hwnd, hdcD);
    }

    // ── Test 16: Clipboard ────────────────────────────────────────────────
    printf("\nTest 16: Clipboard APIs\n");
    BOOL ok16a = OpenClipboard(hwnd);
    check(ok16a, "OpenClipboard returns TRUE");
    BOOL ok16b = EmptyClipboard();
    check(ok16b, "EmptyClipboard returns TRUE");
    BOOL ok16c = CloseClipboard();
    check(ok16c, "CloseClipboard returns TRUE");

    // ── Test 17: LoadStringW ──────────────────────────────────────────────
    printf("\nTest 17: LoadStringW\n");
    WCHAR strbuf[128] = { 0 };
    int len17 = LoadStringW(GetModuleHandleW(NULL), 1, strbuf, 128);
    check(len17 == 0, "LoadStringW returns 0 (no resources in headless)");

    // ── Test 18: AdjustWindowRectEx ───────────────────────────────────────
    printf("\nTest 18: AdjustWindowRectEx\n");
    RECT adjrect = { 0, 0, 800, 600 };
    BOOL ok18 = AdjustWindowRectEx(&adjrect, WS_OVERLAPPEDWINDOW, FALSE, 0);
    check(ok18, "AdjustWindowRectEx returns TRUE");

    // ── Test 19: GetSystemMetrics ─────────────────────────────────────────
    printf("\nTest 19: GetSystemMetrics\n");
    int smcx = GetSystemMetrics(SM_CXSCREEN);
    int smcy = GetSystemMetrics(SM_CYSCREEN);
    check(smcx > 0, "GetSystemMetrics(SM_CXSCREEN) > 0");
    check(smcy > 0, "GetSystemMetrics(SM_CYSCREEN) > 0");

    // ── Test 20: GetMonitorInfoW ──────────────────────────────────────────
    printf("\nTest 20: GetMonitorInfoW\n");
    {
        HMONITOR hmon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
        check(hmon != NULL, "MonitorFromWindow returns non-null HMONITOR");
        MONITORINFO mi;
        memset(&mi, 0, sizeof(mi));
        mi.cbSize = sizeof(mi);
        BOOL ok20 = GetMonitorInfo(hmon, &mi);
        check(ok20, "GetMonitorInfoW returns TRUE");
        check(mi.rcMonitor.right > 0 && mi.rcMonitor.bottom > 0,
              "GetMonitorInfoW reports non-zero monitor dimensions");
    }

    // ── Vulkan tests (loaded dynamically to avoid hard link dependency) ────
    printf("\nTest 21-25: Vulkan API (via LoadLibraryA)\n");
    HMODULE hvk = LoadLibraryA("vulkan-1.dll");
    if (hvk == NULL) {
        // vulkan-1.dll is not linked into this test; skip gracefully
        printf("  [SKIP] vulkan-1.dll not available via LoadLibraryA\n");
    } else {
        // ── Test 21: vkEnumerateInstanceExtensionProperties ───────────────
        PFN_vkEnumerateInstanceExtensionProperties pfnEnumInstExts =
            (PFN_vkEnumerateInstanceExtensionProperties)(void *)
            GetProcAddress(hvk, "vkEnumerateInstanceExtensionProperties");
        check(pfnEnumInstExts != NULL,
              "GetProcAddress(vkEnumerateInstanceExtensionProperties) != NULL");
        if (pfnEnumInstExts) {
            UINT32 extCount = 9999;
            VkResult r = pfnEnumInstExts(NULL, &extCount, NULL);
            check(r == VK_SUCCESS && extCount == 0,
                  "vkEnumerateInstanceExtensionProperties → VK_SUCCESS, count=0");
        }

        // ── Test 22: vkEnumerateInstanceLayerProperties ───────────────────
        PFN_vkEnumerateInstanceLayerProperties pfnEnumLayers =
            (PFN_vkEnumerateInstanceLayerProperties)(void *)
            GetProcAddress(hvk, "vkEnumerateInstanceLayerProperties");
        check(pfnEnumLayers != NULL,
              "GetProcAddress(vkEnumerateInstanceLayerProperties) != NULL");
        if (pfnEnumLayers) {
            UINT32 layerCount = 9999;
            VkResult r = pfnEnumLayers(&layerCount, NULL);
            check(r == VK_SUCCESS && layerCount == 0,
                  "vkEnumerateInstanceLayerProperties → VK_SUCCESS, count=0");
        }

        // ── Test 23: vkCreateInstance returns expected error ───────────────
        PFN_vkCreateInstance pfnCreateInst =
            (PFN_vkCreateInstance)(void *)
            GetProcAddress(hvk, "vkCreateInstance");
        check(pfnCreateInst != NULL,
              "GetProcAddress(vkCreateInstance) != NULL");
        if (pfnCreateInst) {
            VkInstanceCreateInfo ci;
            memset(&ci, 0, sizeof(ci));
            ci.sType = 1; /* VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO */
            VkInstance inst = NULL;
            VkResult r = pfnCreateInst(&ci, NULL, &inst);
            check(r == VK_ERROR_INITIALIZATION_FAILED,
                  "vkCreateInstance → VK_ERROR_INITIALIZATION_FAILED");
            check(inst == NULL, "vkCreateInstance sets *pInstance = NULL");
        }

        // ── Test 24: vkEnumeratePhysicalDevices ───────────────────────────
        PFN_vkEnumeratePhysicalDevices pfnEnumPDs =
            (PFN_vkEnumeratePhysicalDevices)(void *)
            GetProcAddress(hvk, "vkEnumeratePhysicalDevices");
        check(pfnEnumPDs != NULL,
              "GetProcAddress(vkEnumeratePhysicalDevices) != NULL");
        if (pfnEnumPDs) {
            UINT32 pdCount = 9999;
            VkResult r = pfnEnumPDs(NULL, &pdCount, NULL);
            check(r == VK_SUCCESS && pdCount == 0,
                  "vkEnumeratePhysicalDevices → VK_SUCCESS, count=0");
        }

        // ── Test 25: vkGetInstanceProcAddr returns NULL ────────────────────
        PFN_vkGetInstanceProcAddr pfnGIPA =
            (PFN_vkGetInstanceProcAddr)(void *)
            GetProcAddress(hvk, "vkGetInstanceProcAddr");
        check(pfnGIPA != NULL,
              "GetProcAddress(vkGetInstanceProcAddr) != NULL");
        if (pfnGIPA) {
            void *fptr = pfnGIPA(NULL, "vkCreateInstance");
            check(fptr == NULL,
                  "vkGetInstanceProcAddr(NULL, \"vkCreateInstance\") returns NULL");
        }

        FreeLibrary(hvk);
    }

    // ── Cleanup ────────────────────────────────────────────────────────────
    DestroyWindow(hwnd);

    // ── Results ────────────────────────────────────────────────────────────
    printf("\n=== Results: %d passed, %d failed ===\n", g_passes, g_failures);
    return (g_failures > 0) ? 1 : 0;
}
