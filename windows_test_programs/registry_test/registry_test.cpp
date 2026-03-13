// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Windows Registry API Tests
//
// Exercises the ADVAPI32 registry APIs emulated by LiteBox:
//
//   Test 1:  RegCreateKeyExW — create a new key, confirm REG_CREATED_NEW_KEY
//   Test 2:  RegCreateKeyExW — re-open an existing key, confirm REG_OPENED_EXISTING_KEY
//   Test 3:  RegOpenKeyExW — open an existing key
//   Test 4:  RegOpenKeyExW — open a non-existent key, expect ERROR_FILE_NOT_FOUND
//   Test 5:  RegOpenKeyExW — open a predefined root key (HKEY_CURRENT_USER)
//   Test 6:  RegSetValueExW / RegQueryValueExW — REG_DWORD round-trip
//   Test 7:  RegSetValueExW / RegQueryValueExW — REG_SZ round-trip
//   Test 8:  RegSetValueExW / RegQueryValueExW — REG_QWORD round-trip
//   Test 9:  RegSetValueExW / RegQueryValueExW — REG_BINARY round-trip
//   Test 10: RegQueryValueExW — buffer too small returns ERROR_MORE_DATA
//   Test 11: RegDeleteValueW — delete a value, confirm gone
//   Test 12: RegEnumValueW — enumerate values in a key
//   Test 13: RegCreateKeyExW — create child keys and enumerate via RegEnumKeyExW
//   Test 14: RegCreateKeyExW — case-insensitive key lookup
//   Test 15: RegCloseKey — close a handle twice (second close should still succeed)

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

// Root for all test keys — placed under HKCU so no admin rights are needed.
static const wchar_t *TEST_ROOT = L"Software\\LiteBoxRegistryTest";

// ── Helpers ───────────────────────────────────────────────────────────────────

// Open (or create) the test root key and return the handle.
static HKEY open_test_root()
{
    HKEY hk = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER, TEST_ROOT,
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL);
    return hk;
}

// ── Test implementations ──────────────────────────────────────────────────────

static void test1_create_key_new()
{
    printf("\nTest 1: RegCreateKeyExW — new key\n");

    HKEY hk   = NULL;
    DWORD disp = 0;
    LSTATUS rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                                 L"Software\\LiteBoxRegistryTest\\T1",
                                 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, &disp);
    check(rc == ERROR_SUCCESS,       "RegCreateKeyExW returns ERROR_SUCCESS");
    check(hk  != NULL,               "returned handle is non-NULL");
    check(disp == REG_CREATED_NEW_KEY, "disposition == REG_CREATED_NEW_KEY");
    if (hk) RegCloseKey(hk);
}

static void test2_create_key_existing()
{
    printf("\nTest 2: RegCreateKeyExW — re-open existing key\n");

    // First creation
    HKEY hk1 = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\LiteBoxRegistryTest\\T2",
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk1, NULL);
    if (hk1) RegCloseKey(hk1);

    // Second creation of the same key
    HKEY  hk2  = NULL;
    DWORD disp  = 0;
    LSTATUS rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                                 L"Software\\LiteBoxRegistryTest\\T2",
                                 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk2, &disp);
    check(rc == ERROR_SUCCESS,           "RegCreateKeyExW returns ERROR_SUCCESS");
    check(disp == REG_OPENED_EXISTING_KEY, "disposition == REG_OPENED_EXISTING_KEY");
    if (hk2) RegCloseKey(hk2);
}

static void test3_open_existing_key()
{
    printf("\nTest 3: RegOpenKeyExW — open an existing key\n");

    // Ensure the key exists
    HKEY hk_tmp = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\LiteBoxRegistryTest\\T3",
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk_tmp, NULL);
    if (hk_tmp) RegCloseKey(hk_tmp);

    HKEY    hk = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\LiteBoxRegistryTest\\T3",
                               0, KEY_READ, &hk);
    check(rc == ERROR_SUCCESS, "RegOpenKeyExW returns ERROR_SUCCESS");
    check(hk != NULL,          "returned handle is non-NULL");
    if (hk) RegCloseKey(hk);
}

static void test4_open_nonexistent_key()
{
    printf("\nTest 4: RegOpenKeyExW — non-existent key returns ERROR_FILE_NOT_FOUND\n");

    HKEY    hk = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                               L"Software\\LiteBoxRegistryTest\\DoesNotExistXYZ",
                               0, KEY_READ, &hk);
    check(rc == ERROR_FILE_NOT_FOUND, "RegOpenKeyExW returns ERROR_FILE_NOT_FOUND");
    if (hk) RegCloseKey(hk);
}

static void test5_open_root_hkey()
{
    printf("\nTest 5: RegOpenKeyExW — open predefined root key\n");

    HKEY    hk = NULL;
    LSTATUS rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"", 0, KEY_READ, &hk);
    check(rc == ERROR_SUCCESS, "RegOpenKeyExW(HKEY_CURRENT_USER, \"\") returns ERROR_SUCCESS");
    check(hk != NULL,          "returned handle is non-NULL");
    if (hk) RegCloseKey(hk);
}

static void test6_dword_roundtrip()
{
    printf("\nTest 6: REG_DWORD round-trip\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    const DWORD write_val = 0xDEADBEEFul;
    LSTATUS rc = RegSetValueExW(hk, L"DwordVal", 0, REG_DWORD,
                                reinterpret_cast<const BYTE *>(&write_val),
                                sizeof(write_val));
    check(rc == ERROR_SUCCESS, "RegSetValueExW(REG_DWORD) returns ERROR_SUCCESS");

    DWORD read_val  = 0;
    DWORD val_type  = 0;
    DWORD data_size = sizeof(read_val);
    rc = RegQueryValueExW(hk, L"DwordVal", NULL, &val_type,
                          reinterpret_cast<BYTE *>(&read_val), &data_size);
    check(rc == ERROR_SUCCESS,       "RegQueryValueExW returns ERROR_SUCCESS");
    check(val_type == REG_DWORD,     "type == REG_DWORD");
    check(read_val == write_val,     "read value matches written value");
    check(data_size == sizeof(DWORD), "data_size == 4");

    RegCloseKey(hk);
}

static void test7_string_roundtrip()
{
    printf("\nTest 7: REG_SZ round-trip\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    const wchar_t *write_str = L"Hello, LiteBox Registry!";
    DWORD write_bytes = static_cast<DWORD>((wcslen(write_str) + 1) * sizeof(wchar_t));
    LSTATUS rc = RegSetValueExW(hk, L"StringVal", 0, REG_SZ,
                                reinterpret_cast<const BYTE *>(write_str),
                                write_bytes);
    check(rc == ERROR_SUCCESS, "RegSetValueExW(REG_SZ) returns ERROR_SUCCESS");

    // First query: size only
    DWORD val_type  = 0;
    DWORD data_size = 0;
    rc = RegQueryValueExW(hk, L"StringVal", NULL, &val_type, NULL, &data_size);
    check(rc == ERROR_SUCCESS, "RegQueryValueExW(size only) returns ERROR_SUCCESS");
    check(val_type == REG_SZ,  "type == REG_SZ");
    check(data_size >= write_bytes, "reported size >= written bytes");

    // Second query: actual data
    wchar_t buf[256] = {};
    data_size = sizeof(buf);
    rc = RegQueryValueExW(hk, L"StringVal", NULL, &val_type,
                          reinterpret_cast<BYTE *>(buf), &data_size);
    check(rc == ERROR_SUCCESS,         "RegQueryValueExW(data) returns ERROR_SUCCESS");
    check(wcscmp(buf, write_str) == 0, "read string matches written string");

    RegCloseKey(hk);
}

static void test8_qword_roundtrip()
{
    printf("\nTest 8: REG_QWORD round-trip\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    const ULONGLONG write_val = 0x0123456789ABCDEFull;
    LSTATUS rc = RegSetValueExW(hk, L"QwordVal", 0, REG_QWORD,
                                reinterpret_cast<const BYTE *>(&write_val),
                                sizeof(write_val));
    check(rc == ERROR_SUCCESS, "RegSetValueExW(REG_QWORD) returns ERROR_SUCCESS");

    ULONGLONG read_val  = 0;
    DWORD     val_type  = 0;
    DWORD     data_size = sizeof(read_val);
    rc = RegQueryValueExW(hk, L"QwordVal", NULL, &val_type,
                          reinterpret_cast<BYTE *>(&read_val), &data_size);
    check(rc == ERROR_SUCCESS,           "RegQueryValueExW returns ERROR_SUCCESS");
    check(val_type == REG_QWORD,         "type == REG_QWORD");
    check(read_val == write_val,         "read value matches written value");
    check(data_size == sizeof(ULONGLONG), "data_size == 8");

    RegCloseKey(hk);
}

static void test9_binary_roundtrip()
{
    printf("\nTest 9: REG_BINARY round-trip\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    const BYTE write_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    LSTATUS rc = RegSetValueExW(hk, L"BinaryVal", 0, REG_BINARY,
                                write_data, sizeof(write_data));
    check(rc == ERROR_SUCCESS, "RegSetValueExW(REG_BINARY) returns ERROR_SUCCESS");

    BYTE  read_data[16] = {};
    DWORD val_type  = 0;
    DWORD data_size = sizeof(read_data);
    rc = RegQueryValueExW(hk, L"BinaryVal", NULL, &val_type,
                          read_data, &data_size);
    check(rc == ERROR_SUCCESS,                             "RegQueryValueExW returns ERROR_SUCCESS");
    check(val_type == REG_BINARY,                          "type == REG_BINARY");
    check(data_size == sizeof(write_data),                 "data_size matches");
    check(memcmp(read_data, write_data, sizeof(write_data)) == 0, "data matches byte-for-byte");

    RegCloseKey(hk);
}

static void test10_buffer_too_small()
{
    printf("\nTest 10: RegQueryValueExW — buffer too small\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    // Write a known string value
    const wchar_t *s = L"SomeValue";
    RegSetValueExW(hk, L"SmallBuf", 0, REG_SZ,
                   reinterpret_cast<const BYTE *>(s),
                   static_cast<DWORD>((wcslen(s) + 1) * sizeof(wchar_t)));

    // Provide a 1-byte buffer — far too small
    BYTE  tiny_buf[1] = {};
    DWORD val_type    = 0;
    DWORD data_size   = sizeof(tiny_buf);
    LSTATUS rc = RegQueryValueExW(hk, L"SmallBuf", NULL, &val_type,
                                  tiny_buf, &data_size);
    check(rc == ERROR_MORE_DATA, "returns ERROR_MORE_DATA when buffer is too small");
    check(data_size > sizeof(tiny_buf), "data_size updated to required size");

    RegCloseKey(hk);
}

static void test11_delete_value()
{
    printf("\nTest 11: RegDeleteValueW\n");

    HKEY hk = open_test_root();
    if (!hk) { check(false, "open_test_root"); return; }

    // Write a value
    DWORD val = 42;
    RegSetValueExW(hk, L"ToDelete", 0, REG_DWORD,
                   reinterpret_cast<const BYTE *>(&val), sizeof(val));

    // Delete it
    LSTATUS rc = RegDeleteValueW(hk, L"ToDelete");
    check(rc == ERROR_SUCCESS, "RegDeleteValueW returns ERROR_SUCCESS");

    // Query after deletion should fail
    DWORD dummy     = 0;
    DWORD val_type  = 0;
    DWORD data_size = sizeof(dummy);
    rc = RegQueryValueExW(hk, L"ToDelete", NULL, &val_type,
                          reinterpret_cast<BYTE *>(&dummy), &data_size);
    check(rc == ERROR_FILE_NOT_FOUND, "query after delete returns ERROR_FILE_NOT_FOUND");

    // Deleting a non-existent value also returns ERROR_FILE_NOT_FOUND
    rc = RegDeleteValueW(hk, L"NeverExisted");
    check(rc == ERROR_FILE_NOT_FOUND,
          "delete of non-existent value returns ERROR_FILE_NOT_FOUND");

    RegCloseKey(hk);
}

static void test12_enum_values()
{
    printf("\nTest 12: RegEnumValueW\n");

    // Use a dedicated key for this test to keep values predictable
    HKEY hk = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\LiteBoxRegistryTest\\T12",
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL);
    if (!hk) { check(false, "create key T12"); return; }

    // Write two values
    DWORD v0 = 100, v1 = 200;
    RegSetValueExW(hk, L"Alpha", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&v0), 4);
    RegSetValueExW(hk, L"Beta",  0, REG_DWORD, reinterpret_cast<const BYTE *>(&v1), 4);

    // Enumerate index 0
    wchar_t name_buf[64] = {};
    DWORD   name_len     = 64;
    DWORD   val_type     = 0;
    BYTE    data_buf[4]  = {};
    DWORD   data_size    = 4;
    LSTATUS rc = RegEnumValueW(hk, 0,
                               name_buf, &name_len,
                               NULL, &val_type,
                               data_buf, &data_size);
    check(rc == ERROR_SUCCESS,   "RegEnumValueW index 0 returns ERROR_SUCCESS");
    check(name_len > 0,          "name_len > 0 for index 0");
    check(val_type == REG_DWORD, "type == REG_DWORD for index 0");

    // Enumerate index 1
    memset(name_buf, 0, sizeof(name_buf));
    name_len  = 64;
    val_type  = 0;
    data_size = 4;
    rc = RegEnumValueW(hk, 1,
                       name_buf, &name_len,
                       NULL, &val_type,
                       data_buf, &data_size);
    check(rc == ERROR_SUCCESS,   "RegEnumValueW index 1 returns ERROR_SUCCESS");
    check(name_len > 0,          "name_len > 0 for index 1");

    // Enumerate index 2 — should be out of range
    memset(name_buf, 0, sizeof(name_buf));
    name_len = 64;
    rc = RegEnumValueW(hk, 2,
                       name_buf, &name_len,
                       NULL, NULL, NULL, NULL);
    check(rc == ERROR_NO_MORE_ITEMS, "RegEnumValueW index 2 returns ERROR_NO_MORE_ITEMS");

    RegCloseKey(hk);
}

static void test13_enum_sub_keys()
{
    printf("\nTest 13: RegEnumKeyExW — enumerate sub-keys\n");

    // Create a parent key
    HKEY hk_parent = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\LiteBoxRegistryTest\\T13",
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk_parent, NULL);
    if (!hk_parent) { check(false, "create key T13"); return; }

    // Create two child keys under the parent handle
    const wchar_t *children[] = {L"ChildA", L"ChildB"};
    for (const wchar_t *child : children) {
        HKEY hk_child = NULL;
        RegCreateKeyExW(hk_parent, child,
                        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk_child, NULL);
        if (hk_child) RegCloseKey(hk_child);
    }

    // Enumerate index 0
    wchar_t name_buf[64] = {};
    DWORD   name_len     = 64;
    LSTATUS rc = RegEnumKeyExW(hk_parent, 0,
                               name_buf, &name_len,
                               NULL, NULL, NULL, NULL);
    check(rc == ERROR_SUCCESS, "RegEnumKeyExW index 0 returns ERROR_SUCCESS");
    check(name_len > 0,        "name_len > 0 for index 0");

    // Enumerate index 1
    memset(name_buf, 0, sizeof(name_buf));
    name_len = 64;
    rc = RegEnumKeyExW(hk_parent, 1,
                       name_buf, &name_len,
                       NULL, NULL, NULL, NULL);
    check(rc == ERROR_SUCCESS, "RegEnumKeyExW index 1 returns ERROR_SUCCESS");

    // Enumerate index 2 — should be out of range
    memset(name_buf, 0, sizeof(name_buf));
    name_len = 64;
    rc = RegEnumKeyExW(hk_parent, 2,
                       name_buf, &name_len,
                       NULL, NULL, NULL, NULL);
    check(rc == ERROR_NO_MORE_ITEMS, "RegEnumKeyExW index 2 returns ERROR_NO_MORE_ITEMS");

    RegCloseKey(hk_parent);
}

static void test14_case_insensitive_lookup()
{
    printf("\nTest 14: Case-insensitive key lookup\n");

    // Create a key with mixed case
    HKEY hk_c = NULL;
    RegCreateKeyExW(HKEY_CURRENT_USER,
                    L"Software\\LiteBoxRegistryTest\\MixedCaseKey",
                    0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk_c, NULL);
    if (hk_c) RegCloseKey(hk_c);

    // Open with all-upper case
    HKEY    hk_u = NULL;
    LSTATUS rc   = RegOpenKeyExW(HKEY_CURRENT_USER,
                                 L"SOFTWARE\\LITEBOXREGISTRYTEST\\MIXEDCASEKEY",
                                 0, KEY_READ, &hk_u);
    check(rc == ERROR_SUCCESS, "open with upper-case path succeeds");
    if (hk_u) RegCloseKey(hk_u);

    // Open with all-lower case
    HKEY hk_l = NULL;
    rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                       L"software\\liteboxregistrytest\\mixedcasekey",
                       0, KEY_READ, &hk_l);
    check(rc == ERROR_SUCCESS, "open with lower-case path succeeds");
    if (hk_l) RegCloseKey(hk_l);
}

static void test15_close_handle()
{
    printf("\nTest 15: RegCloseKey\n");

    HKEY    hk = NULL;
    LSTATUS rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                                 L"Software\\LiteBoxRegistryTest\\T15",
                                 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL);
    check(rc == ERROR_SUCCESS, "create T15 succeeds");
    rc = RegCloseKey(hk);
    check(rc == ERROR_SUCCESS, "first RegCloseKey returns ERROR_SUCCESS");

    // Closing a predefined root key should always succeed
    rc = RegCloseKey(HKEY_CURRENT_USER);
    check(rc == ERROR_SUCCESS, "RegCloseKey(HKEY_CURRENT_USER) returns ERROR_SUCCESS");
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(void)
{
    printf("=== Windows Registry API Tests ===\n");

    test1_create_key_new();
    test2_create_key_existing();
    test3_open_existing_key();
    test4_open_nonexistent_key();
    test5_open_root_hkey();
    test6_dword_roundtrip();
    test7_string_roundtrip();
    test8_qword_roundtrip();
    test9_binary_roundtrip();
    test10_buffer_too_small();
    test11_delete_value();
    test12_enum_values();
    test13_enum_sub_keys();
    test14_case_insensitive_lookup();
    test15_close_handle();

    printf("\n=== Windows Registry API Tests %s (%d failure%s) ===\n",
           g_failures == 0 ? "PASSED" : "FAILED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
