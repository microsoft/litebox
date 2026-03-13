// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// SEH C++ Test Program — clang-cl / MSVC ABI variant
//
// This C++ program exercises MSVC-style C++ exception handling
// (`_CxxThrowException` / `__CxxFrameHandler3`) through the LiteBox
// Windows-on-Linux shim.
//
// Unlike the MinGW/GCC variant (`seh_cpp_test.cpp`), this test is compiled
// with `clang++ --target=x86_64-pc-windows-msvc` and generates MSVC-compatible
// exception handling tables (FuncInfo, TryBlockMap, HandlerType, etc.).
// It does NOT depend on MSVC headers or the MSVC CRT — all needed
// declarations are provided inline, making it fully self-contained for
// cross-compilation on Linux.
//
// Tests covered:
//   1.  throw int / catch(int)
//   2.  throw double / catch(double)
//   3.  throw const char* / catch(const char*)
//   4.  Rethrowing with throw; from a catch block
//   5.  catch(...) — catch-all handler
//   6.  Stack unwinding — destructors are called when exception propagates
//   7.  Nested try/catch blocks
//   8.  Exception propagates across multiple stack frames
//   9.  Multiple catch clauses — correct one is selected
//  10.  Exception through indirect (function pointer) call
//
// Build (on Linux):
//   make seh_cpp_test_msvc.exe
//
// Prerequisites:
//   clang (with x86_64-pc-windows-msvc target support)
//   lld-link (LLVM linker)
//   llvm-dlltool (for generating import libraries)

// ── Minimal runtime declarations (no MSVC headers needed) ────────────────────

extern "C" {
    // From msvcrt.dll / ucrtbase.dll
    int printf(const char *fmt, ...);
    int puts(const char *s);

    // Process control
    [[noreturn]] void exit(int status);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static int g_passes   = 0;
static int g_failures = 0;

// Write a small integer (0–999) to stdout using puts
static void print_int(int n)
{
    char buf[16];
    int i = 0;
    if (n < 0) { buf[i++] = '-'; n = -n; }
    if (n == 0) { buf[i++] = '0'; }
    else {
        char tmp[16];
        int j = 0;
        while (n > 0) { tmp[j++] = (char)('0' + (n % 10)); n /= 10; }
        while (j > 0) { buf[i++] = tmp[--j]; }
    }
    buf[i] = '\0';
    printf(buf);
}

static void pass(const char *desc)
{
    printf("  [PASS] ");
    printf(desc);
    printf("\n");
    ++g_passes;
}

static void fail(const char *desc)
{
    printf("  [FAIL] ");
    printf(desc);
    printf("\n");
    ++g_failures;
}

static void check(bool ok, const char *desc)
{
    if (ok) pass(desc); else fail(desc);
}

// Simple C-string comparison (no strcmp dependency)
static bool streq(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && *b) {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}

// ── Test 1: throw int / catch(int) ───────────────────────────────────────────

static void test1_throw_int()
{
    printf("\nTest 1: throw int / catch(int)\n");
    bool caught = false;
    int  value  = 0;

    try {
        throw 42;
    } catch (int v) {
        caught = true;
        value  = v;
    }

    check(caught,      "catch(int) handler entered");
    check(value == 42, "thrown int value is 42");
}

// ── Test 2: throw double / catch(double) ─────────────────────────────────────

static void test2_throw_double()
{
    printf("\nTest 2: throw double / catch(double)\n");
    bool   caught = false;
    double value  = 0.0;

    try {
        throw 3.14;
    } catch (double v) {
        caught = true;
        value  = v;
    }

    check(caught, "catch(double) handler entered");
    // Compare with small epsilon
    check(value > 3.13 && value < 3.15, "thrown double value is ~3.14");
}

// ── Test 3: throw const char* / catch(const char*) ───────────────────────────

static void test3_throw_cstring()
{
    printf("\nTest 3: throw const char* / catch(const char*)\n");
    bool caught = false;
    const char *msg = nullptr;

    try {
        throw "hello from MSVC C++";
    } catch (const char *s) {
        caught = true;
        msg    = s;
    }

    check(caught, "catch(const char*) handler entered");
    check(streq(msg, "hello from MSVC C++"), "thrown string value correct");
}

// ── Test 4: rethrow with throw; ──────────────────────────────────────────────

static void test4_rethrow()
{
    printf("\nTest 4: rethrow with throw;\n");
    bool inner_caught = false;
    bool outer_caught = false;
    int  val          = 0;

    try {
        try {
            throw 99;
        } catch (int v) {
            inner_caught = true;
            val          = v;
            throw;  // rethrow
        }
    } catch (int v) {
        outer_caught = true;
        val          = v;
    }

    check(inner_caught, "inner catch(int) was entered before rethrow");
    check(outer_caught, "outer catch(int) received the rethrown exception");
    check(val == 99,    "rethrown exception value is 99");
}

// ── Test 5: catch(...) catch-all ─────────────────────────────────────────────

static void test5_catch_all()
{
    printf("\nTest 5: catch(...) catch-all handler\n");
    bool caught = false;

    try {
        throw 3.14;
    } catch (...) {
        caught = true;
    }

    check(caught, "catch(...) handler entered for double throw");
}

// ── Test 6: stack unwinding — destructors are called ─────────────────────────

static int g_dtor_count = 0;

struct Tracker {
    explicit Tracker(int /*id*/) { }
    ~Tracker() { ++g_dtor_count; }
};

static void throw_with_trackers()
{
    Tracker t1(1);
    Tracker t2(2);
    Tracker t3(3);
    throw 42;
    // t3, t2, t1 destructors must run
}

static void test6_stack_unwinding()
{
    printf("\nTest 6: stack unwinding - destructors called during exception propagation\n");
    g_dtor_count = 0;
    bool caught  = false;

    try {
        throw_with_trackers();
    } catch (int) {
        caught = true;
    }

    check(caught,            "exception caught by caller");
    check(g_dtor_count == 3, "all 3 Tracker destructors ran during unwinding");
}

// ── Test 7: nested try/catch ─────────────────────────────────────────────────

static void test7_nested()
{
    printf("\nTest 7: nested try/catch blocks\n");
    bool inner_caught = false;
    bool outer_caught = false;

    try {
        try {
            throw 100;
        } catch (int) {
            inner_caught = true;
            throw 200;  // throw a new exception from the catch block
        }
    } catch (int v) {
        outer_caught = (v == 200);
    }

    check(inner_caught, "inner catch(int) entered");
    check(outer_caught, "outer catch(int) caught exception from inner handler");
}

// ── Test 8: exception from called function caught by caller ──────────────────

static void deep_throw(int depth)
{
    if (depth == 0) throw -1;
    deep_throw(depth - 1);
}

static void test8_cross_function()
{
    printf("\nTest 8: exception propagates across multiple stack frames\n");
    bool caught = false;
    int  value  = 0;

    try {
        deep_throw(5);
    } catch (int v) {
        caught = true;
        value  = v;
    }

    check(caught,       "exception propagated across 5 stack frames");
    check(value == -1,  "exception value preserved across frames");
}

// ── Test 9: multiple catch clauses — correct one is selected ─────────────────

static void test9_multiple_catch()
{
    printf("\nTest 9: multiple catch clauses - correct one selected\n");

    // throw int -> catch int (not double, not ...)
    {
        int which = 0;
        try {
            throw 7;
        } catch (double) {
            which = 1;
        } catch (int) {
            which = 2;
        } catch (...) {
            which = 3;
        }
        check(which == 2, "catch(int) selected when int is thrown");
    }

    // throw double -> catch double
    {
        int which = 0;
        try {
            throw 1.5;
        } catch (int) {
            which = 1;
        } catch (double) {
            which = 2;
        } catch (...) {
            which = 3;
        }
        check(which == 2, "catch(double) selected when double is thrown");
    }

    // throw const char* -> catch(...)
    {
        int which = 0;
        try {
            throw "oops";
        } catch (int) {
            which = 1;
        } catch (double) {
            which = 2;
        } catch (...) {
            which = 3;
        }
        check(which == 3, "catch(...) selected when const char* is thrown");
    }
}

// ── Test 10: C++ exception through indirect call ─────────────────────────────

static void throwing_callback()
{
    throw -42;
}

static void test10_exception_through_callback()
{
    printf("\nTest 10: C++ exception propagates through an indirect function call\n");
    bool caught = false;
    int  value  = 0;

    try {
        void (*fn)() = throwing_callback;
        fn();
    } catch (int v) {
        caught = true;
        value  = v;
    }

    check(caught,       "exception from called function caught by caller");
    check(value == -42, "exception value preserved");
}

// ── main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== SEH C++ Test Suite (MSVC ABI / clang-cl) ===\n");
    printf("Tests MSVC-style C++ exception handling on Windows x64\n");
    printf("(Uses _CxxThrowException / __CxxFrameHandler3)\n");

    test1_throw_int();
    test2_throw_double();
    test3_throw_cstring();
    test4_rethrow();
    test5_catch_all();
    test6_stack_unwinding();
    test7_nested();
    test8_cross_function();
    test9_multiple_catch();
    test10_exception_through_callback();

    // Print results using character output to avoid printf format specifier issues
    printf("\n=== Results: ");
    print_int(g_passes);
    printf(" passed, ");
    print_int(g_failures);
    printf(" failed ===\n");

    return (g_failures > 0) ? 1 : 0;
}
