#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Build seh_cpp_test_msvc.exe using clang++ targeting x86_64-pc-windows-msvc.
#
# This produces a PE executable that uses MSVC-style C++ exception handling
# (_CxxThrowException / __CxxFrameHandler3) instead of the GCC/MinGW-style
# (_GCC_specific_handler / _Unwind_Resume).
#
# Prerequisites:
#   clang (with x86_64-pc-windows-msvc target support)
#   lld-link (LLVM linker — typically from the lld package)
#   llvm-dlltool (for generating .lib import libraries from .def files)
#
# Usage:
#   ./build_msvc.sh          # build seh_cpp_test_msvc.exe
#   ./build_msvc.sh clean    # remove build artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_msvc"
OUTPUT="${SCRIPT_DIR}/seh_cpp_test_msvc.exe"
SOURCE="${SCRIPT_DIR}/seh_cpp_test_msvc.cpp"

# ── Tool detection ────────────────────────────────────────────────────────────

find_tool() {
    local name="$1"
    # Try versioned names first (18, 17, 16), then unversioned
    for suffix in -18 -17 -16 ""; do
        if command -v "${name}${suffix}" &>/dev/null; then
            echo "${name}${suffix}"
            return 0
        fi
    done
    echo "ERROR: ${name} not found (tried ${name}-18, ${name}-17, ${name}-16, ${name})" >&2
    return 1
}

CLANGXX=$(find_tool clang++)
LLD_LINK=$(find_tool lld-link)
LLVM_DLLTOOL=$(find_tool llvm-dlltool)

# ── Clean mode ────────────────────────────────────────────────────────────────

if [[ "${1:-}" == "clean" ]]; then
    rm -rf "${BUILD_DIR}" "${OUTPUT}"
    echo "Cleaned build_msvc/ and seh_cpp_test_msvc.exe"
    exit 0
fi

# ── Build ─────────────────────────────────────────────────────────────────────

mkdir -p "${BUILD_DIR}"

echo "=== Building seh_cpp_test_msvc.exe (MSVC ABI via clang) ==="
echo "  clang++:      ${CLANGXX}"
echo "  lld-link:     ${LLD_LINK}"
echo "  llvm-dlltool: ${LLVM_DLLTOOL}"

# Step 1: Compile the C++ source to an object file targeting MSVC ABI
echo "  [1/4] Compiling ${SOURCE}..."
${CLANGXX} \
    --target=x86_64-pc-windows-msvc \
    -fexceptions -fcxx-exceptions \
    -std=c++17 -O0 -g \
    -Wall -Wextra \
    -DWIN32_LEAN_AND_MEAN \
    -c -o "${BUILD_DIR}/seh_cpp_test_msvc.o" \
    "${SOURCE}"

# Step 2: Generate import libraries from .def files
# msvcrt.dll — provides printf, puts, exit
echo "  [2/4] Generating msvcrt.lib..."
cat > "${BUILD_DIR}/msvcrt.def" <<'DEF'
LIBRARY msvcrt.dll
EXPORTS
    printf
    puts
    exit
DEF
${LLVM_DLLTOOL} -m i386:x86-64 -d "${BUILD_DIR}/msvcrt.def" -l "${BUILD_DIR}/msvcrt.lib"

# vcruntime140.dll — provides _CxxThrowException, __CxxFrameHandler3
echo "  [3/4] Generating vcruntime140.lib..."
cat > "${BUILD_DIR}/vcruntime140.def" <<'DEF'
LIBRARY vcruntime140.dll
EXPORTS
    _CxxThrowException
    __CxxFrameHandler3
    __CxxFrameHandler4
DEF
${LLVM_DLLTOOL} -m i386:x86-64 -d "${BUILD_DIR}/vcruntime140.def" -l "${BUILD_DIR}/vcruntime140.lib"

# Step 3: Provide linker stubs for data symbols the compiler references
echo "  [3b/4] Generating linker stubs..."
cat > "${BUILD_DIR}/crt_stubs.c" <<'STUB'
// Minimal type_info vtable stub for linking.
// The MSVC C++ ABI references ??_7type_info@@6B@ for RTTI; we provide
// a zero-filled vtable since litebox handles exception type matching
// through its own __CxxFrameHandler3 implementation.
__asm__(".globl \"??_7type_info@@6B@\"\n"
        ".section .rdata,\"dr\"\n"
        "\"??_7type_info@@6B@\":\n"
        ".quad 0\n"
        ".quad 0\n");

// _fltused: MSVC CRT marker for floating-point usage.
// The MSVC compiler emits a reference to this symbol whenever floating-point
// operations appear in the code. It's normally defined in the CRT.
int _fltused = 0x9875;
STUB
${CLANG_C} --target=x86_64-pc-windows-msvc -c \
    -o "${BUILD_DIR}/crt_stubs.o" "${BUILD_DIR}/crt_stubs.c"

# Step 4: Link into a PE executable
echo "  [4/4] Linking ${OUTPUT}..."
${LLD_LINK} \
    "${BUILD_DIR}/seh_cpp_test_msvc.o" \
    "${BUILD_DIR}/crt_stubs.o" \
    "${BUILD_DIR}/msvcrt.lib" \
    "${BUILD_DIR}/vcruntime140.lib" \
    -entry:main \
    -subsystem:console \
    -out:"${OUTPUT}"

echo ""
echo "  ✓ Built ${OUTPUT}"
echo ""

# Verify the binary
echo "  Sections:"
x86_64-w64-mingw32-objdump -h "${OUTPUT}" 2>/dev/null | grep -E "^\s+[0-9]" || true
echo ""
echo "  Imports:"
x86_64-w64-mingw32-objdump -p "${OUTPUT}" 2>/dev/null | grep -E "DLL Name:|vma:.*[0-9a-f]" | head -10 || true
