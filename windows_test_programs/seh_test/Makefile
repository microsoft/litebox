# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the SEH (Structured Exception Handling) test programs for Windows
# (x86_64) using the MinGW cross-compiler that ships with most Linux
# distributions.
#
# seh_c_test  – plain-C program testing Windows SEH runtime APIs and
#               setjmp/longjmp (GCC/MinGW does not support MSVC's
#               __try/__except syntax in C mode).
# seh_cpp_test – C++ program testing C++ exceptions (try/catch/throw),
#               which on Windows x64 use the SEH .pdata/.xdata machinery.
# seh_cpp_test_clang – same as seh_cpp_test but compiled with clang++ using
#               the LLVM front-end targeting MinGW.  This variant generates
#               cleanup landing pads that call _Unwind_Resume (which tests
#               the STATUS_GCC_UNWIND path through RaiseException).
# seh_cpp_test_msvc – self-contained C++ program compiled with clang targeting
#               the MSVC ABI (x86_64-pc-windows-msvc).  Uses MSVC-style
#               exception handling (_CxxThrowException / __CxxFrameHandler3)
#               instead of GCC-style (_GCC_specific_handler / _Unwind_Resume).
#
# Usage:
#   make                            # build all programs
#   make seh_c_test.exe             # build only the C test
#   make seh_cpp_test.exe           # build only the C++ test (GCC)
#   make seh_cpp_test_clang.exe     # build only the C++ test (Clang/MinGW)
#   make seh_cpp_test_msvc.exe      # build only the C++ test (Clang/MSVC ABI)
#   make clean                      # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64 clang lld

CC      := x86_64-w64-mingw32-gcc
CXX     := x86_64-w64-mingw32-g++
CLANGXX := clang++ --target=x86_64-w64-mingw32

CFLAGS   := -Wall -Wextra -std=c11   -O2 -DWIN32_LEAN_AND_MEAN
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN -fexceptions

LDFLAGS  := -static-libgcc -static-libstdc++

PROGRAMS := seh_c_test.exe seh_cpp_test.exe seh_cpp_test_clang.exe seh_cpp_test_msvc.exe

# ── Tool detection for MSVC-ABI builds ─────────────────────────────────────────
# Try versioned LLVM tools first, then fall back to unversioned
CLANGXX_MSVC := $(firstword $(foreach v,18 17 16,$(shell command -v clang++-$(v) 2>/dev/null)) $(shell command -v clang++ 2>/dev/null))
CLANG_C      := $(firstword $(foreach v,18 17 16,$(shell command -v clang-$(v) 2>/dev/null)) $(shell command -v clang 2>/dev/null))
LLD_LINK     := $(firstword $(foreach v,18 17 16,$(shell command -v lld-link-$(v) 2>/dev/null)) $(shell command -v lld-link 2>/dev/null))
LLVM_DLLTOOL := $(firstword $(foreach v,18 17 16,$(shell command -v llvm-dlltool-$(v) 2>/dev/null)) $(shell command -v llvm-dlltool 2>/dev/null))

MSVC_BUILD   := build_msvc

.PHONY: all clean

all: $(PROGRAMS)

seh_c_test.exe: seh_c_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

seh_cpp_test.exe: seh_cpp_test.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

seh_cpp_test_clang.exe: seh_cpp_test.cpp
	$(CLANGXX) $(CXXFLAGS) -O0 -o $@ $< $(LDFLAGS)

# ── MSVC-ABI build via clang + lld-link ───────────────────────────────────────
seh_cpp_test_msvc.exe: seh_cpp_test_msvc.cpp
	@mkdir -p $(MSVC_BUILD)
	$(CLANGXX_MSVC) --target=x86_64-pc-windows-msvc \
		-fexceptions -fcxx-exceptions -std=c++17 -O0 -g \
		-Wall -Wextra -DWIN32_LEAN_AND_MEAN \
		-c -o $(MSVC_BUILD)/seh_cpp_test_msvc.o $<
	@printf 'LIBRARY msvcrt.dll\nEXPORTS\n    printf\n    puts\n    exit\n' > $(MSVC_BUILD)/msvcrt.def
	$(LLVM_DLLTOOL) -m i386:x86-64 -d $(MSVC_BUILD)/msvcrt.def -l $(MSVC_BUILD)/msvcrt.lib
	@printf 'LIBRARY vcruntime140.dll\nEXPORTS\n    _CxxThrowException\n    __CxxFrameHandler3\n    __CxxFrameHandler4\n' > $(MSVC_BUILD)/vcruntime140.def
	$(LLVM_DLLTOOL) -m i386:x86-64 -d $(MSVC_BUILD)/vcruntime140.def -l $(MSVC_BUILD)/vcruntime140.lib
	@printf '/* CRT stubs */\n__asm__(".globl \\"??_7type_info@@6B@\\"\\n" ".section .rdata,\\"dr\\"\\n" "\\"??_7type_info@@6B@\\":\\n" ".quad 0\\n" ".quad 0\\n");\nint _fltused = 0x9875;\n' > $(MSVC_BUILD)/crt_stubs.c
	$(CLANG_C) --target=x86_64-pc-windows-msvc -c -o $(MSVC_BUILD)/crt_stubs.o $(MSVC_BUILD)/crt_stubs.c
	$(LLD_LINK) $(MSVC_BUILD)/seh_cpp_test_msvc.o $(MSVC_BUILD)/crt_stubs.o \
		$(MSVC_BUILD)/msvcrt.lib $(MSVC_BUILD)/vcruntime140.lib \
		-entry:main -subsystem:console -out:$@

clean:
	rm -f $(PROGRAMS)
	rm -rf $(MSVC_BUILD)
