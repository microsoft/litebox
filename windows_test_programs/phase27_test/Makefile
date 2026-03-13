# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the Phase 27 Windows API C++ test program using the MinGW cross-compiler.
#
# Covers: SetThreadPriority, GetThreadPriority, SuspendThread, ResumeThread,
#         OpenThread, GetExitCodeThread, OpenProcess, GetProcessTimes,
#         GetFileTime, CompareFileTime, FileTimeToLocalFileTime,
#         GetSystemDirectoryW, GetWindowsDirectoryW, GetTempFileNameW,
#         CharUpperW, CharLowerW, CharUpperA, CharLowerA,
#         IsCharAlphaW, IsCharAlphaNumericW, IsCharUpperW, IsCharLowerW,
#         IsWindow, IsWindowEnabled, IsWindowVisible, EnableWindow,
#         GetWindowTextW, SetWindowTextW, GetParent
#
# Usage:
#   make                   # build phase27_test.exe
#   make clean             # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CXX      := x86_64-w64-mingw32-g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS  := -static-libgcc -static-libstdc++

PROGRAMS := phase27_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
