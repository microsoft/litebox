# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the Windows synchronization API C++ test program using the MinGW
# cross-compiler.
#
# Covers: CreateMutexW, OpenMutexW, ReleaseMutex,
#         CreateEventW, SetEvent, ResetEvent,
#         CreateSemaphoreW, ReleaseSemaphore,
#         WaitForSingleObject, CloseHandle
#
# Usage:
#   make              # build sync_test.exe
#   make clean        # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CXX      := x86_64-w64-mingw32-g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS  := -static-libgcc -static-libstdc++

PROGRAMS := sync_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
