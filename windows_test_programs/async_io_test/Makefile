# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the async I/O C++ test program for Windows (x86_64) using the MinGW
# cross-compiler that ships with most Linux distributions.
#
# Usage:
#   make                          # build all programs
#   make async_io_test.exe        # build one program
#   make clean                    # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CXX      := x86_64-w64-mingw32-g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN -DNOMINMAX
LDFLAGS  := -static-libgcc -static-libstdc++

PROGRAMS := async_io_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
