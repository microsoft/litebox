# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the Windows Registry C++ test program using the MinGW cross-compiler.
#
# Usage:
#   make                   # build registry_test.exe
#   make clean             # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CXX      := x86_64-w64-mingw32-g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS  := -ladvapi32 -static-libgcc -static-libstdc++

PROGRAMS := registry_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
