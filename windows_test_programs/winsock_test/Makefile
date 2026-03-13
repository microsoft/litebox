# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds WinSock C++ test programs for Windows (x86_64) using the MinGW
# cross-compiler that ships with most Linux distributions.
#
# Usage:
#   make                        # build all programs
#   make winsock_basic_test.exe # build one program
#   make clean                  # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y mingw-w64

CXX      := x86_64-w64-mingw32-g++
CXXFLAGS := -Wall -Wextra -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS  := -lws2_32 -static-libgcc -static-libstdc++

PROGRAMS := winsock_basic_test.exe winsock_tcp_test.exe winsock_udp_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
