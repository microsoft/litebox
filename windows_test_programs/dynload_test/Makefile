# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the GetProcAddress C test program for Windows (x86_64) using the
# MinGW cross-compiler that ships with most Linux distributions.
#
# Usage:
#   make                             # build all programs
#   make getprocaddress_test.exe     # build one program
#   make clean                       # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y gcc-mingw-w64-x86-64

CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -DWIN32_LEAN_AND_MEAN
LDFLAGS := -static-libgcc

PROGRAMS := getprocaddress_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
