# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the Windows GUI + Vulkan API test program for Windows (x86_64) using
# the MinGW cross-compiler that ships with most Linux distributions.
#
# The test exercises USER32 (window creation, menus, painting, clipboard,
# monitor info), GDI32 (drawing primitives, bitmaps, device context), and
# Vulkan-1 (via dynamic LoadLibraryA / GetProcAddress).
#
# Usage:
#   make                 # build all programs
#   make gui_test.exe    # build one program
#   make clean           # remove compiled executables
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt install -y gcc-mingw-w64-x86-64

CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -Wall -Wextra -std=c11 -O2 -DWIN32_LEAN_AND_MEAN -DUNICODE -D_UNICODE
LDFLAGS := -static-libgcc -lgdi32 -luser32

PROGRAMS := gui_test.exe

.PHONY: all clean

all: $(PROGRAMS)

%.exe: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(PROGRAMS)
