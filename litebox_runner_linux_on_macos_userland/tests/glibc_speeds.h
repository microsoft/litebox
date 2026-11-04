// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Speed codes for glibc releases before 2.42, which `tests/test-bins/libc.so.6` (2.38) is. Zig's
// glibc headers define the speed macros as plain rates for every target version, as glibc 2.42
// does, but an older glibc's `cfgetospeed` returns the codes.
#define _GNU_SOURCE
#include <termios.h>
#undef B9600
#define B9600 0000015
#undef B38400
#define B38400 0000017
