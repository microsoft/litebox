#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Rebuilds the x86-64 Mach-O test binaries in this directory from their `.S`
# sources. The results are committed, so tests need neither tool; rerun this
# after editing a source. Needs clang and LLVM's ld64.lld (on Debian/Ubuntu,
# the clang and lld packages; ld64.lld lives in /usr/lib/llvm-<N>/bin).
#
# The binaries link against nothing: no libSystem, so no dyld at run time.
# Each defines `_main`, which ld64.lld records as the LC_MAIN entry point.

set -euo pipefail

cd "$(dirname "$0")"

CLANG=${CLANG:-clang}
LD64=${LD64:-$(command -v ld64.lld || ls /usr/lib/llvm-*/bin/ld64.lld 2>/dev/null | sort -V | tail -n 1)}
if [ -z "$LD64" ]; then
    echo "ld64.lld not found; set LD64" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for src in *.S; do
    name=${src%.S}
    "$CLANG" --target=x86_64-apple-macos11 -c "$src" -o "$tmp/$name.o"
    "$LD64" -arch x86_64 -platform_version macos 11.0 11.0 -e _main \
        -o "$name.macho" "$tmp/$name.o"
done
