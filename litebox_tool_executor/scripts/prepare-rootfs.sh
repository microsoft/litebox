#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Prepare a minimal busybox rootfs tar for litebox_tool_executor.
#
# Run this script inside WSL2 Ubuntu. It:
# 1. Installs busybox-static if needed
# 2. Uses litebox_packager to rewrite syscalls in the busybox binary
# 3. Creates a minimal tar with busybox + litebox_rtld_audit.so
#
# Usage:
#   ./prepare-rootfs.sh [output-path]
#
# Default output: ../../target/busybox-minimal.tar (relative to this script)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT="${1:-$REPO_ROOT/target/busybox-minimal.tar}"

echo "==> Checking for busybox-static..."
if ! command -v busybox &>/dev/null; then
    echo "    Installing busybox-static..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq busybox-static
fi
echo "    busybox: $(which busybox)"

echo "==> Building litebox_packager..."
cd "$REPO_ROOT"
cargo build -p litebox_packager 2>&1 | tail -1

echo "==> Packaging busybox (syscall rewriting)..."
TMPTAR="$(mktemp)"
cargo run -p litebox_packager -- "$(which busybox)" -o "$TMPTAR" 2>&1 | tail -3

echo "==> Building rootfs..."
BUILDDIR="$(mktemp -d)"
mkdir -p "$BUILDDIR/bin" "$BUILDDIR/usr/bin" "$BUILDDIR/lib" "$BUILDDIR/tmp"
tar xf "$TMPTAR" -C "$BUILDDIR/"

# Copy busybox to /bin
cp "$BUILDDIR/usr/bin/busybox" "$BUILDDIR/bin/busybox"

# Create hard links for common commands (works on ext4, not NTFS)
COMMANDS="sh echo ls cat cp mv rm mkdir rmdir head tail wc grep sed sort uniq
          env printenv pwd id whoami true false test sleep date tr tee xargs
          find du df free uname hostname basename dirname"
for cmd in $COMMANDS; do
    ln -f "$BUILDDIR/bin/busybox" "$BUILDDIR/bin/$cmd" 2>/dev/null || true
done

cd "$BUILDDIR"
tar cf "$OUTPUT" .
rm -rf "$BUILDDIR" "$TMPTAR"

SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
ENTRIES=$(tar tf "$OUTPUT" | wc -l)
echo "==> Created $OUTPUT ($ENTRIES entries, $SIZE)"
