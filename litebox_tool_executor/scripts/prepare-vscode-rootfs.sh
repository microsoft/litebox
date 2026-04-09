#!/bin/bash
# Prepare a rootfs directory containing a minimal Ubuntu environment
# with Node.js, git, and VS Code Server for use with the LiteBox sandbox
# via 9P directory serving (broker --root-dir).
#
# This script:
#   1. Uses debootstrap to create a minimal Ubuntu rootfs
#   2. Installs Node.js, git, ca-certificates, libssl, procps
#   3. Downloads VS Code Server CLI
#   4. Runs litebox_syscall_rewriter on all ELF binaries
#
# Usage:
#   sudo ./prepare-vscode-rootfs.sh [output-dir]
#
# The resulting directory is used with:
#   litebox_broker --root-dir <output-dir> --rewrite-syscalls ...
#   litebox_runner_linux_userland --network-broker <socket> -- /usr/bin/node ...

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"
REWRITER="$WORKSPACE/target/debug/litebox_syscall_rewriter"
OUTPUT="${1:-$WORKSPACE/target/vscode-rootfs}"
SUITE="noble"  # Ubuntu 24.04 LTS

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (for debootstrap)"
    echo "Usage: sudo $0 [output-dir]"
    exit 1
fi

if ! command -v debootstrap &>/dev/null; then
    echo "Installing debootstrap..."
    apt-get update -qq && apt-get install -y -qq debootstrap
fi

if [ ! -f "$REWRITER" ]; then
    echo "ERROR: litebox_syscall_rewriter not found at $REWRITER"
    echo "Build it first: cargo build -p litebox_syscall_rewriter"
    exit 1
fi

echo "=== Phase 1: Debootstrap minimal Ubuntu ($SUITE) ==="
if [ -d "$OUTPUT" ] && [ -f "$OUTPUT/etc/os-release" ]; then
    echo "  Rootfs already exists at $OUTPUT, skipping debootstrap"
else
    mkdir -p "$OUTPUT"
    debootstrap \
        --variant=minbase \
        --include=apt,ca-certificates,curl,gnupg \
        "$SUITE" "$OUTPUT" http://archive.ubuntu.com/ubuntu
fi

echo "=== Phase 2: Install packages ==="
# Mount necessary filesystems for chroot
mount --bind /dev "$OUTPUT/dev" 2>/dev/null || true
mount --bind /dev/pts "$OUTPUT/dev/pts" 2>/dev/null || true
mount -t proc proc "$OUTPUT/proc" 2>/dev/null || true
mount -t sysfs sysfs "$OUTPUT/sys" 2>/dev/null || true
mount -t tmpfs tmpfs "$OUTPUT/tmp" 2>/dev/null || true

cleanup_mounts() {
    umount "$OUTPUT/tmp" 2>/dev/null || true
    umount "$OUTPUT/sys" 2>/dev/null || true
    umount "$OUTPUT/proc" 2>/dev/null || true
    umount "$OUTPUT/dev/pts" 2>/dev/null || true
    umount "$OUTPUT/dev" 2>/dev/null || true
}
trap cleanup_mounts EXIT

# Install packages inside the chroot
chroot "$OUTPUT" bash -c '
    export DEBIAN_FRONTEND=noninteractive

    # Add NodeSource repo for Node.js LTS
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -

    apt-get install -y --no-install-recommends \
        bash \
        coreutils \
        git \
        nodejs \
        python3-minimal \
        libssl3t64 \
        openssl \
        ca-certificates \
        procps \
        findutils \
        grep \
        sed \
        gawk \
        less \
        wget \
        xz-utils \
        tar

    # Clean up apt caches to reduce size
    apt-get clean
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*
'

echo "=== Phase 3: Configure rootfs ==="
# DNS resolver pointing at broker virtual IP
echo "nameserver 10.0.0.1" > "$OUTPUT/etc/resolv.conf"

# Create workspace mount point
mkdir -p "$OUTPUT/workspaces"

# Create tmp directory
mkdir -p "$OUTPUT/tmp"
chmod 1777 "$OUTPUT/tmp"

echo "=== Phase 4: Download VS Code Server ==="
# Download the VS Code Server CLI (code-server standalone)
VSCODE_DIR="$OUTPUT/opt/vscode-server"
if [ -d "$VSCODE_DIR" ] && [ -f "$VSCODE_DIR/bin/code-server" ]; then
    echo "  VS Code Server already exists, skipping download"
else
    mkdir -p "$VSCODE_DIR"
    ARCH="x64"
    # Download the official VS Code CLI which can serve as a server
    VSCODE_COMMIT=$(curl -fsSL "https://update.code.visualstudio.com/api/releases/stable" | head -c 1000 | grep -o '"[a-f0-9]\{40\}"' | head -1 | tr -d '"')
    if [ -n "$VSCODE_COMMIT" ]; then
        echo "  Downloading VS Code Server (commit: $VSCODE_COMMIT)..."
        curl -fsSL "https://update.code.visualstudio.com/commit:${VSCODE_COMMIT}/server-linux-${ARCH}/stable" \
            -o /tmp/vscode-server.tar.gz
        tar xzf /tmp/vscode-server.tar.gz -C "$VSCODE_DIR" --strip-components=1
        rm -f /tmp/vscode-server.tar.gz
    else
        echo "  WARNING: Could not determine VS Code Server version, downloading latest CLI..."
        curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64" \
            -o /tmp/vscode-cli.tar.gz
        tar xzf /tmp/vscode-cli.tar.gz -C "$VSCODE_DIR"
        rm -f /tmp/vscode-cli.tar.gz
    fi
fi

# Unmount before rewriting (so we don't rewrite /dev, /proc, etc.)
cleanup_mounts
trap - EXIT

echo "=== Phase 5: Rewrite ELF binaries ==="
REWRITTEN=0
SKIPPED=0
FAILED=0

rewrite_binary() {
    local path="$1"
    local backup="${path}.orig"

    # Skip if not a regular file or not executable
    [ -f "$path" ] || return 0
    [ -x "$path" ] || return 0

    # Check if it's an ELF binary
    if ! file "$path" 2>/dev/null | grep -q "ELF.*executable\|ELF.*shared object"; then
        return 0
    fi

    # Skip if already rewritten (check for .orig backup)
    if [ -f "$backup" ]; then
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    # Try to rewrite
    if "$REWRITER" "$path" -o "${path}.rewritten" 2>/dev/null; then
        cp "$path" "$backup"
        mv "${path}.rewritten" "$path"
        REWRITTEN=$((REWRITTEN + 1))
    else
        rm -f "${path}.rewritten"
        FAILED=$((FAILED + 1))
    fi
}

# Find and rewrite all ELF binaries
echo "  Scanning for ELF binaries..."
while IFS= read -r -d '' binary; do
    rewrite_binary "$binary"
done < <(find "$OUTPUT" -type f \( -perm -100 -o -name "*.so" -o -name "*.so.*" \) -print0 2>/dev/null)

echo "  Rewritten: $REWRITTEN, Skipped (already done): $SKIPPED, Failed: $FAILED"

echo "=== Phase 6: Summary ==="
TOTAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
FILE_COUNT=$(find "$OUTPUT" -type f | wc -l)

echo ""
echo "Created rootfs at $OUTPUT"
echo "  Total size: $TOTAL_SIZE"
echo "  File count: $FILE_COUNT"
echo ""
echo "Key binaries:"
for bin in node git python3 bash; do
    path=$(chroot "$OUTPUT" which "$bin" 2>/dev/null || echo "NOT FOUND")
    echo "  $bin: $path"
done
echo ""
echo "Usage:"
echo "  # Start broker serving this rootfs directory:"
echo "  litebox_broker --root-dir $OUTPUT --rewrite-syscalls \\"
echo "    --network-proxy-listen /tmp/litebox-broker.sock"
echo ""
echo "  # Run a command inside the sandbox:"
echo "  litebox_runner_linux_userland --unstable \\"
echo "    --network-broker /tmp/litebox-broker.sock \\"
echo "    --env 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \\"
echo "    --env 'HOME=/root' \\"
echo "    -- /usr/bin/node --version"
