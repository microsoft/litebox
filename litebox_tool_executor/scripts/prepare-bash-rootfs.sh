#!/bin/bash
# Prepare a rootfs tar containing common utilities + shared libraries
# for use with the LiteBox sandbox demo.
#
# Stages bash, common utilities, and shared libraries into a tar.
#
# Usage:
#   ./prepare-bash-rootfs.sh [output.tar]
#
# The resulting tar is used with:
#   litebox_tool_executor --rootfs <output.tar> --interactive
#   litebox_tool_executor --rootfs <output.tar> -- /usr/bin/bash -c 'echo hello'
#   litebox_runner_linux_userland --unstable --initial-files <output.tar> \
#     --program-from-tar -- /usr/bin/bash --norc --noprofile -c 'echo hello'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"
REWRITER="$WORKSPACE/target/debug/litebox_syscall_rewriter"
OUTPUT="${1:-$WORKSPACE/target/bash-sandbox.tar}"

UTILS=(cat ls grep sort uniq wc find head tail mkdir rm cp mv echo tr sed awk pwd dirname basename env printenv date id uname xargs tee touch chmod)

if [ ! -f "$REWRITER" ]; then
    echo "ERROR: litebox_syscall_rewriter not found at $REWRITER"
    echo "Build it first: cargo build -p litebox_syscall_rewriter"
    exit 1
fi

STAGING=$(mktemp -d)
trap "rm -rf $STAGING" EXIT

echo "Staging directory: $STAGING"

declare -A STAGED_LIBS

stage_lib() {
    local orig_path="$1"
    local lib_path
    lib_path=$(readlink -f "$orig_path")
    if [ "${STAGED_LIBS[$lib_path]:-}" = "1" ]; then
        # Still create symlink at the original path if needed
        if [ "$orig_path" != "$lib_path" ]; then
            local sym_dest="$STAGING$orig_path"
            if [ ! -e "$sym_dest" ]; then
                mkdir -p "$(dirname "$sym_dest")"
                cp "$STAGING$lib_path" "$sym_dest" 2>/dev/null || true
            fi
        fi
        return
    fi
    STAGED_LIBS["$lib_path"]=1
    local dest="$STAGING$lib_path"
    mkdir -p "$(dirname "$dest")"
    "$REWRITER" "$lib_path" -o "$dest" 2>/dev/null || cp "$lib_path" "$dest"
    # Also copy at the original (symlink) path if different
    if [ "$orig_path" != "$lib_path" ]; then
        local sym_dest="$STAGING$orig_path"
        if [ ! -e "$sym_dest" ]; then
            mkdir -p "$(dirname "$sym_dest")"
            cp "$dest" "$sym_dest"
        fi
    fi
}

stage_deps() {
    local binary="$1"
    local deps
    deps=$(ldd "$binary" 2>/dev/null || true)
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [ -z "$line" ] && continue
        local lib_path=""
        if echo "$line" | grep -q "=>"; then
            lib_path=$(echo "$line" | sed -n 's/.*=> \(\/[^ ]*\).*/\1/p')
        elif echo "$line" | grep -q "^/"; then
            lib_path=$(echo "$line" | awk '{print $1}')
        fi
        if [ -n "$lib_path" ] && [ -f "$lib_path" ]; then
            stage_lib "$lib_path"
        fi
    done <<< "$deps"
}

stage_binary() {
    local name="$1"
    local host_path
    host_path=$(which "$name" 2>/dev/null || true)
    if [ -z "$host_path" ]; then
        echo "  SKIP: $name not found"
        return
    fi
    host_path=$(readlink -f "$host_path")
    local dest="$STAGING$host_path"
    if [ -f "$dest" ]; then
        return
    fi
    echo "  $name -> $host_path"
    mkdir -p "$(dirname "$dest")"
    "$REWRITER" "$host_path" -o "$dest" 2>/dev/null || {
        echo "    WARNING: rewriter failed, copying raw"
        cp "$host_path" "$dest"
    }
    stage_deps "$host_path"
}

echo "=== Staging bash + dependencies ==="
stage_binary bash
bash_path=$(readlink -f "$(which bash)")
stage_deps "$bash_path"

echo "=== Staging utilities ==="
for util in "${UTILS[@]}"; do
    stage_binary "$util"
done

echo "=== Creating compatibility symlinks ==="
mkdir -p "$STAGING/bin" "$STAGING/usr/bin"
for util in "${UTILS[@]}"; do
    real_path=$(readlink -f "$(which "$util" 2>/dev/null)" 2>/dev/null || true)
    if [ -n "$real_path" ] && [ -f "$STAGING$real_path" ]; then
        if [[ "$real_path" == /usr/bin/* ]] && [ ! -e "$STAGING/bin/$util" ]; then
            ln -s "$real_path" "$STAGING/bin/$util" 2>/dev/null || true
        fi
    fi
done

mkdir -p "$STAGING/tmp" "$STAGING/etc"

# Ensure the dynamic linker is available at its PT_INTERP path
# (bash expects /lib64/ld-linux-x86-64.so.2 but readlink resolves
# to /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 on Ubuntu)
if [ ! -f "$STAGING/lib64/ld-linux-x86-64.so.2" ]; then
    mkdir -p "$STAGING/lib64"
    real_ld=$(readlink -f /lib64/ld-linux-x86-64.so.2 2>/dev/null || true)
    if [ -n "$real_ld" ] && [ -f "$STAGING$real_ld" ]; then
        cp "$STAGING$real_ld" "$STAGING/lib64/ld-linux-x86-64.so.2"
        echo "  Copied ld-linux to /lib64/ (PT_INTERP path)"
    fi
fi

echo "=== Creating tar ==="
(cd "$STAGING" && tar cf "$OUTPUT" --format=ustar .)

ENTRIES=$(tar tf "$OUTPUT" | wc -l)
SIZE=$(du -h "$OUTPUT" | cut -f1)
echo ""
echo "Created $OUTPUT ($ENTRIES entries, $SIZE)"
echo ""
echo "Usage:"
echo "  litebox_runner_linux_userland --unstable \\"
echo "    --initial-files $OUTPUT \\"
echo "    --program-from-tar \\"
echo "    --env 'LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib' \\"
echo "    /usr/bin/bash --norc --noprofile -c 'echo hello | cat'"
