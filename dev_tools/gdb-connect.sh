#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# gdb-connect.sh — Connect GDB to a litebox runner via gdbserver remote.
#
# Usage:
#   bash dev_tools/gdb-connect.sh [--port PORT] [-- <extra-gdb-args>]
#
# Connects to a litebox runner running under gdbserver inside a Docker
# container (started with litebox_tool_executor --debug).
#
# The script finds the runner binary with debug symbols and configures
# GDB for litebox debugging (SIGSYS passthrough for seccomp compatibility).
#
# Options:
#   --port PORT   GDB remote port (default: 9999)
#   --            Extra arguments passed to GDB
#
# Environment:
#   LITEBOX_RUNNER_SYMBOLS  Override path to runner binary with debug symbols
#   CARGO_TARGET_DIR        Override cargo target directory

set -euo pipefail

PORT=9999
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="$2"
            shift 2
            ;;
        --)
            shift
            EXTRA_ARGS=("$@")
            break
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Find the runner binary with debug symbols.
find_runner_symbols() {
    if [[ -n "${LITEBOX_RUNNER_SYMBOLS:-}" ]]; then
        echo "$LITEBOX_RUNNER_SYMBOLS"
        return
    fi

    local candidates=(
        "$HOME/litebox-out/debug/litebox_runner_linux_userland"
    )

    # Try CARGO_TARGET_DIR or workspace-relative paths.
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local workspace_root
    workspace_root="$(cd "$script_dir/.." && pwd)"
    local target_dir="${CARGO_TARGET_DIR:-$workspace_root/target}/debug"
    candidates+=("$target_dir/litebox_runner_linux_userland")

    for c in "${candidates[@]}"; do
        if [[ -f "$c" ]]; then
            echo "$c"
            return
        fi
    done

    echo "ERROR: Cannot find litebox_runner_linux_userland with debug symbols." >&2
    echo "  Looked in:" >&2
    for c in "${candidates[@]}"; do
        echo "    $c" >&2
    done
    echo "  Set LITEBOX_RUNNER_SYMBOLS or build with:" >&2
    echo "    cargo build --target-dir ~/litebox-out -p litebox_runner_linux_userland" >&2
    exit 1
}

RUNNER_SYMBOLS="$(find_runner_symbols)"

# Find GDB.
if command -v rust-gdb &>/dev/null; then
    GDB="rust-gdb"
elif command -v gdb &>/dev/null; then
    GDB="gdb"
else
    echo "ERROR: Neither rust-gdb nor gdb found." >&2
    echo "  Install with: sudo apt install gdb" >&2
    exit 1
fi

echo "=== GDB Connect ===" >&2
echo "  Runner symbols: $RUNNER_SYMBOLS" >&2
echo "  GDB remote:     localhost:$PORT" >&2
echo "  GDB binary:     $GDB" >&2
echo "" >&2
echo "  Tips:" >&2
echo "    break do_clone        — guest fork/clone" >&2
echo "    break sys_execve      — guest exec" >&2
echo "    break exit_group      — guest process exit" >&2
echo "    info threads           — list all threads" >&2
echo "    thread apply all bt    — all thread backtraces" >&2
echo "===================" >&2
echo "" >&2

exec "$GDB" \
    -ex "set pagination off" \
    -ex "set print pretty on" \
    -ex "handle SIGSYS nostop noprint pass" \
    -ex "target remote localhost:$PORT" \
    "${EXTRA_ARGS[@]}" \
    "$RUNNER_SYMBOLS"
