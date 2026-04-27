#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# gdb-connect.sh — Connect GDB to a litebox session via gdbserver remote.
#
# Usage:
#   bash dev_tools/gdb-connect.sh [--port PORT] [-- <extra-gdb-args>]
#
# Connects to a litebox_tool_executor running under gdbserver inside a Docker
# container (started with litebox_tool_executor --debug).
#
# The --debug flag wraps the entire tool_executor under gdbserver, so the
# broker and runner (spawned as children) are all debuggable. GDB is
# configured with `set detach-on-fork off` to track all child processes.
#
# Options:
#   --port PORT   GDB remote port (default: 9999)
#   --            Extra arguments passed to GDB
#
# Environment:
#   LITEBOX_SYMBOLS_DIR     Override directory containing debug binaries
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

# Find the debug symbols directory.
find_symbols_dir() {
    if [[ -n "${LITEBOX_SYMBOLS_DIR:-}" ]]; then
        echo "$LITEBOX_SYMBOLS_DIR"
        return
    fi

    local candidates=(
        "$HOME/litebox-out/debug"
    )

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local workspace_root
    workspace_root="$(cd "$script_dir/.." && pwd)"
    local target_dir="${CARGO_TARGET_DIR:-$workspace_root/target}/debug"
    candidates+=("$target_dir")

    for c in "${candidates[@]}"; do
        if [[ -f "$c/litebox_tool_executor" ]]; then
            echo "$c"
            return
        fi
    done

    echo "ERROR: Cannot find litebox binaries with debug symbols." >&2
    echo "  Looked in:" >&2
    for c in "${candidates[@]}"; do
        echo "    $c" >&2
    done
    echo "  Set LITEBOX_SYMBOLS_DIR or build with:" >&2
    echo "    cargo build --target-dir ~/litebox-out -p litebox_tool_executor -p litebox_runner_linux_userland -p litebox_broker" >&2
    exit 1
}

SYMBOLS_DIR="$(find_symbols_dir)"
EXECUTOR="$SYMBOLS_DIR/litebox_tool_executor"
RUNNER="$SYMBOLS_DIR/litebox_runner_linux_userland"
BROKER="$SYMBOLS_DIR/litebox_broker"

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
echo "  Symbols dir:     $SYMBOLS_DIR" >&2
echo "  GDB remote:      localhost:$PORT" >&2
echo "  GDB binary:      $GDB" >&2
echo "" >&2
echo "  Tips:" >&2
echo "    info inferiors             — list all processes (executor, broker, runner)" >&2
echo "    inferior 2                 — switch to broker" >&2
echo "    break process.rs:LINE      — breakpoint by file:line (handles monomorphization)" >&2
echo "    break do_clone             — guest fork/clone" >&2
echo "    break exit_group           — guest process exit" >&2
echo "    thread apply all bt        — all thread backtraces" >&2
echo "===================" >&2
echo "" >&2

# Configure GDB to:
# - Pass SIGSYS/SIGSEGV to the program (seccomp/guest faults)
# - Track ALL child processes (broker + runner + workers)
# - Load symbols for all litebox binaries
exec "$GDB" \
    -ex "set pagination off" \
    -ex "set print pretty on" \
    -ex "handle SIGSYS nostop noprint pass" \
    -ex "handle SIGSEGV nostop noprint pass" \
    -ex "set detach-on-fork off" \
    -ex "set follow-fork-mode child" \
    -ex "set schedule-multiple on" \
    -ex "target remote localhost:$PORT" \
    -ex "add-symbol-file $RUNNER" \
    -ex "add-symbol-file $BROKER" \
    "${EXTRA_ARGS[@]}" \
    "$EXECUTOR"
