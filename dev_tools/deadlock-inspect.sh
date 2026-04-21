#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# deadlock-inspect.sh — Attach to running litebox runner(s) and dump thread stacks.
#
# Usage:
#   bash dev_tools/deadlock-inspect.sh           # Find and inspect all runners
#   bash dev_tools/deadlock-inspect.sh <PID>     # Inspect a specific process
#
# Attaches GDB to each running litebox_runner_linux_userland process,
# dumps all thread backtraces, and detaches without killing the process.
# Useful when a test hangs or times out.
#
# Environment:
#   LITEBOX_GDB  Override GDB binary (default: rust-gdb, fallback: gdb)

set -euo pipefail

# Find GDB.
find_gdb() {
    if [[ -n "${LITEBOX_GDB:-}" ]]; then
        echo "$LITEBOX_GDB"
    elif command -v rust-gdb &>/dev/null; then
        echo "rust-gdb"
    elif command -v gdb &>/dev/null; then
        echo "gdb"
    else
        echo "ERROR: Neither rust-gdb nor gdb found." >&2
        exit 1
    fi
}

GDB="$(find_gdb)"

inspect_pid() {
    local pid="$1"
    local exe
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "unknown")

    echo "=== PID $pid ($exe) ==="
    echo "--- Thread list ---"

    "$GDB" -batch \
        -ex "set pagination off" \
        -ex "set print pretty on" \
        -ex "handle SIGSYS nostop noprint pass" \
        -ex "echo === All thread backtraces ===\n" \
        -ex "thread apply all bt" \
        -ex "echo \n=== Mutexes (info threads) ===\n" \
        -ex "info threads" \
        -ex "detach" \
        -ex "quit" \
        -p "$pid" 2>/dev/null || echo "  (GDB attach failed — permission denied or process exited)"

    echo
}

if [[ $# -gt 0 ]]; then
    # Specific PID provided.
    inspect_pid "$1"
else
    # Find all litebox_runner_linux_userland processes.
    PIDS=$(pgrep -f 'litebox_runner_linux_userland' 2>/dev/null || true)

    if [[ -z "$PIDS" ]]; then
        echo "No running litebox_runner_linux_userland processes found."
        echo
        echo "Also checking for litebox_tool_executor and litebox_broker..."
        pgrep -af 'litebox_tool_executor|litebox_broker' 2>/dev/null || echo "  (none found)"
        exit 0
    fi

    echo "Found $(echo "$PIDS" | wc -w) runner process(es):"
    for pid in $PIDS; do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "unknown")
        echo "  PID=$pid  exe=$exe"
        echo "    cmdline: $cmdline"
    done
    echo

    for pid in $PIDS; do
        inspect_pid "$pid"
    done

    echo "=== Done: inspected $(echo "$PIDS" | wc -w) process(es) ==="
fi
