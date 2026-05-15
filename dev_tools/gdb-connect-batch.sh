#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# gdb-connect-batch.sh — Non-interactive variant of gdb-connect.sh.
#
# Drives a litebox gdbserver session (started with
# `litebox_tool_executor --debug PORT`) from a caller-supplied GDB
# command file. Designed for coding-agent workflows that need a
# transcript rather than an interactive (gdb) prompt.
#
# Usage:
#   bash dev_tools/gdb-connect-batch.sh \
#       --port 9999 \
#       --commands probe.gdb \
#       [--timeout 120] \
#       [-- <extra-gdb-args>]
#
# Where probe.gdb is a file of GDB commands, e.g.:
#
#   break litebox_runner_linux_userland::syscalls::process::do_clone
#   commands
#     silent
#     printf "clone tid=%d\n", $_thread
#     bt 5
#     continue
#   end
#   continue
#   quit
#
# Options:
#   --port PORT      GDB remote port (default: 9999)
#   --commands FILE  GDB command file (required)
#   --timeout SECS   Wall-clock budget (default: 120; KILL on expiry)
#   --              Extra arguments forwarded to GDB
#
# Environment:
#   LITEBOX_SYMBOLS_DIR  Override directory containing debug binaries
#
# Output:
#   - All GDB output goes to stdout (transcript).
#   - Resolved configuration goes to stderr.
#
# Exit codes:
#   0    GDB completed (note: GDB's exit code reflects its own status,
#        not the inferior's verdict — parse the transcript for that)
#   124  Timed out (from `timeout`)
#   other  GDB or shell error

set -euo pipefail

PORT=9999
COMMANDS=""
TIMEOUT=120
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="$2"
            shift 2
            ;;
        --commands)
            COMMANDS="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
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

if [[ -z "$COMMANDS" ]]; then
    echo "ERROR: --commands FILE is required." >&2
    echo "Usage: $0 --port PORT --commands FILE [--timeout SECS] [-- gdb-args]" >&2
    exit 2
fi

if [[ ! -f "$COMMANDS" ]]; then
    echo "ERROR: commands file not found: $COMMANDS" >&2
    exit 2
fi

# Find the debug symbols directory.
find_symbols_dir() {
    if [[ -n "${LITEBOX_SYMBOLS_DIR:-}" ]]; then
        echo "$LITEBOX_SYMBOLS_DIR"
        return
    fi
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local workspace_root
    workspace_root="$(cd "$script_dir/.." && pwd)"
    local target_dir="$workspace_root/target/debug"
    if [[ -f "$target_dir/litebox_tool_executor" ]]; then
        echo "$target_dir"
        return
    fi
    echo "ERROR: Cannot find litebox binaries with debug symbols." >&2
    echo "  Looked in: $target_dir" >&2
    echo "  Set LITEBOX_SYMBOLS_DIR, or build with:" >&2
    echo "    cargo build -p litebox_tool_executor -p litebox_runner_linux_userland -p litebox_broker" >&2
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
    echo "ERROR: Neither rust-gdb nor gdb found. Install with: sudo apt install gdb" >&2
    exit 1
fi

echo "=== GDB Connect (batch) ===" >&2
echo "  Symbols dir:     $SYMBOLS_DIR" >&2
echo "  GDB remote:      localhost:$PORT" >&2
echo "  GDB binary:      $GDB" >&2
echo "  Commands file:   $COMMANDS" >&2
echo "  Wall timeout:    ${TIMEOUT}s" >&2
echo "===========================" >&2
echo "" >&2

# `set follow-fork-mode parent` is the right default for shim-side
# debugging (litebox runner / broker bugs). To debug a forked guest
# binary instead, append `-ex 'set follow-fork-mode child'` after
# `--`.
exec timeout --signal=KILL "$TIMEOUT" \
    "$GDB" \
    -batch \
    -ex "set pagination off" \
    -ex "set print pretty on" \
    -ex "set print frame-arguments all" \
    -ex "set print object on" \
    -ex "set print elements 0" \
    -ex "set max-completions 0" \
    -ex "handle SIGSYS nostop noprint pass" \
    -ex "handle SIGSEGV nostop noprint pass" \
    -ex "set detach-on-fork off" \
    -ex "set follow-fork-mode parent" \
    -ex "set schedule-multiple on" \
    -ex "define ll
info locals
info args
end" \
    -ex "target remote localhost:$PORT" \
    -ex "add-symbol-file $RUNNER" \
    -ex "add-symbol-file $BROKER" \
    -x "$COMMANDS" \
    "${EXTRA_ARGS[@]}" \
    "$EXECUTOR"
