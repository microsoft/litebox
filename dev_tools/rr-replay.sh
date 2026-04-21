#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# rr-replay.sh — Replay an rr trace with optional scripted GDB commands.
#
# Usage:
#   bash dev_tools/rr-replay.sh [TRACE_DIR]                    # Interactive GDB session
#   bash dev_tools/rr-replay.sh [TRACE_DIR] --batch             # Run to crash, dump backtrace
#   bash dev_tools/rr-replay.sh [TRACE_DIR] --break SYMBOL      # Set breakpoint, run to it
#   bash dev_tools/rr-replay.sh [TRACE_DIR] --commands "CMD;CMD" # Run GDB commands
#
# If TRACE_DIR is omitted, uses the most recent trace in target/rr-traces/.
#
# Options:
#   --batch         Non-interactive: run to crash/end, dump backtrace, exit
#   --break SYMBOL  Set a breakpoint before running (can be used multiple times)
#   --commands CMDS Semicolon-separated GDB commands to execute
#   --interactive   Force interactive mode (default when no --batch/--commands)
#   --process N     Replay a specific process in a multi-process trace
#
# Examples (agent use):
#   # Record, then replay with a breakpoint:
#   TRACE=$(bash dev_tools/rr-record.sh --target harness --rootfs R)
#   bash dev_tools/rr-replay.sh "$TRACE" --batch --break "litebox_shim_linux::syscalls::pipe::do_pipe2"
#
#   # Replay with custom commands (reverse-continue from crash):
#   bash dev_tools/rr-replay.sh "$TRACE" --commands "run;reverse-continue;bt full;info locals"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TRACE_BASE="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/rr-traces"

# Verify rr is available.
if ! command -v rr &>/dev/null; then
    echo "ERROR: rr not found. Install with: sudo apt install rr" >&2
    exit 1
fi

# Parse arguments.
TRACE_DIR=""
BATCH=false
INTERACTIVE=false
BREAKPOINTS=()
COMMANDS=""
PROCESS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --batch)
            BATCH=true
            shift
            ;;
        --interactive)
            INTERACTIVE=true
            shift
            ;;
        --break)
            BREAKPOINTS+=("$2")
            shift 2
            ;;
        --commands)
            COMMANDS="$2"
            shift 2
            ;;
        --process)
            PROCESS="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            TRACE_DIR="$1"
            shift
            ;;
    esac
done

# If no trace dir specified, find the most recent one.
if [[ -z "$TRACE_DIR" ]]; then
    if [[ -d "$TRACE_BASE" ]]; then
        LATEST=$(find "$TRACE_BASE" -maxdepth 2 -name "trace" -type d 2>/dev/null | sort -r | head -1)
        if [[ -n "$LATEST" ]]; then
            TRACE_DIR="$LATEST"
            echo "Using latest trace: $TRACE_DIR" >&2
        else
            echo "ERROR: No traces found in $TRACE_BASE" >&2
            echo "Record one first: bash dev_tools/rr-record.sh --target ..." >&2
            exit 1
        fi
    else
        echo "ERROR: No trace directory specified and $TRACE_BASE does not exist" >&2
        exit 1
    fi
fi

if [[ ! -d "$TRACE_DIR" ]]; then
    echo "ERROR: Trace directory not found: $TRACE_DIR" >&2
    exit 1
fi

# Build rr replay command.
RR_ARGS=(replay "$TRACE_DIR")
if [[ -n "$PROCESS" ]]; then
    RR_ARGS+=(-p "$PROCESS")
fi

if $BATCH || [[ -n "$COMMANDS" ]] || [[ ${#BREAKPOINTS[@]} -gt 0 && ! $INTERACTIVE ]]; then
    # Non-interactive mode.
    GDB_CMDS=()
    GDB_CMDS+=(-ex "set pagination off")
    GDB_CMDS+=(-ex "set print pretty on")
    GDB_CMDS+=(-ex "set print elements 0")

    # Set breakpoints.
    for bp in "${BREAKPOINTS[@]}"; do
        GDB_CMDS+=(-ex "break $bp")
    done

    if [[ -n "$COMMANDS" ]]; then
        # Execute user-specified commands.
        IFS=';' read -ra CMD_LIST <<< "$COMMANDS"
        for cmd in "${CMD_LIST[@]}"; do
            cmd="$(echo "$cmd" | xargs)"  # trim whitespace
            if [[ -n "$cmd" ]]; then
                GDB_CMDS+=(-ex "$cmd")
            fi
        done
    else
        # Default batch behavior: run to crash/breakpoint, dump info.
        GDB_CMDS+=(-ex "continue")
        GDB_CMDS+=(-ex "echo \n=== rr-replay: stopped ===\n")
        GDB_CMDS+=(-ex "info threads")
        GDB_CMDS+=(-ex "echo \n=== Backtrace ===\n")
        GDB_CMDS+=(-ex "bt full")
        GDB_CMDS+=(-ex "echo \n=== Locals ===\n")
        GDB_CMDS+=(-ex "info locals")
    fi
    GDB_CMDS+=(-ex "quit")

    echo "=== rr-replay: batch mode ===" >&2
    echo "=== Trace: $TRACE_DIR ===" >&2
    rr "${RR_ARGS[@]}" "${GDB_CMDS[@]}"
else
    # Interactive mode.
    GDB_CMDS=()
    GDB_CMDS+=(-ex "set pagination off")
    GDB_CMDS+=(-ex "set print pretty on")

    for bp in "${BREAKPOINTS[@]}"; do
        GDB_CMDS+=(-ex "break $bp")
    done

    echo "=== rr-replay: interactive mode ===" >&2
    echo "=== Trace: $TRACE_DIR ===" >&2
    echo "=== Tips: 'reverse-continue', 'reverse-step', 'reverse-next' for time-travel ===" >&2
    rr "${RR_ARGS[@]}" "${GDB_CMDS[@]}"
fi
