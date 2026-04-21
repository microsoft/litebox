#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# debug-runner.sh — Run litebox components under GDB in batch mode.
#
# Usage:
#   bash dev_tools/debug-runner.sh --target runner --rootfs /path/to/rootfs -- /program args...
#   bash dev_tools/debug-runner.sh --target tool-executor -- --rootfs /path/to/rootfs -- /program args...
#   bash dev_tools/debug-runner.sh --target integration
#   bash dev_tools/debug-runner.sh --target harness --rootfs /path/to/rootfs
#
# Targets:
#   runner          Debug litebox_runner_linux_userland directly (manages broker)
#   tool-executor   Debug litebox_tool_executor (includes broker + runner spawn)
#   integration     Debug the integration test binary
#   harness         Debug test harness inside runner (alias for runner with harness args)
#
# Environment:
#   LITEBOX_GDB       Override GDB binary (default: rust-gdb, fallback: gdb)
#   LITEBOX_GDB_CMDS  Extra GDB commands to run (semicolon-separated)
#   CARGO_TARGET_DIR  Override target directory (default: <workspace>/target)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/debug"

# Find GDB.
find_gdb() {
    if [[ -n "${LITEBOX_GDB:-}" ]]; then
        echo "$LITEBOX_GDB"
    elif command -v rust-gdb &>/dev/null; then
        echo "rust-gdb"
    elif command -v gdb &>/dev/null; then
        echo "gdb"
    else
        echo "ERROR: Neither rust-gdb nor gdb found. Install with: sudo apt install gdb" >&2
        exit 1
    fi
}

GDB="$(find_gdb)"

# Parse arguments.
TARGET=""
ROOTFS=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --rootfs)
            ROOTFS="$2"
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

if [[ -z "$TARGET" ]]; then
    echo "Usage: debug-runner.sh --target {runner|tool-executor|integration|harness} [--rootfs PATH] [-- args...]"
    exit 1
fi

# GDB batch commands: run, catch signals, dump backtrace on crash.
GDB_BATCH_CMDS=(
    -ex "set pagination off"
    -ex "set print pretty on"
    -ex "set print elements 0"
    -ex "set follow-fork-mode parent"
    -ex "set detach-on-fork on"
    -ex "handle SIGSYS nostop noprint pass"  # seccomp SIGSYS must pass through
    -ex "run"
    -ex "echo \n=== GDB: Program stopped ===\n"
    -ex "info threads"
    -ex "echo \n=== Backtrace (current thread) ===\n"
    -ex "bt full"
    -ex "echo \n=== All threads ===\n"
    -ex "thread apply all bt"
)

# Add user-specified extra GDB commands.
if [[ -n "${LITEBOX_GDB_CMDS:-}" ]]; then
    IFS=';' read -ra CUSTOM_CMDS <<< "$LITEBOX_GDB_CMDS"
    for cmd in "${CUSTOM_CMDS[@]}"; do
        GDB_BATCH_CMDS+=(-ex "$cmd")
    done
fi

GDB_BATCH_CMDS+=(-ex "quit")

# Find a binary or die.
require_binary() {
    local name="$1"
    local path="$TARGET_DIR/$name"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: $name not found at $path" >&2
        echo "Build with: cargo build -p $name" >&2
        exit 1
    fi
    echo "$path"
}

# Start broker as a background process, return PID and socket path.
BROKER_PID=""
BROKER_SOCKET=""
start_broker() {
    local rootfs="$1"
    local broker
    broker="$(require_binary litebox_broker)"
    BROKER_SOCKET="/tmp/litebox-debug-broker-$$.sock"
    rm -f "$BROKER_SOCKET"

    local broker_args=(
        --network-proxy-listen "$BROKER_SOCKET"
        --rewrite-syscalls
    )
    if [[ -d "$rootfs" ]]; then
        broker_args+=(--root-dir "$rootfs")
    fi

    "$broker" "${broker_args[@]}" >/dev/null 2>/dev/null &
    BROKER_PID=$!

    # Wait for socket to appear.
    for _ in $(seq 1 50); do
        if [[ -S "$BROKER_SOCKET" ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "WARNING: Broker socket not found after 5s (broker PID=$BROKER_PID)" >&2
}

cleanup_broker() {
    if [[ -n "$BROKER_PID" ]]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
        rm -f "$BROKER_SOCKET"
        BROKER_PID=""
    fi
}
trap cleanup_broker EXIT

# Build runner command line (mirrors tool_executor's runner_command logic).
build_runner_cmd() {
    local rootfs="$1"
    shift
    local runner
    runner="$(require_binary litebox_runner_linux_userland)"

    local cmd=("$runner" "--unstable")

    if [[ -d "$rootfs" ]]; then
        # Directory rootfs: 9P mode.
        if [[ -n "$BROKER_SOCKET" ]]; then
            cmd+=(--nine-p-broker "$BROKER_SOCKET")
        fi
    else
        # Tar rootfs.
        cmd+=(--initial-files "$rootfs" --program-from-tar)
    fi

    if [[ -n "$BROKER_SOCKET" ]]; then
        cmd+=(--network-broker "$BROKER_SOCKET")
    fi

    cmd+=(
        --env "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib"
        --env "HOME=/root"
        --env "PATH=/usr/local/bin:/usr/bin:/bin"
        --env "TERM=dumb"
        --guest-uid 0 --guest-euid 0 --guest-gid 0 --guest-egid 0
        --
    )
    cmd+=("$@")
    echo "${cmd[@]}"
}

case "$TARGET" in
    runner)
        if [[ -z "$ROOTFS" ]]; then
            echo "ERROR: --rootfs is required for --target runner" >&2
            exit 1
        fi
        start_broker "$ROOTFS"
        RUNNER_CMD=($(build_runner_cmd "$ROOTFS" "${EXTRA_ARGS[@]}"))
        echo "=== debug-runner: target=runner ===" >&2
        echo "=== GDB: $GDB ===" >&2
        echo "=== Command: ${RUNNER_CMD[*]} ===" >&2
        "$GDB" -batch "${GDB_BATCH_CMDS[@]}" --args "${RUNNER_CMD[@]}"
        ;;

    tool-executor)
        TOOL_EXECUTOR="$(require_binary litebox_tool_executor)"
        echo "=== debug-runner: target=tool-executor ===" >&2
        echo "=== GDB: $GDB ===" >&2
        echo "=== Command: $TOOL_EXECUTOR ${EXTRA_ARGS[*]} ===" >&2
        "$GDB" -batch "${GDB_BATCH_CMDS[@]}" --args "$TOOL_EXECUTOR" "${EXTRA_ARGS[@]}"
        ;;

    integration)
        # Find the integration test binary.
        INTEGRATION_BIN=$(find "$TARGET_DIR/deps" -name 'integration-*' -executable -type f 2>/dev/null | head -1)
        if [[ -z "$INTEGRATION_BIN" ]]; then
            echo "ERROR: Integration test binary not found." >&2
            echo "Build with: cargo test -p litebox_test_harness --test integration --no-run" >&2
            exit 1
        fi
        echo "=== debug-runner: target=integration ===" >&2
        echo "=== GDB: $GDB ===" >&2
        echo "=== Binary: $INTEGRATION_BIN ===" >&2
        "$GDB" -batch "${GDB_BATCH_CMDS[@]}" --args "$INTEGRATION_BIN" "${EXTRA_ARGS[@]}"
        ;;

    harness)
        if [[ -z "$ROOTFS" ]]; then
            echo "ERROR: --rootfs is required for --target harness" >&2
            exit 1
        fi
        start_broker "$ROOTFS"
        # Default: run the test harness in spawn-tree mode.
        HARNESS_ARGS=("${EXTRA_ARGS[@]}")
        if [[ ${#HARNESS_ARGS[@]} -eq 0 ]]; then
            HARNESS_ARGS=("/litebox-test-harness" "spawn-tree")
        fi
        RUNNER_CMD=($(build_runner_cmd "$ROOTFS" "${HARNESS_ARGS[@]}"))
        echo "=== debug-runner: target=harness ===" >&2
        echo "=== GDB: $GDB ===" >&2
        echo "=== Command: ${RUNNER_CMD[*]} ===" >&2
        "$GDB" -batch "${GDB_BATCH_CMDS[@]}" --args "${RUNNER_CMD[@]}"
        ;;

    *)
        echo "ERROR: Unknown target '$TARGET'. Use: runner, tool-executor, integration, or harness" >&2
        exit 1
        ;;
esac
