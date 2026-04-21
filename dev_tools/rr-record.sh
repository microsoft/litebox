#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# rr-record.sh — Record a litebox session under rr for deterministic replay.
#
# Usage:
#   bash dev_tools/rr-record.sh --target runner --rootfs /path/to/rootfs -- /program args...
#   bash dev_tools/rr-record.sh --target tool-executor -- --rootfs /path/to/rootfs -- /program args...
#   bash dev_tools/rr-record.sh --target integration
#   bash dev_tools/rr-record.sh --target harness --rootfs /path/to/rootfs
#
# rr records the entire process tree (parent runner + worker hosts + broker).
# The trace is stored in target/rr-traces/<timestamp>/ for use with rr-replay.sh.
#
# Environment:
#   CARGO_TARGET_DIR  Override target directory (default: <workspace>/target)
#   RR_FLAGS          Extra flags to pass to rr record (e.g. "-n" for no syscall buffering)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/debug"
TRACE_BASE="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/rr-traces"

# Verify rr is available.
if ! command -v rr &>/dev/null; then
    echo "ERROR: rr not found. Install with: sudo apt install rr" >&2
    exit 1
fi

# Check perf_event_paranoid.
if [[ -f /proc/sys/kernel/perf_event_paranoid ]]; then
    PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
    if (( PARANOID > 1 )); then
        echo "ERROR: perf_event_paranoid=$PARANOID (must be ≤ 1 for rr)" >&2
        echo "Fix with: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid" >&2
        exit 1
    fi
fi

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
    echo "Usage: rr-record.sh --target {runner|tool-executor|integration|harness} [--rootfs PATH] [-- args...]"
    exit 1
fi

# Create trace output directory.
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TRACE_DIR="$TRACE_BASE/$TIMESTAMP"
mkdir -p "$TRACE_DIR"

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

# Broker management (same as debug-runner.sh).
BROKER_PID=""
BROKER_SOCKET=""
start_broker() {
    local rootfs="$1"
    local broker
    broker="$(require_binary litebox_broker)"
    BROKER_SOCKET="/tmp/litebox-rr-broker-$$.sock"
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

# Build runner command line.
build_runner_cmd() {
    local rootfs="$1"
    shift
    local runner
    runner="$(require_binary litebox_runner_linux_userland)"

    local cmd=("$runner" "--unstable")

    if [[ -d "$rootfs" ]]; then
        if [[ -n "$BROKER_SOCKET" ]]; then
            cmd+=(--nine-p-broker "$BROKER_SOCKET")
        fi
    else
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

# rr record flags.
RR_RECORD_FLAGS=(
    record
    --output-trace-dir "$TRACE_DIR/trace"
)
# Add user-specified rr flags.
if [[ -n "${RR_FLAGS:-}" ]]; then
    read -ra EXTRA_RR <<< "$RR_FLAGS"
    RR_RECORD_FLAGS+=("${EXTRA_RR[@]}")
fi

case "$TARGET" in
    runner)
        if [[ -z "$ROOTFS" ]]; then
            echo "ERROR: --rootfs is required for --target runner" >&2
            exit 1
        fi
        start_broker "$ROOTFS"
        RUNNER_CMD=($(build_runner_cmd "$ROOTFS" "${EXTRA_ARGS[@]}"))
        echo "=== rr-record: target=runner ===" >&2
        echo "=== Trace dir: $TRACE_DIR ===" >&2
        echo "=== Command: ${RUNNER_CMD[*]} ===" >&2
        rr "${RR_RECORD_FLAGS[@]}" "${RUNNER_CMD[@]}" || true
        ;;

    tool-executor)
        TOOL_EXECUTOR="$(require_binary litebox_tool_executor)"
        echo "=== rr-record: target=tool-executor ===" >&2
        echo "=== Trace dir: $TRACE_DIR ===" >&2
        echo "=== Command: $TOOL_EXECUTOR ${EXTRA_ARGS[*]} ===" >&2
        # rr records tool_executor + all children (broker, runner, workers).
        rr "${RR_RECORD_FLAGS[@]}" "$TOOL_EXECUTOR" "${EXTRA_ARGS[@]}" || true
        ;;

    integration)
        INTEGRATION_BIN=$(find "$TARGET_DIR/deps" -name 'integration-*' -executable -type f 2>/dev/null | head -1)
        if [[ -z "$INTEGRATION_BIN" ]]; then
            echo "ERROR: Integration test binary not found." >&2
            echo "Build with: cargo test -p litebox_test_harness --test integration --no-run" >&2
            exit 1
        fi
        echo "=== rr-record: target=integration ===" >&2
        echo "=== Trace dir: $TRACE_DIR ===" >&2
        echo "=== Binary: $INTEGRATION_BIN ===" >&2
        rr "${RR_RECORD_FLAGS[@]}" "$INTEGRATION_BIN" "${EXTRA_ARGS[@]}" || true
        ;;

    harness)
        if [[ -z "$ROOTFS" ]]; then
            echo "ERROR: --rootfs is required for --target harness" >&2
            exit 1
        fi
        start_broker "$ROOTFS"
        HARNESS_ARGS=("${EXTRA_ARGS[@]}")
        if [[ ${#HARNESS_ARGS[@]} -eq 0 ]]; then
            HARNESS_ARGS=("/litebox-test-harness" "spawn-tree")
        fi
        RUNNER_CMD=($(build_runner_cmd "$ROOTFS" "${HARNESS_ARGS[@]}"))
        echo "=== rr-record: target=harness ===" >&2
        echo "=== Trace dir: $TRACE_DIR ===" >&2
        echo "=== Command: ${RUNNER_CMD[*]} ===" >&2
        rr "${RR_RECORD_FLAGS[@]}" "${RUNNER_CMD[@]}" || true
        ;;

    *)
        echo "ERROR: Unknown target '$TARGET'. Use: runner, tool-executor, integration, or harness" >&2
        exit 1
        ;;
esac

echo >&2
echo "=== Recording complete ===" >&2
echo "=== Trace: $TRACE_DIR/trace ===" >&2
echo "=== Replay with: bash dev_tools/rr-replay.sh $TRACE_DIR/trace ===" >&2

# Write the trace path to stdout for scripting.
echo "$TRACE_DIR/trace"
