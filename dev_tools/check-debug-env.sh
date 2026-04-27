#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# check-debug-env.sh — Validate that debugging prerequisites are available.
#
# Usage: bash dev_tools/check-debug-env.sh
#
# Checks:
#   1. rust-gdb is installed and has Rust pretty-printers
#   2. rr is installed and PMU hardware counters are available
#      (rr requires hardware perf counters; WSL2's Hyper-V VM does
#       not virtualize PMU, so rr typically does NOT work under WSL2)
#   3. Debug symbols are present in built binaries
#   4. Required litebox binaries exist (runner, broker, tool_executor)
#
# Exit code 0 if GDB checks pass (rr is optional), 1 if GDB checks fail.

set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  ✓ $1"; ((PASS++)); }
fail() { echo "  ✗ $1"; ((FAIL++)); }
warn() { echo "  ⚠ $1"; ((WARN++)); }

echo "=== Debug Environment Check ==="
echo

# --- 1. rust-gdb ---
echo "[1] GDB / rust-gdb"
if command -v rust-gdb &>/dev/null; then
    GDB_VERSION=$(rust-gdb --batch -ex "show version" 2>/dev/null | head -1)
    pass "rust-gdb found: $GDB_VERSION"
elif command -v gdb &>/dev/null; then
    GDB_VERSION=$(gdb --batch -ex "show version" 2>/dev/null | head -1)
    warn "gdb found but rust-gdb not found (no Rust pretty-printers): $GDB_VERSION"
    echo "       Install with: rustup component add rust-gdb (or install via rustup)"
else
    fail "Neither gdb nor rust-gdb found"
    echo "       Install with: sudo apt install gdb && rustup component add rust-gdb"
fi

# --- 2. rr (optional — does NOT work under WSL2) ---
echo "[2] rr (record-replay debugger) [optional]"
RR_AVAILABLE=false
if ! command -v rr &>/dev/null; then
    warn "rr not installed (optional — install with: sudo apt install rr)"
else
    RR_VERSION=$(rr version 2>/dev/null || echo "unknown")
    # rr requires hardware PMU counters. WSL2's Hyper-V VM does not
    # virtualize the PMU, so perf_event_open fails even when
    # perf_event_paranoid is permissive.  Test by actually trying rr.
    if rr record --output-trace-dir /tmp/rr-check-$$ true 2>/dev/null; then
        rm -rf /tmp/rr-check-$$
        pass "rr $RR_VERSION works (PMU counters available)"
        RR_AVAILABLE=true
    else
        rm -rf /tmp/rr-check-$$ 2>/dev/null
        # Check if this is a WSL2 environment.
        if grep -qi microsoft /proc/version 2>/dev/null; then
            warn "rr $RR_VERSION installed but PMU counters unavailable (WSL2 does not virtualize PMU hardware)"
            echo "       rr requires hardware performance counters that Hyper-V does not expose to the WSL2 VM."
            echo "       Use debug-runner.sh (GDB) instead. rr-record.sh / rr-replay.sh will not work."
        else
            warn "rr $RR_VERSION installed but perf_event_open failed"
            echo "       Check: /proc/sys/kernel/perf_event_paranoid (must be ≤ 1)"
            echo "       Check: hardware PMU support (VM guests need PMU virtualization enabled)"
        fi
    fi
fi

# --- 3. Debug symbols in built binaries ---
echo "[3] Debug symbols"

# Find the workspace root (script may be called from any directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}/debug"

check_debug_symbols() {
    local binary_name="$1"
    local binary_path="$TARGET_DIR/$binary_name"
    if [[ -f "$binary_path" ]]; then
        if readelf -S "$binary_path" 2>/dev/null | grep -q '\.debug_info'; then
            pass "$binary_name has debug symbols"
        else
            warn "$binary_name exists but has no .debug_info section (release build?)"
        fi
    else
        warn "$binary_name not found at $binary_path (not built yet?)"
    fi
}

check_debug_symbols "litebox_runner_linux_userland"
check_debug_symbols "litebox_broker"
check_debug_symbols "litebox_tool_executor"
check_debug_symbols "litebox_test_harness"

# --- 4. Required binaries ---
echo "[4] Required binaries"

check_binary() {
    local binary_name="$1"
    local binary_path="$TARGET_DIR/$binary_name"
    if [[ -f "$binary_path" ]]; then
        pass "$binary_name found at $binary_path"
    else
        fail "$binary_name not found at $binary_path"
        echo "       Build with: cargo build -p $binary_name"
    fi
}

check_binary "litebox_runner_linux_userland"
check_binary "litebox_broker"
check_binary "litebox_tool_executor"
check_binary "litebox_test_harness"

# --- Summary ---
echo
echo "=== Summary: $PASS passed, $FAIL failed, $WARN warnings ==="

if (( FAIL > 0 )); then
    echo "Some checks failed. Fix the issues above before using debug scripts."
    exit 1
else
    echo "Environment is ready for debugging."
    exit 0
fi
