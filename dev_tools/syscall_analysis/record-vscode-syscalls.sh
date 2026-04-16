#!/bin/bash
# Record the syscall profile of VS Code Remote Server using strace.
#
# Run this on bare Linux (not inside LiteBox) to capture the complete
# syscall profile without early-failure masking.
#
# Usage:
#   # Record with a VS Code Server binary:
#   ./record-vscode-syscalls.sh /path/to/code-server
#
#   # Or attach to a running VS Code Server:
#   ./record-vscode-syscalls.sh --pid $(pgrep -f "code-server")
#
# Outputs:
#   results/syscall_summary.txt    — strace -c output (counts per syscall)
#   results/syscall_unique.txt     — sorted unique syscall names
#   results/syscall_details.log    — detailed trace for key syscalls
#   results/socket_families.txt    — socket() address family usage

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

# Parse arguments.
PID=""
SERVER_CMD=""
DURATION=120  # seconds to run before stopping

if [ "${1:-}" = "--pid" ]; then
    PID="${2:?Usage: $0 --pid <PID>}"
    echo "Attaching to PID $PID"
elif [ -n "${1:-}" ]; then
    SERVER_CMD="$1"
    shift
    echo "Will launch: $SERVER_CMD $*"
else
    echo "Usage: $0 <code-server-path> [args...]"
    echo "       $0 --pid <PID>"
    exit 1
fi

echo "Results will be saved to: $RESULTS_DIR"
echo ""

# ─── Step 1: Syscall count summary ───────────────────────────────────────────
echo "=== Step 1: Syscall count summary (strace -c) ==="

if [ -n "$PID" ]; then
    echo "Attaching to PID $PID for ${DURATION}s..."
    timeout "$DURATION" strace -f -c -p "$PID" 2>"$RESULTS_DIR/syscall_summary.txt" || true
else
    echo "Running server for ${DURATION}s..."
    timeout "$DURATION" strace -f -c "$SERVER_CMD" "$@" 2>"$RESULTS_DIR/syscall_summary.txt" || true
fi

echo "Summary saved to $RESULTS_DIR/syscall_summary.txt"
echo ""

# ─── Step 2: Detailed trace for key syscalls ─────────────────────────────────
echo "=== Step 2: Detailed trace (key syscalls only) ==="

KEY_SYSCALLS="socket,connect,bind,listen,accept4,openat,open,execve,clone,clone3,fork,vfork,dup,dup2,dup3,pipe,pipe2,ioctl,fcntl,prctl,arch_prctl,signalfd4,eventfd2,inotify_init1,timerfd_create,memfd_create,mmap,mprotect,sched_setaffinity,sched_getaffinity,flock,sendfile,splice,tee,copy_file_range,statx,io_uring_setup,io_uring_enter,seccomp,unshare,setns"

if [ -n "$PID" ]; then
    timeout "$DURATION" strace -f -e "trace=$KEY_SYSCALLS" -p "$PID" \
        2>"$RESULTS_DIR/syscall_details.log" || true
else
    timeout "$DURATION" strace -f -e "trace=$KEY_SYSCALLS" "$SERVER_CMD" "$@" \
        2>"$RESULTS_DIR/syscall_details.log" || true
fi

echo "Details saved to $RESULTS_DIR/syscall_details.log"
echo ""

# ─── Step 3: Extract unique syscall names ────────────────────────────────────
echo "=== Step 3: Extracting unique syscall names ==="

# From the summary, extract syscall names (last column in strace -c output).
grep -oP '^\s+[\d.]+\s+[\d.]+\s+\d+\s+\d+\s+\d+\s+\K\S+' \
    "$RESULTS_DIR/syscall_summary.txt" | sort -u > "$RESULTS_DIR/syscall_unique.txt" 2>/dev/null || true

# Fallback: parse from detail log if summary parsing fails.
if [ ! -s "$RESULTS_DIR/syscall_unique.txt" ]; then
    grep -oP '^\d+\s+\K[a-z_0-9]+(?=\()' "$RESULTS_DIR/syscall_details.log" \
        | sort -u > "$RESULTS_DIR/syscall_unique.txt" 2>/dev/null || true
fi

# Also try parsing the summary table format directly.
if [ ! -s "$RESULTS_DIR/syscall_unique.txt" ]; then
    awk '/^---/{found=1; next} found && NF>=6 {print $NF}' \
        "$RESULTS_DIR/syscall_summary.txt" | sort -u > "$RESULTS_DIR/syscall_unique.txt"
fi

UNIQUE_COUNT=$(wc -l < "$RESULTS_DIR/syscall_unique.txt")
echo "Found $UNIQUE_COUNT unique syscalls"
echo "Saved to $RESULTS_DIR/syscall_unique.txt"
echo ""

# ─── Step 4: Socket address family analysis ──────────────────────────────────
echo "=== Step 4: Socket address family usage ==="

{
    echo "# Socket address families used by VS Code Server"
    echo "# AF_UNIX=1, AF_INET=2, AF_INET6=10, AF_NETLINK=16"
    echo ""
    grep -oP 'socket\(\K[A-Z_]+' "$RESULTS_DIR/syscall_details.log" 2>/dev/null \
        | sort | uniq -c | sort -rn || echo "(no socket calls captured in detail log)"
} > "$RESULTS_DIR/socket_families.txt"

echo "Socket families saved to $RESULTS_DIR/socket_families.txt"
cat "$RESULTS_DIR/socket_families.txt"
echo ""

# ─── Done ────────────────────────────────────────────────────────────────────
echo "=== Recording complete ==="
echo ""
echo "Files:"
ls -lh "$RESULTS_DIR/"
echo ""
echo "Next step: run analyze-syscall-gaps.py to compare against LiteBox shim"
