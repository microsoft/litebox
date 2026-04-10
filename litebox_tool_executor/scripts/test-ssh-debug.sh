#!/bin/bash
# Quick test: start SSH server, try one command, show all logs
set -u

EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"
LOGFILE="/tmp/litebox-ssh-debug.log"

rm -f "$LOGFILE"

echo "=== Starting server ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline 2>"$LOGFILE" &
PID=$!
sleep 5

echo "=== Server log so far ==="
cat "$LOGFILE"
echo ""

echo "=== Connecting with SSH ==="
timeout 10 ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 user@127.0.0.1 "echo HELLO" 2>&1

echo ""
echo "=== Server log after connection ==="
cat "$LOGFILE"

echo ""
echo "=== Cleanup ==="
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "DONE"
