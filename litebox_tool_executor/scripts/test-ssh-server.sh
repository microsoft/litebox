#!/bin/bash
# Test the embedded SSH server.
set -u

EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"
LOG="/tmp/litebox-ssh-test-stderr.log"

echo "=== Starting LiteBox with embedded SSH ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server 2>"$LOG" &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for SSH server to start by watching stderr log
PORT=""
for i in $(seq 1 15); do
    PORT=$(grep -oP 'listening on 127\.0\.0\.1:\K\d+' "$LOG" 2>/dev/null | head -1)
    if [ -n "$PORT" ]; then
        break
    fi
    sleep 1
done

echo "=== Server log ==="
cat "$LOG"
echo ""

if [ -z "$PORT" ]; then
    echo "ERROR: Could not determine SSH port after 15s"
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "=== SSH server on port $PORT, testing connection ==="
timeout 5 ssh -v \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PasswordAuthentication=yes \
    -p "$PORT" \
    user@127.0.0.1 \
    echo "SSH_CONNECTION_WORKS" 2>&1 || true

echo ""
echo "=== Cleaning up ==="
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true
echo "DONE"
