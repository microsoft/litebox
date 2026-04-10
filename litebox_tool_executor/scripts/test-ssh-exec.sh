#!/bin/bash
# Test that the SSH server runs VS Code's requested command inside litebox.
set -u

EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"
LOG="/tmp/litebox-ssh-exec-test.log"

echo "=== Starting LiteBox SSH server ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline 2>"$LOG" &
SERVER_PID=$!

# Wait for SSH server
PORT=""
for i in $(seq 1 15); do
    PORT=$(grep -oP 'listening on 0\.0\.0\.0:\K\d+' "$LOG" 2>/dev/null | head -1)
    [ -n "$PORT" ] && break
    sleep 1
done

if [ -z "$PORT" ]; then
    echo "ERROR: Could not find SSH port"
    cat "$LOG"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

echo "SSH on port $PORT"

# Test 1: simple exec (like ssh litebox 'echo hello')
echo "=== Test 1: exec 'echo hello' ==="
timeout 10 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$PORT" user@127.0.0.1 "echo HELLO_FROM_LITEBOX" 2>&1 || true

echo ""

# Test 2: pipe a script into sh (like VS Code does)
echo "=== Test 2: pipe script into sh (VS Code style) ==="
echo 'echo PLATFORM=linux; echo VSCODE_OK; uname -a' | \
    timeout 10 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -T -p "$PORT" user@127.0.0.1 sh 2>&1 || true

echo ""

# Test 3: check if VS Code Server is findable
echo "=== Test 3: check server path ==="
timeout 10 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p "$PORT" user@127.0.0.1 "ls -la /root/.vscode-server/bin/" 2>&1 || true

echo ""
echo "=== Server log ==="
tail -5 "$LOG"

echo ""
echo "=== Cleanup ==="
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true
echo "DONE"
