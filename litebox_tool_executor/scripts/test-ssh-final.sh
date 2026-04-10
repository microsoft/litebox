#!/bin/bash
# Test SSH exec with full debug output (all in one stream)
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

echo "=== Starting server ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline &
PID=$!

# Wait for SSH server to be ready
for i in $(seq 1 15); do
    if ss -tlnp 2>/dev/null | grep -q ":2222"; then
        break
    fi
    sleep 1
done
echo "Server PID=$PID, port 2222"

echo ""
echo "=== Test: ssh echo HELLO ==="
timeout 10 ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 user@127.0.0.1 "echo HELLO" 2>&1
echo "Exit: $?"

echo ""
echo "=== Cleanup ==="
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "DONE"
