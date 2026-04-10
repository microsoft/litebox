#!/bin/bash
# Debug: check if broker socket exists while server is running
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline &
PID=$!
sleep 5

echo "=== Tool executor PID: $PID ==="
echo "=== Looking for broker socket ==="
ls -la /tmp/litebox-broker-*.sock 2>/dev/null || echo "NO SOCKETS FOUND"
echo ""
echo "=== Child processes ==="
ps --forest -p $PID -o pid,ppid,comm 2>/dev/null || ps -f --ppid $PID 2>/dev/null || echo "ps failed"
echo ""
echo "=== All litebox processes ==="
ps aux | grep litebox | grep -v grep

kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
