#!/bin/bash
# Test sshd e2e - verbose output
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

echo "=== Starting sshd in sandbox ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline 2>&1 &
PID=$!
sleep 8

echo ""
echo "=== SSH connection attempt ==="
timeout 15 ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PasswordAuthentication=yes -o PreferredAuthentications=password,none \
    -p 2222 root@127.0.0.1 "echo HELLO" 2>&1 | tail -30

echo ""
echo "=== Cleanup ==="
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "DONE"
