#!/bin/bash
# Test the full sshd-in-sandbox architecture
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

echo "=== Starting sshd in sandbox ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline &
PID=$!
sleep 8

echo ""
echo "=== Testing SSH connection ==="
timeout 10 ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 root@127.0.0.1 "echo HELLO_FROM_SSHD_SANDBOX; uname -a; whoami" 2>&1 | \
    grep -E "HELLO|Linux|root|Authenticated|Connection|debug1: Sending|error|Error"

echo ""
echo "Exit: $?"
echo "=== Cleanup ==="
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "DONE"
