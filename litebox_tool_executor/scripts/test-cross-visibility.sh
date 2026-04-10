#!/bin/bash
# Test if cross-runner file visibility works
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

# Ensure the .tar.gz file exists in rootfs
if [ ! -f "$ROOTFS/root/.vscode-server/vscode-cli-41dd792b5e652393e7787322889ed5fdc58bd75b.tar.gz" ]; then
    echo "ERROR: No tar.gz in rootfs, run VS Code connect first"
    exit 1
fi

echo "=== File on host ==="
ls -la "$ROOTFS/root/.vscode-server/"*.tar.gz* 2>/dev/null

echo ""
echo "=== Starting server ==="
"$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline &
PID=$!
sleep 5

echo ""
echo "=== Test: can a new SSH exec see the file? ==="
timeout 5 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 user@127.0.0.1 "test -f /root/.vscode-server/vscode-cli-41dd792b5e652393e7787322889ed5fdc58bd75b.tar.gz && echo FILE_FOUND || echo FILE_NOT_FOUND; ls /root/.vscode-server/" 2>&1

echo ""
echo "=== Cleanup ==="
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "DONE"
