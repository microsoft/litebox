#!/bin/bash
# Debug: try starting the server WITHOUT --record-baseline and check errors
set -u
EXECUTOR="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
ROOTFS="/home/wportnoy/vscode-rootfs"

echo "=== Test without --record-baseline ==="
timeout 8 "$EXECUTOR" --rootfs "$ROOTFS" --vscode-server 2>&1 | head -20
echo ""
echo "=== Test with --record-baseline ==="
timeout 8 "$EXECUTOR" --rootfs "$ROOTFS" --vscode-server --record-baseline 2>&1 | head -20
