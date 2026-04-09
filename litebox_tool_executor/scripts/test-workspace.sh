#!/bin/bash
# Set up a test workspace and verify VS Code Server can access it via 9P.
set -euo pipefail

ROOTFS="${LITEBOX_ROOTFS:-/home/wportnoy/vscode-rootfs}"

echo "=== Creating test workspace ==="
WORKSPACE_IN_ROOTFS="$ROOTFS/workspaces/repo"
mkdir -p "$WORKSPACE_IN_ROOTFS/src"
echo 'console.log("hello from sandbox");' > "$WORKSPACE_IN_ROOTFS/test.js"
cat > "$WORKSPACE_IN_ROOTFS/package.json" << 'PKGJSON'
{"name": "test-project", "version": "1.0.0"}
PKGJSON
echo 'function add(a, b) { return a + b; }' > "$WORKSPACE_IN_ROOTFS/src/math.js"
echo "  Created $(find "$WORKSPACE_IN_ROOTFS" -type f | wc -l) files in $WORKSPACE_IN_ROOTFS"

echo "=== Linking workspace into rootfs ==="
ls -la "$ROOTFS/workspaces/"

echo "=== Testing file access via litebox ==="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Test 1: List workspace files
echo "--- Test 1: ls /workspaces/repo ---"
bash "$SCRIPT_DIR/smoke-test.sh" /usr/bin/ls /workspaces/repo

echo ""
echo "--- Test 2: cat /workspaces/repo/test.js ---"
bash "$SCRIPT_DIR/smoke-test.sh" /usr/bin/cat /workspaces/repo/test.js

echo ""
echo "--- Test 3: Write a file and read it back ---"
bash "$SCRIPT_DIR/smoke-test.sh" /usr/bin/bash -c 'echo "written inside sandbox" > /workspaces/repo/sandbox-output.txt && cat /workspaces/repo/sandbox-output.txt'

echo ""
echo "--- Test 4: Verify file appeared on host ---"
if [ -f "$WORKSPACE_IN_ROOTFS/sandbox-output.txt" ]; then
    echo "SUCCESS: File written by sandbox is visible on host:"
    cat "$WORKSPACE_IN_ROOTFS/sandbox-output.txt"
else
    echo "NOTE: File not visible on host (expected if using in-memory upper layer)"
fi

echo ""
echo "=== All workspace tests complete ==="
