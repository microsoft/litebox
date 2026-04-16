#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p results

SERVER_DIR=$(ls -d $HOME/.vscode-server/bin/*/out/server-main.js 2>/dev/null | head -1)
NODE=$(ls -d $HOME/.vscode-server/bin/*/node 2>/dev/null | head -1)

if [ -z "$NODE" ] || [ -z "$SERVER_DIR" ]; then
    echo "ERROR: VS Code Server not found in ~/.vscode-server/"
    exit 1
fi

echo "Node: $NODE"
echo "Server: $SERVER_DIR"
echo ""
echo "Starting VS Code Server under strace -c for 30s..."

timeout 30 strace -f -c "$NODE" "$SERVER_DIR" \
    --port 9999 --without-connection-token --accept-server-license-terms \
    2>results/syscall_summary.txt || true

echo ""
echo "=== Syscall Summary ==="
cat results/syscall_summary.txt

echo ""
echo "=== Running gap analysis ==="
python3 analyze-syscall-gaps.py results/syscall_summary.txt
