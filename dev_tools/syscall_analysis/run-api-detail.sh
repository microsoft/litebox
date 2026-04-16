#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results

SERVER_DIR=$(ls -d $HOME/.vscode-server/bin/*/out/server-main.js 2>/dev/null | head -1)
NODE=$(ls -d $HOME/.vscode-server/bin/*/node 2>/dev/null | head -1)

echo "Recording socket/ioctl/fork detail for 15s..."
timeout 15 strace -f -v \
    -e trace=socket,connect,ioctl,setsockopt,getsockname,bind,listen,clone,clone3,execve,pipe2,dup2,dup3,socketpair \
    -o results/api_detail.log \
    "$NODE" "$SERVER_DIR" --port 9998 --without-connection-token --accept-server-license-terms \
    2>/dev/null || true

echo ""
echo "=== Socket address families ==="
grep 'socket(' results/api_detail.log | sed 's/.*socket(/socket(/' | sort | uniq -c | sort -rn

echo ""
echo "=== Connect targets ==="
grep 'connect(' results/api_detail.log | head -20

echo ""
echo "=== Ioctl (network-related) ==="
grep -i 'ioctl.*sioc\|ioctl.*FIONREAD\|ioctl.*TIOC' results/api_detail.log | head -10

echo ""
echo "=== Fork (non-thread clone) ==="
echo -n "Count: "; grep -c 'clone(child_stack=NULL' results/api_detail.log
grep 'clone(child_stack=NULL' results/api_detail.log | head -5

echo ""
echo "=== Thread clone3 ==="
echo -n "Count: "; grep -c 'clone3.*CLONE_VM' results/api_detail.log

echo ""
echo "=== Pipe/socketpair ==="
echo -n "Count: "; grep -cE 'pipe2|socketpair' results/api_detail.log
grep -E 'pipe2|socketpair' results/api_detail.log | head -10

echo ""
echo "=== Dup2/dup3 ==="
echo -n "Count: "; grep -cE 'dup[23]' results/api_detail.log
grep -E 'dup[23]' results/api_detail.log | head -10
