#!/bin/bash
# Test sftp-server inside litebox directly (outside SSH)
set -u
ROOTFS="/home/wportnoy/vscode-rootfs"
BROKER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_broker"
RUNNER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_runner_linux_userland"
SOCKET="/tmp/litebox-sftp-test.sock"

rm -f "$SOCKET"
"$BROKER" --root-dir "$ROOTFS" --rewrite-syscalls --network-proxy-listen "$SOCKET" 2>/dev/null &
BPID=$!
sleep 2

echo "=== Test 1: sftp-server -e (stderr logging) ==="
echo "" | timeout 5 "$RUNNER" --unstable \
    --network-broker "$SOCKET" --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin" --env "HOME=/root" \
    -- /usr/lib/openssh/sftp-server -e 2>&1
echo "Exit: $?"

echo ""
echo "=== Test 2: check if sftp-server binary loads ==="
timeout 5 "$RUNNER" --unstable \
    --network-broker "$SOCKET" --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin" --env "HOME=/root" \
    -- /usr/bin/ls -la /usr/lib/openssh/sftp-server 2>&1 | grep -v "^{"
echo "Exit: $?"

echo ""
echo "=== Test 3: check /etc/passwd ==="
timeout 5 "$RUNNER" --unstable \
    --network-broker "$SOCKET" --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin" --env "HOME=/root" \
    -- /usr/bin/cat /etc/passwd 2>&1 | grep -v "^{"
echo "Exit: $?"

kill $BPID 2>/dev/null
wait $BPID 2>/dev/null || true
rm -f "$SOCKET"
