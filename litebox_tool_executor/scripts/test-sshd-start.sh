#!/bin/bash
# Test: can sshd start inside litebox?
set -u
ROOTFS="/home/wportnoy/vscode-rootfs"
BROKER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_broker"
RUNNER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_runner_linux_userland"
SOCKET="/tmp/litebox-sshd-test.sock"

rm -f "$SOCKET"
"$BROKER" --root-dir "$ROOTFS" --rewrite-syscalls --network-proxy-listen "$SOCKET" 2>/dev/null &
BPID=$!
sleep 2

echo "=== Starting sshd inside litebox ==="
timeout 5 "$RUNNER" --unstable \
    --network-broker "$SOCKET" --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin" \
    --env "HOME=/root" \
    -- /usr/sbin/sshd -D -e 2>&1 | head -30
echo "Exit: $?"

kill $BPID 2>/dev/null
wait $BPID 2>/dev/null || true
rm -f "$SOCKET"
