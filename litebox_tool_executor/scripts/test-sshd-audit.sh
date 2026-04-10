#!/bin/bash
# Test sshd inside litebox with audit analysis
set -u
ROOTFS="/home/wportnoy/vscode-rootfs"
BROKER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_broker"
RUNNER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_runner_linux_userland"
SOCKET="/tmp/litebox-sshd-test.sock"
AUDIT="/tmp/litebox-sshd-test.jsonl"

rm -f "$SOCKET" "$AUDIT"
"$BROKER" --root-dir "$ROOTFS" --rewrite-syscalls --network-proxy-listen "$SOCKET" 2>/dev/null &
BPID=$!
sleep 2

echo "=== Starting sshd inside litebox (5s) ==="
timeout 5 "$RUNNER" --unstable \
    --network-broker "$SOCKET" --nine-p-broker "$SOCKET" \
    --audit-log "$AUDIT" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin" \
    --env "HOME=/root" \
    -- /usr/sbin/sshd -D -e 2>&1 | grep -v "^{" || true

echo ""
echo "=== Audit: bind/listen/accept calls ==="
grep -E '"(bind|listen|accept|socket)"' "$AUDIT" 2>/dev/null | head -10

echo ""
echo "=== Audit: any errors ==="
grep 'sshd' "$AUDIT" 2>/dev/null | grep '"err"' | grep -v Newfstatat | grep -v Access | head -10

echo ""
echo "=== Audit: unique syscalls from sshd ==="
grep '"comm":"sshd"' "$AUDIT" 2>/dev/null | grep -oP '"syscall":"[^"]*"' | sort -u

kill $BPID 2>/dev/null
wait $BPID 2>/dev/null || true
rm -f "$SOCKET"
