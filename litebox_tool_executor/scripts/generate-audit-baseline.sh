#!/bin/bash
# Generate an audit JSONL file from a VS Code Server session for analysis.
set -u

ROOTFS="/home/wportnoy/vscode-rootfs"
BROKER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_broker"
RUNNER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_runner_linux_userland"
SOCKET="/tmp/litebox-audit-gen.sock"
AUDIT="/tmp/litebox-audit-baseline.jsonl"

rm -f "$SOCKET" "$AUDIT"

echo "Starting broker..."
"$BROKER" --root-dir "$ROOTFS" --network-proxy-listen "$SOCKET" 2>/dev/null &
BROKER_PID=$!
sleep 2

if [ ! -S "$SOCKET" ]; then
    echo "ERROR: broker socket not created"
    exit 1
fi

echo "Starting VS Code Server (10s timeout)..."
timeout 10 "$RUNNER" --unstable \
    --network-broker "$SOCKET" \
    --nine-p-broker "$SOCKET" \
    --audit-log "$AUDIT" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin" \
    --env "HOME=/root" \
    --env "TERM=dumb" \
    -- /usr/local/bin/node /opt/vscode-server/out/server-main.js \
    --accept-server-license-terms --host 127.0.0.1 --port 0 \
    --without-connection-token --disable-telemetry 2>/dev/null || true

kill "$BROKER_PID" 2>/dev/null
wait "$BROKER_PID" 2>/dev/null || true
rm -f "$SOCKET"

if [ -f "$AUDIT" ]; then
    LINES=$(wc -l < "$AUDIT")
    echo "Audit log: $AUDIT ($LINES events)"
else
    echo "ERROR: no audit log generated"
    exit 1
fi
