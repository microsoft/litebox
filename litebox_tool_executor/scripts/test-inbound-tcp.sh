#!/bin/bash
# Test inbound TCP through the broker's port forwarding.
# Runs a Python TCP echo server inside litebox and connects from outside.
set -u

EXE="/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"
RUNNER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_runner_linux_userland"
BROKER="/mnt/c/src/litebox-vscode-server/target/debug/litebox_broker"
ROOTFS="/home/wportnoy/vscode-rootfs"

echo "=== Inbound TCP Echo Test ==="

# Start the broker with port forwarding and the runner with python echo server.
# We reuse the vscode-server mode's broker setup but run python instead of sshd.
BROKER_SOCK="/tmp/litebox-tcp-test-$$.sock"
AUDIT_LOG="/tmp/litebox-tcp-test-$$.jsonl"
BROKER_LOG="/tmp/litebox-tcp-test-$$.broker.log"

rm -f "$BROKER_SOCK"

# Start broker with inbound port forward: host:2223 -> guest:22
"$BROKER" \
    --network-proxy-listen "$BROKER_SOCK" \
    --root-dir "$ROOTFS" \
    --rewrite-syscalls \
    --forward-port "2223:10.0.0.2:22" \
    >"$BROKER_LOG" 2>&1 &
BROKER_PID=$!

# Wait for broker socket
for i in $(seq 1 50); do
    [ -e "$BROKER_SOCK" ] && break
    sleep 0.1
done
if [ ! -e "$BROKER_SOCK" ]; then
    echo "FAIL: broker socket not created"
    kill $BROKER_PID 2>/dev/null
    exit 1
fi
echo "Broker started (PID=$BROKER_PID)"

# Start runner with python TCP echo server
"$RUNNER" \
    --network-broker "$BROKER_SOCK" \
    --nine-p-broker "$BROKER_SOCK" \
    -- /usr/bin/python3 /tcp_echo.py &
RUNNER_PID=$!
echo "Runner started (PID=$RUNNER_PID)"

# Wait for the echo server to start listening
sleep 5

echo ""
echo "=== Connecting to echo server on port 2223 ==="
# Send "HELLO" and expect "HELLO" back
REPLY=$(echo "HELLO_LITEBOX_TCP" | timeout 10 nc -q 1 127.0.0.1 2223 2>/dev/null)
echo "Reply: '$REPLY'"

if [ "$REPLY" = "HELLO_LITEBOX_TCP" ]; then
    echo "PASS: TCP echo through broker works!"
else
    echo "FAIL: Expected 'HELLO_LITEBOX_TCP', got '$REPLY'"
    echo ""
    echo "=== Broker log ==="
    grep -E "inbound|INBOUND|TX→|RX←|bridge|forward" "$BROKER_LOG" | tail -20
fi

echo ""
echo "=== Cleanup ==="
kill $RUNNER_PID 2>/dev/null
kill $BROKER_PID 2>/dev/null
wait $RUNNER_PID 2>/dev/null
wait $BROKER_PID 2>/dev/null
rm -f "$BROKER_SOCK" "$AUDIT_LOG" "$BROKER_LOG"
echo "DONE"
