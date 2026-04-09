#!/bin/bash
# Smoke test: run a command inside litebox using 9P directory serving.
# Usage: ./smoke-test.sh [command args...]
# Default command: /usr/local/bin/node --version
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKTREE="$(cd "$SCRIPT_DIR/../.." && pwd)"
BROKER="$WORKTREE/target/debug/litebox_broker"
RUNNER="$WORKTREE/target/debug/litebox_runner_linux_userland"
ROOTFS="${LITEBOX_ROOTFS:-/home/wportnoy/vscode-rootfs}"
SOCKET="/tmp/litebox-vscode-broker-$$.sock"

if [ ! -f "$BROKER" ]; then
    echo "ERROR: broker not found at $BROKER"
    exit 1
fi
if [ ! -f "$RUNNER" ]; then
    echo "ERROR: runner not found at $RUNNER"
    exit 1
fi
if [ ! -d "$ROOTFS" ]; then
    echo "ERROR: rootfs not found at $ROOTFS"
    exit 1
fi

# Default command
if [ $# -eq 0 ]; then
    set -- /usr/local/bin/node --version
fi

cleanup() {
    if [ -n "${BROKER_PID:-}" ]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
    fi
    rm -f "$SOCKET"
}
trap cleanup EXIT

# Start broker in background
echo "=== Starting broker ==="
echo "  rootfs: $ROOTFS"
echo "  socket: $SOCKET"
"$BROKER" --root-dir "$ROOTFS" --network-proxy-listen "$SOCKET" &
BROKER_PID=$!

# Wait for socket
for i in $(seq 1 10); do
    if [ -S "$SOCKET" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S "$SOCKET" ]; then
    echo "ERROR: Broker socket not created after 5s"
    exit 1
fi
echo "  broker PID: $BROKER_PID"

# Run command inside sandbox
echo "=== Running: $* ==="
"$RUNNER" --unstable \
    --network-broker "$SOCKET" \
    --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin:/opt/vscode-server/bin" \
    --env "HOME=/root" \
    --env "NODE_PATH=/usr/local/lib/node_modules" \
    --env "TERM=xterm-256color" \
    -- "$@"
EXIT_CODE=$?

echo "=== Exit code: $EXIT_CODE ==="
