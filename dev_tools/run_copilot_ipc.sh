#!/bin/bash
# Launch GitHub Copilot CLI inside the litebox sandbox using IPC networking.
#
# Unlike run_copilot.sh (which requires TUN + root), this script uses the
# IPC network proxy and runs entirely unprivileged.
#
# Usage: ./dev_tools/run_copilot_ipc.sh [copilot args...]
#
# If the broker is already running (socket exists), the script connects to it
# directly.  Otherwise it starts a broker in the background and cleans it up
# on exit.
#
# Examples:
#   ./dev_tools/run_copilot_ipc.sh                    # interactive TUI
#   ./dev_tools/run_copilot_ipc.sh -p "say hello"     # one-shot prompt
#
# Prerequisites:
#   1. Build the runner and broker:
#        cargo build --release -p litebox_runner_linux_userland -p litebox_broker
#   2. Create the tar (only needed once, or when copilot is updated):
#        ./dev_tools/create_tar_for_copilot.sh --ipc
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$REPO_ROOT/target/release/litebox_runner_linux_userland"
BROKER="$REPO_ROOT/target/release/litebox_broker"
TAR="${COPILOT_TAR:-/tmp/copilot_ustar.tar}"
BROKER_SOCK="${BROKER_SOCK:-/tmp/litebox-broker.sock}"
CWD="${SANDBOX_CWD:-$(pwd)}"
SANDBOX_HOME="${SANDBOX_HOME:-$HOME}"

# Find copilot binary (used as the in-tar program path)
COPILOT_BIN="$(which copilot 2>/dev/null || true)"
if [ -z "$COPILOT_BIN" ]; then
    echo "Error: copilot not found on PATH" >&2
    exit 1
fi

if [ ! -x "$RUNNER" ]; then
    echo "Error: runner not found at $RUNNER" >&2
    echo "Run: cargo build --release -p litebox_runner_linux_userland" >&2
    exit 1
fi

if [ ! -f "$TAR" ]; then
    echo "Error: tar not found at $TAR" >&2
    echo "Run: ./dev_tools/create_tar_for_copilot.sh --ipc" >&2
    exit 1
fi

STARTED_BROKER=false

if [ -S "$BROKER_SOCK" ]; then
    [ "${DEBUG:-}" = "1" ] && echo "Using existing broker at $BROKER_SOCK"
else
    # Need to start the broker ourselves.
    if [ ! -x "$BROKER" ]; then
        echo "Error: broker not found at $BROKER" >&2
        echo "Run: cargo build --release -p litebox_broker" >&2
        exit 1
    fi

    # Start the broker in the background.
    RUST_LOG="${RUST_LOG:-litebox_broker=warn}" "$BROKER" \
      --root-dir / \
      --rewrite-syscalls \
      --read-only \
      --writable-path "$CWD" \
      --writable-path /tmp \
      --network-proxy-listen "$BROKER_SOCK" &
    BROKER_PID=$!
    STARTED_BROKER=true

    # Wait for the broker socket to appear.
    for i in $(seq 1 50); do
        if [ -S "$BROKER_SOCK" ]; then
            break
        fi
        sleep 0.1
    done
    if [ ! -S "$BROKER_SOCK" ]; then
        echo "Error: broker did not create socket at $BROKER_SOCK" >&2
        exit 1
    fi
fi

# Clean up broker on exit (only if we started it).
cleanup() {
    if [ "$STARTED_BROKER" = true ] && [ -n "${BROKER_PID:-}" ]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
        rm -f "$BROKER_SOCK"
    fi
}
trap cleanup EXIT

# Run the guest with IPC networking.
"$RUNNER" -Z \
  --initial-files "$TAR" --program-from-tar \
  --network-broker "$BROKER_SOCK" \
  --nine-p-broker "$BROKER_SOCK" \
  --cwd "$CWD" \
  --env HOME=$SANDBOX_HOME \
  --env COPILOT_DATA_DIR=$SANDBOX_HOME/.copilot \
  --env COPILOT_RUN_APP=1 \
  --env SHELL=/bin/bash \
  --env "PATH=/tmp/litebox-bin:${PATH:-/usr/local/bin:/usr/bin:/bin}" \
  --env TERM=xterm-256color \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env "GIT_CONFIG_VALUE_0=*" \
  -- "$COPILOT_BIN" --allow-all --no-auto-update "$@"
