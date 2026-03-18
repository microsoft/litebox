#!/bin/bash
# Launch GitHub Copilot CLI inside the litebox sandbox.
#
# Usage: ./dev_tools/run_copilot.sh [copilot args...]
#
# Examples:
#   ./dev_tools/run_copilot.sh                    # interactive TUI
#   ./dev_tools/run_copilot.sh -p "say hello"     # one-shot prompt
#
# Prerequisites:
#   1. Build the runner:
#        cargo build --release -p litebox_runner_linux_userland
#   2. Create the tar (only needed once, or when copilot is updated):
#        ./dev_tools/create_tar_for_copilot_cli.sh
#   3. Set up TUN networking:
#        sudo ./dev_tools/setup_tun_nat.sh up
#   4. Start the 9P file broker (in a separate terminal):
#        ./target/release/litebox_broker --root-dir / --rewrite-syscalls \
#          --read-only --writable-path "$(pwd)" --writable-path /tmp \
#          --listen-addr 10.0.0.1:5640
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$REPO_ROOT/target/release/litebox_runner_linux_userland"
TAR="${COPILOT_TAR:-/tmp/copilot_ustar.tar}"
TUN_DEVICE="${TUN_DEVICE:-tun99}"
BROKER_ADDR="${BROKER_ADDR:-10.0.0.1:5640}"
CWD="${SANDBOX_CWD:-$(pwd)}"

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
    echo "Run: ./dev_tools/create_tar_for_copilot_cli.sh" >&2
    exit 1
fi

"$RUNNER" -Z \
  --initial-files "$TAR" --program-from-tar \
  --tun-device-name "$TUN_DEVICE" \
  --nine-p-broker "$BROKER_ADDR" \
  --cwd "$CWD" \
  --env HOME=/tmp \
  --env COPILOT_DATA_DIR=/tmp/.copilot \
  --env COPILOT_RUN_APP=1 \
  --env SHELL=/bin/bash \
  --env "PATH=/tmp/litebox-bin:${PATH:-/usr/local/bin:/usr/bin:/bin}" \
  --env TERM=xterm-256color \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env "GIT_CONFIG_VALUE_0=*" \
  -- "$COPILOT_BIN" --allow-all --no-auto-update "$@"
