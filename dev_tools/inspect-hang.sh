#!/bin/bash
# Inspect hanging litebox runner processes
cd /mnt/c/src/litebox-vscode-server

target/debug/litebox_tool_executor \
  --rootfs /home/wportnoy/vscode-rootfs \
  --record-baseline \
  -- /litebox-test-harness capture-pipe nested_fork_nowait &>/dev/null &
BGPID=$!
sleep 3

PIDS=$(pgrep -f litebox_runner_linux_userland)
echo "Runner PIDs: $PIDS"
for P in $PIDS; do
  echo "=== PID $P ==="
  gdb -batch -ex "thread apply all bt 10" -p "$P" 2>/dev/null \
    | grep -E "^Thread|#[0-9] " | head -50
  echo "---"
done

kill "$BGPID" 2>/dev/null
wait "$BGPID" 2>/dev/null
