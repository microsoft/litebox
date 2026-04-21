#!/bin/bash
cd /mnt/c/src/litebox-vscode-server
target/debug/litebox_tool_executor --rootfs /home/wportnoy/vscode-rootfs --record-baseline -- /litebox-test-harness capture-pipe nested_fork_nowait &>/dev/null &
BGPID=$!
sleep 6
for P in $(pgrep -f litebox_runner_linux_userland); do
  case $P in 1985|2042) continue;; esac
  echo "=== PID $P ==="
  gdb -batch -ex "thread apply all bt 8" -p "$P" 2>/dev/null | head -80
  echo "---"
done
kill $BGPID 2>/dev/null
wait $BGPID 2>/dev/null