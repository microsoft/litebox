#!/bin/bash
cd /mnt/c/src/litebox-vscode-server
target/debug/litebox_tool_executor --rootfs /home/wportnoy/vscode-rootfs --record-baseline -- /litebox-test-harness capture-pipe nested_fork_nowait &>/dev/null &
BGPID=$!
sleep 4
for P in $(pgrep -f litebox_runner_linux_userland); do
  case $P in 1985|2042) continue;; esac
  CMD=$(tr '\0' ' ' < /proc/$P/cmdline 2>/dev/null | cut -c1-100)
  echo "=== PID $P: $CMD ==="
  gdb -batch -ex "thread apply all bt 8" -p "$P" 2>/dev/null | head -100
  echo "---"
done
kill $BGPID 2>/dev/null
wait $BGPID 2>/dev/null