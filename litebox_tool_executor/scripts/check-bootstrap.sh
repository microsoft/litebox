#!/bin/bash
# Check what the bootstrap bash process is doing
LOG=$(ls -t /tmp/litebox-vscode-server-logs/*.jsonl 2>/dev/null | head -1)
if [ -z "$LOG" ]; then echo "No log found"; exit 1; fi

echo "Log: $LOG"
echo "Total events: $(wc -l < "$LOG")"
echo ""

echo "=== Recent events from PID 416 (bash bootstrap) ==="
grep '"pid":416' "$LOG" | grep -v EpollPwait | grep -v ClockGettime | grep -v Nanosleep | tail -20
echo ""

echo "=== Any references to .done or vscode-server.tar ==="
grep -c 'done\|vscode-server.tar' "$LOG"
echo ""

echo "=== Last 10 Newfstatat/Access from bash ==="
grep '"pid":416' "$LOG" | grep -E 'Newfstatat|Access|openat.*vscode' | tail -10
echo ""

echo "=== All unique PIDs and comms ==="
grep -oP '"pid":\d+,"comm":"[^"]*"' "$LOG" | sort -u
