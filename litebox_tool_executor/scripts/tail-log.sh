#!/bin/bash
# Wait for and tail the broker log
while true; do
    LOG=$(ls -t /tmp/litebox-vscode-server-logs/*.broker.log 2>/dev/null | head -1)
    if [ -n "$LOG" ]; then
        echo "=== Tailing $LOG ==="
        tail -f "$LOG"
        break
    fi
    sleep 1
done
