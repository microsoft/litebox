#!/bin/bash
# Analyze the audit log for CLI extraction and execution attempts
LOG=$(ls -t /tmp/litebox-vscode-server-logs/*.jsonl 2>/dev/null | head -1)
if [ -z "$LOG" ]; then echo "No log found"; exit 1; fi

echo "Log: $LOG ($(wc -l < "$LOG") events)"
echo ""

echo "=== Events from PID 416 (bootstrap bash) that mention vscode/tar/extract ==="
grep '"pid":416' "$LOG" | grep -i 'openat.*vscode\|openat.*tar\|openat.*done' | head -20
echo ""

echo "=== All tar-related events ==="
grep '"comm":"tar"' "$LOG" | head -10
echo ""

echo "=== All unique comms from PID 416's children ==="
# The bootstrap script forks children — check if any tried to run tar
grep '"comm":"tar"\|"comm":"code"\|"comm":"wget"\|"comm":"curl"' "$LOG" | head -10
echo ""

echo "=== All openat calls that succeeded for vscode-server ==="
grep 'openat.*vscode.*ok' "$LOG" | head -10
echo ""

echo "=== The .done file access attempts ==="
grep 'done' "$LOG" | head -10
echo ""

echo "=== What happened right after SCP (PID 558 sftp-server end) ==="
# Find the line number where sftp-server exited
SFTP_END=$(grep -n '"pid":558' "$LOG" | tail -1 | cut -d: -f1)
if [ -n "$SFTP_END" ]; then
    echo "sftp-server last event at line $SFTP_END"
    # Show 20 events after sftp-server ended
    sed -n "$((SFTP_END+1)),$((SFTP_END+20))p" "$LOG" | grep -v EpollPwait | grep -v ClockGettime | grep -v Nanosleep
fi
