#!/bin/bash
# Analyze the latest audit log for network activity
LOG=$(ls -t /tmp/litebox-vscode-server-logs/*.jsonl 2>/dev/null | head -1)
if [ -z "$LOG" ]; then echo "No audit log found"; exit 1; fi
echo "=== Log: $LOG ($(wc -l < "$LOG") events) ==="
echo ""
echo "=== All connect syscalls ==="
grep '"connect"' "$LOG" | head -20
echo ""
echo "=== All socket syscalls ==="
grep '"socket"' "$LOG" | head -10
echo ""
echo "=== DNS events ==="
grep 'dns' "$LOG" | head -5
echo ""
echo "=== TCP events ==="
grep 'tcp' "$LOG" | head -10
echo ""
echo "=== Unique process names ==="
grep -oP '"comm":"[^"]*"' "$LOG" | sort -u
echo ""
echo "=== SCP related ==="
grep -i 'scp' "$LOG" | head -5
