#!/bin/sh
# Simplified: no touch/chmod, just redirect directly.
COMMIT_ID=10c8e557c8b9f9ed0a87f61f1c9a44bde731c409
CLI=/root/.vscode-server/code-${COMMIT_ID}
LOG=/tmp/cli-e2e.log
export VSCODE_AGENT_FOLDER=/root/.vscode-server

rm -f "$LOG"

VSCODE_CLI_REQUIRE_TOKEN=test "$CLI" command-shell --cli-data-dir /root/.vscode-server/cli --parent-process-id $$ --on-host=127.0.0.1 --on-port > "$LOG" 2>&1 < /dev/null &
CLI_PID=$!
echo "Spawned=$CLI_PID"

count=0
while [ $count -lt 10 ]; do
  count=$((count+1))
  sleep 1
  LISTENING_ON=$(cat "$LOG" 2>/dev/null | grep -a -E 'Listening on .+' | sed 's/Listening on //')
  if [ -n "$LISTENING_ON" ]; then
    echo "FOUND=$LISTENING_ON iter=$count"
    break
  fi
  if ! kill -0 $CLI_PID 2>/dev/null; then
    echo "DEAD iter=$count"
    cat "$LOG" 2>&1
    break
  fi
  echo "poll=$count alive=yes size=$(wc -c < "$LOG" 2>/dev/null) cat=$(cat "$LOG" 2>&1 | head -1)"
done
echo "listeningOn==$LISTENING_ON=="
kill $CLI_PID 2>/dev/null
