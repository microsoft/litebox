#!/usr/bin/bash
CSBIN=/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389/server/bin/code-server
SDIR=/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389

$CSBIN --connection-token=remotessh --accept-server-license-terms --start-server --enable-remote-auto-shutdown > $SDIR/log.txt 2>&1 &
CS_PID=$!
echo $CS_PID > $SDIR/pid.txt
echo "PREWARM_PID=$CS_PID"
sleep 6
echo "PREWARM_PIDFILE=$(cat $SDIR/pid.txt)"
echo "PREWARM_LOGLINES=$(wc -l $SDIR/log.txt)"
echo "PREWARM_LOGTAIL=$(tail -1 $SDIR/log.txt)"
kill -0 $CS_PID 2>/dev/null && echo "PREWARM_ALIVE=yes" || echo "PREWARM_ALIVE=no"
