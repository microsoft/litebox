#!/usr/bin/bash
SDIR=/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389
echo "CHECK: pid.txt exists=no"
echo "CHECK: pid.txt content=Cannot find path 'C:\src\litebox\$SDIR\pid.txt' because it does not exist."
echo "CHECK: log.txt exists=no"
echo "CHECK: log.txt lines="
PID=
if [ -n "$PID" ]; then
  kill -0 $PID 2>/dev/null && echo "CHECK: pid $PID alive=yes" || echo "CHECK: pid $PID alive=no"
fi
echo "CHECK: log.txt tail="