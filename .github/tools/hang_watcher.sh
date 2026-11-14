#!/bin/bash
# TEMPORARY (iperf-stress branch): dumps every thread of a hung iperf3 test.
#
# Usage: hang_watcher.sh DIR
#
# `test_broker_with_iperf3` writes `DIR/hang-<runner pid>` ("<runner pid> <server pid>") when it
# times out, then waits for `DIR/hang-<runner pid>.done` before killing anything. This writes
# `DIR/hang-<runner pid>.dump` with the stacks of the runner (the guest) and of the test process
# (which hosts the broker), then the `.done` marker. Attaching needs `sudo`, as Ubuntu restricts
# ptrace to descendants.

set -u
dir=$1

dump() {
    local pid=$1 out=$2
    {
        echo "=== pid $pid: $(tr '\0' ' ' < "/proc/$pid/cmdline" | cut -c1-300)"
        for task in /proc/"$pid"/task/*; do
            echo "--- tid ${task##*/} comm=$(cat "$task/comm" 2>/dev/null)" \
                "wchan=$(cat "$task/wchan" 2>/dev/null)" \
                "syscall=$(sudo cat "$task/syscall" 2>/dev/null)"
        done
        sudo timeout 300 gdb -p "$pid" -batch -nx \
            -ex 'set pagination off' -ex 'thread apply all bt 100' 2>&1
    } >> "$out"
}

while :; do
    for marker in "$dir"/hang-*; do
        [ -e "$marker" ] || continue
        case "$marker" in *.done | *.dump) continue ;; esac
        [ -e "$marker.done" ] && continue
        read -r runner server < "$marker"
        test_process=$(ps -o ppid= -p "$runner" | tr -d ' ')
        out="$marker.dump"
        echo "runner $runner, iperf3 server $server, test process $test_process" > "$out"
        dump "$runner" "$out"
        dump "$test_process" "$out"
        touch "$marker.done"
    done
    sleep 1
done
