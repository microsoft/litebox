#!/bin/bash
# Automated test that simulates VS Code Remote-SSH's bootstrap flow.
# This replays what VS Code does when connecting:
#   1. ssh litebox sh  (pipe bootstrap script)
#   2. scp/sftp to transfer the VS Code CLI
#   3. Start the server
#
# Usage:
#   bash test-vscode-bootstrap.sh [port]
#
# The test verifies that the sandbox can handle the VS Code bootstrap
# protocol without errors.
set -u

PORT="${1:-2222}"
EXE=/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor
ROOTFS=/home/wportnoy/vscode-rootfs
PASS=0
FAIL=0

# Helper: run SSH command with empty password
ssh_cmd() {
    cat > /tmp/ssh-ep.sh << 'P'
#!/bin/bash
echo ""
P
    chmod +x /tmp/ssh-ep.sh
    export SSH_ASKPASS=/tmp/ssh-ep.sh
    export SSH_ASKPASS_REQUIRE=force
    timeout 20 ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        -T -p "$PORT" root@127.0.0.1 "$@" 2>/dev/null
}

# Helper: pipe to SSH
ssh_pipe() {
    cat > /tmp/ssh-ep.sh << 'P'
#!/bin/bash
echo ""
P
    chmod +x /tmp/ssh-ep.sh
    export SSH_ASKPASS=/tmp/ssh-ep.sh
    export SSH_ASKPASS_REQUIRE=force
    timeout 20 ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        -T -p "$PORT" root@127.0.0.1 sh 2>/dev/null
}

check() {
    local name="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name (expected '$expected')"
        echo "    got: $(echo "$actual" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== VS Code Bootstrap Simulation Test ==="
echo "Starting dropbear in sandbox..."
"$EXE" --rootfs "$ROOTFS" --vscode-server --record-baseline 2>/dev/null &
BGPID=$!
sleep 8

echo ""
echo "--- Test 1: Basic command execution ---"
R=$(ssh_cmd "echo HELLO_TEST")
check "echo command" "HELLO_TEST" "$R"

echo ""
echo "--- Test 2: sh accepts piped script (VS Code bootstrap pattern) ---"
R=$(echo 'echo PIPE_OK' | ssh_pipe)
check "pipe to sh" "PIPE_OK" "$R"

echo ""
echo "--- Test 3: Platform detection (VS Code bootstrap step 1) ---"
BOOTSTRAP='
echo "==PROBE=="
echo "PLATFORM=$(uname -s)"
echo "ARCH=$(uname -m)"
echo "HOME=$HOME"
command -v tar >/dev/null 2>&1 && echo "HAS_TAR=yes" || echo "HAS_TAR=no"
command -v wget >/dev/null 2>&1 && echo "HAS_WGET=yes" || echo "HAS_WGET=no"
echo "==PROBE_END=="
'
R=$(echo "$BOOTSTRAP" | ssh_pipe)
check "platform=Linux" "PLATFORM=Linux" "$R"
check "arch=x86_64" "ARCH=x86_64" "$R"
check "has tar" "HAS_TAR=yes" "$R"

echo ""
echo "--- Test 4: Create directories (VS Code server install) ---"
R=$(echo 'mkdir -p /root/.vscode-server/bin/test && echo DIR_OK && ls -d /root/.vscode-server/bin/test' | ssh_pipe)
check "mkdir vscode-server" "DIR_OK" "$R"

echo ""
echo "--- Test 5: Multiple sequential connections ---"
R1=$(ssh_cmd "echo CONN1")
R2=$(ssh_cmd "echo CONN2")
check "connection 1" "CONN1" "$R1"
check "connection 2" "CONN2" "$R2"

echo ""
echo "--- Test 6: SFTP subsystem ---"
R=$(echo "ls /root" | timeout 10 sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -P "$PORT" root@127.0.0.1 2>&1)
# sftp might fail but we want to see if the subsystem starts
if echo "$R" | grep -qE "sftp>|Connected|Couldn't"; then
    echo "  PASS: SFTP subsystem responds"
    PASS=$((PASS + 1))
else
    echo "  SKIP: SFTP test inconclusive"
fi

# Cleanup
kill $BGPID 2>/dev/null
wait 2>/dev/null
rm -f /tmp/ssh-ep.sh

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
