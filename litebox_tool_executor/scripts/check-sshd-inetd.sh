#!/bin/bash
# Check sshd -i (inetd mode) support
/home/wportnoy/vscode-rootfs/usr/sbin/sshd --help 2>&1 | head -5
echo "---"
man sshd 2>/dev/null | grep -A2 "\-i" | head -5
