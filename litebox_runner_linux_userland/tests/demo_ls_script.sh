#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Test script that demonstrates script interpreter support
# This script lists files in /tmp to validate that commands work within scripts

echo "=== Script Interpreter Test ==="
echo "Script: $0"
echo "Arguments: $*"
echo ""

# Test basic command execution
echo "Testing /bin/ls command from within script..."
/bin/ls /tmp 2>/dev/null || echo "Note: /tmp not accessible or /bin/ls not found"

echo ""
echo "Testing built-in commands..."
pwd
echo "Current directory listed above"

echo ""
echo "=== Script execution successful ==="
exit 0
