#!/usr/bin/env pwsh
# litebox-ssh-shim.ps1 — VS Code Remote-SSH shim for LiteBox
#
# This acts as a drop-in replacement for the SSH binary. VS Code's
# Remote-SSH extension calls it with SSH-style arguments; the shim
# ignores them and instead launches VS Code Server inside a LiteBox
# sandbox via WSL2 with inherited stdio.
#
# Configure VS Code:
#   "remote.SSH.path": "C:\\src\\litebox-vscode-server\\litebox_tool_executor\\scripts\\litebox-ssh-shim.ps1"
#
# Then add to your SSH config (~/.ssh/config):
#   Host litebox
#     HostName litebox
#
# Connect via: Ctrl+Shift+P → "Remote-SSH: Connect to Host..." → litebox
#
# The VS Code Remote protocol runs over stdin/stdout — same transport
# as docker exec -i or real SSH.

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SshArgs
)

# Configuration — adjust these paths for your environment
$WSL_DISTRO = "Ubuntu"
$ROOTFS = "/home/wportnoy/vscode-rootfs"
$EXECUTOR = "/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"

# Parse the last positional argument as the "host" — if it's not "litebox",
# fall back to real SSH so other Remote-SSH connections still work.
$host = ""
$command = ""
$skipNext = $false
for ($i = 0; $i -lt $SshArgs.Count; $i++) {
    if ($skipNext) { $skipNext = $false; continue }
    $arg = $SshArgs[$i]
    # Skip SSH flags that take a value argument
    if ($arg -match "^-[bcDEeFIiJLlmOopQRSWw]$") { $skipNext = $true; continue }
    # Skip SSH flags without value
    if ($arg -match "^-") { continue }
    # First non-flag arg is the host, rest is the command
    if (-not $host) { $host = $arg }
    else { $command += " $arg" }
}

if ($host -ne "litebox") {
    # Not targeting litebox — fall back to real SSH
    $realSsh = (Get-Command ssh -ErrorAction SilentlyContinue).Source
    if ($realSsh) {
        & $realSsh @SshArgs
        exit $LASTEXITCODE
    }
    Write-Error "SSH not found and host is not 'litebox': $host"
    exit 1
}

# Launch VS Code Server inside LiteBox via WSL2.
# VS Code's stdin/stdout become the remote protocol transport.
& wsl.exe -d $WSL_DISTRO -- $EXECUTOR --rootfs $ROOTFS --vscode-server
exit $LASTEXITCODE

