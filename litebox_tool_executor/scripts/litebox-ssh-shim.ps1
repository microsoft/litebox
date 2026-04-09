#!/usr/bin/env pwsh
# litebox-ssh-shim.ps1 — Drop-in SSH replacement for VS Code Remote-SSH
#
# This shim intercepts connections to host "litebox" and routes them through
# a LiteBox sandbox. All other hosts pass through to real SSH unchanged.
#
# Setup (one-time, in VS Code Default profile user settings):
#   "remote.SSH.path": "C:\\src\\litebox-vscode-server\\litebox_tool_executor\\scripts\\litebox-ssh-shim.ps1"
#   "remote.SSH.showLoginTerminal": true
#
# NOTE: remote.SSH.path has application scope — it affects all Remote-SSH
# connections. This shim preserves normal SSH behavior for non-litebox hosts
# by falling through to the real ssh binary. For full isolation, use a
# dedicated VS Code profile (File → Preferences → Profiles → Create Profile).
#
# Then connect: Ctrl+Shift+P → "Remote-SSH: Connect to Host..." → litebox

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SshArgs
)

# Configuration — adjust these paths for your environment
$WSL_DISTRO = "Ubuntu"
$ROOTFS = "/home/wportnoy/vscode-rootfs"
$EXECUTOR = "/mnt/c/src/litebox-vscode-server/target/debug/litebox_tool_executor"

# Parse SSH arguments to find the target host.
# SSH CLI: ssh [options] destination [command]
# Options that take a value: -b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w
$host = ""
$skipNext = $false
for ($i = 0; $i -lt $SshArgs.Count; $i++) {
    if ($skipNext) { $skipNext = $false; continue }
    $arg = $SshArgs[$i]
    # Skip SSH flags that take a value argument
    if ($arg -match "^-[bcDEeFIiJLlmOopQRSWw]$") { $skipNext = $false; continue }
    if ($arg -match "^-[bcDEeFIiJLlmOopQRSWw].") { continue }  # -oValue form
    # Skip flags without value
    if ($arg -match "^-") { continue }
    # First non-flag arg is the destination
    if (-not $host) { $host = $arg; break }
}

if ($host -ne "litebox") {
    # Not targeting litebox — fall back to real SSH
    $realSsh = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
    if (-not $realSsh) {
        $realSsh = "$env:SystemRoot\System32\OpenSSH\ssh.exe"
    }
    if (Test-Path $realSsh) {
        & $realSsh @SshArgs
        exit $LASTEXITCODE
    }
    Write-Error "Real SSH not found and host is not 'litebox': $host"
    exit 1
}

# Launch VS Code Server inside LiteBox via WSL2.
# VS Code's stdin/stdout become the remote protocol transport.
& wsl.exe -d $WSL_DISTRO -- $EXECUTOR --rootfs $ROOTFS --vscode-server
exit $LASTEXITCODE

