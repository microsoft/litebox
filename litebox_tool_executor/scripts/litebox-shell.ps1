# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# PowerShell REPL wrapper for the LiteBox tool executor.
# Each command runs in a fresh LiteBox sandbox (avoids fork() limitation).
#
# Environment variables:
#   LITEBOX_ROOTFS   - Path to the rootfs .tar  (required)
#   LITEBOX_POLICY   - Path to a JSON policy file (optional)
#   LITEBOX_AUDIT    - Path to write audit log    (optional)

if (-not $env:LITEBOX_ROOTFS) {
    Write-Host "ERROR: LITEBOX_ROOTFS environment variable must point to a rootfs .tar file."
    exit 1
}

# Locate the executor binary.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$Executor = if (Test-Path "$RepoRoot\target\debug\litebox_tool_executor.exe") {
    "$RepoRoot\target\debug\litebox_tool_executor.exe"
} elseif (Test-Path "$RepoRoot\target\release\litebox_tool_executor.exe") {
    "$RepoRoot\target\release\litebox_tool_executor.exe"
} else {
    "litebox_tool_executor.exe"
}

# Audit log destination.
if (-not $env:LITEBOX_AUDIT) {
    $env:LITEBOX_AUDIT = "$env:LITEBOX_ROOTFS.audit.jsonl"
}

# Build base arguments.
$BaseArgs = @("--rootfs", $env:LITEBOX_ROOTFS)
if ($env:LITEBOX_POLICY) {
    $BaseArgs += @("--policy", $env:LITEBOX_POLICY)
}

function Invoke-Sandbox {
    param([string]$Command)
    # Run the command via busybox sh -c, appending stderr to audit log.
    # The 2>> redirect in PowerShell captures the error stream; we convert
    # native stderr to the error stream and append to the log file.
    $output = & $Executor @BaseArgs /bin/busybox sh -c $Command 2>&1
    foreach ($line in $output) {
        if ($line -is [System.Management.Automation.ErrorRecord]) {
            # Stderr line — append to audit log
            Add-Content -Path $env:LITEBOX_AUDIT -Value $line.ToString()
        } else {
            # Stdout line — display to user
            Write-Host $line
        }
    }
}

# One-shot mode: if arguments were passed, run them and exit.
if ($args.Count -gt 0) {
    $Command = $args -join ' '
    Invoke-Sandbox $Command
    exit $LASTEXITCODE
}

# Interactive REPL mode.
Write-Host "LiteBox Sandbox Shell (each command runs in a fresh sandbox)"
Write-Host "Type 'exit' to quit. Commands are executed via busybox."
Write-Host ""

while ($true) {
    Write-Host -NoNewline "/ `$ "
    $cmd = Read-Host
    if ($null -eq $cmd -or $cmd -eq 'exit') { break }
    if ($cmd.Trim() -eq '') { continue }
    Invoke-Sandbox $cmd
}
