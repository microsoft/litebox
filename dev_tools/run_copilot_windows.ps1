# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

<#
.SYNOPSIS
    Launch GitHub Copilot CLI inside the litebox sandbox on Windows.

.DESCRIPTION
    Windows equivalent of dev_tools/run_copilot.sh.

    Prerequisites:
      1. Build the runner:
           cargo build --release -p litebox_runner_linux_on_windows_userland
      2. Prepare the tar (copilot_ustar.tar with pre-rewritten binaries)
      3. Place wintun.dll next to the runner binary (target\release\)
      4. Set up TUN networking (run as admin):
           .\dev_tools\setup_tun_nat_windows.ps1 -Action up
      5. Start the 9P file broker in WSL2:
           ./target/release/litebox_broker --root-dir / --rewrite-syscalls `
             --read-only --writable-path "$(pwd)" --writable-path /tmp `
             --listen-addr 10.0.0.1:5640

.PARAMETER CopilotArgs
    Additional arguments passed to copilot (e.g., -p "say hello").

.EXAMPLE
    .\dev_tools\run_copilot_windows.ps1                       # interactive TUI
    .\dev_tools\run_copilot_windows.ps1 -p "say hello"        # one-shot prompt
#>

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CopilotArgs
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$Runner = Join-Path $RepoRoot 'target\release\litebox_runner_linux_on_windows_userland.exe'
$DefaultTar = 'C:\Users\wdcui\tmp\copilot_ustar.tar'
$Tar = if ($env:COPILOT_TAR) { $env:COPILOT_TAR } else { $DefaultTar }
$TunDevice = if ($env:TUN_DEVICE) { $env:TUN_DEVICE } else { 'litebox0' }
$BrokerAddr = if ($env:BROKER_ADDR) { $env:BROKER_ADDR } else { '10.0.0.1:5640' }
$Cwd = if ($env:SANDBOX_CWD) { $env:SANDBOX_CWD } else { (Get-Location).Path }

# Find copilot binary path (used as the in-tar program path).
$CopilotBin = (Get-Command copilot -ErrorAction SilentlyContinue).Source
if (-not $CopilotBin) {
    Write-Error "Error: copilot not found on PATH"
    exit 1
}

if (-not (Test-Path $Runner)) {
    Write-Error "Error: runner not found at $Runner`nRun: cargo build --release -p litebox_runner_linux_on_windows_userland"
    exit 1
}

if (-not (Test-Path $Tar)) {
    Write-Error "Error: tar not found at $Tar"
    exit 1
}

# Check wintun.dll is next to the runner.
$WintunDll = Join-Path (Split-Path $Runner) 'wintun.dll'
if (-not (Test-Path $WintunDll)) {
    Write-Warning "wintun.dll not found at $WintunDll — TUN networking will fail."
    Write-Warning "Download from https://www.wintun.net/ and place wintun.dll next to the runner."
}

# Convert Windows cwd path to Unix-style for the sandbox.
$UnixCwd = '/' + ($Cwd -replace '\\', '/' -replace '^([A-Za-z]):', '$1')

$RunnerArgs = @(
    '-Z'
    '--initial-files', $Tar
    '--tun-device-name', $TunDevice
    '--nine-p-broker', $BrokerAddr
    '--cwd', $UnixCwd
    '--env', 'HOME=/tmp'
    '--env', 'COPILOT_DATA_DIR=/tmp/.copilot'
    '--env', 'COPILOT_RUN_APP=1'
    '--env', 'SHELL=/bin/bash'
    '--env', 'PATH=/tmp/litebox-bin:/usr/local/bin:/usr/bin:/bin'
    '--env', 'TERM=xterm-256color'
    '--env', 'GIT_CONFIG_COUNT=1'
    '--env', 'GIT_CONFIG_KEY_0=safe.directory'
    '--env', 'GIT_CONFIG_VALUE_0=*'
    '--', $CopilotBin, '--allow-all', '--no-auto-update'
)

if ($CopilotArgs) {
    $RunnerArgs += $CopilotArgs
}

& $Runner @RunnerArgs
