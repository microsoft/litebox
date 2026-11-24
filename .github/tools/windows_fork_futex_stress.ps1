# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#Requires -Version 7.2

<#
.SYNOPSIS
Stresses test_fork_shared_futex_with_windows_broker to reproduce its intermittent hang, printing the
stacks of every broker and runner each time the test runs slow.

.DESCRIPTION
`alone` runs the test by itself. `loaded` runs it alongside the other fork tests of the loader, which
CI runs at the same time. Needs WSL with GCC, as the loader tests do, and a disposable runner, as it
attaches a debugger to the test's processes.

.EXAMPLE
./.github/tools/windows_fork_futex_stress.ps1 alone
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('alone', 'loaded')][string]$Mode
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This investigation attaches a debugger on a disposable GitHub-hosted runner.'
}

$test = 'test_fork_shared_futex_with_windows_broker'
$cdb = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"
if (!(Test-Path -LiteralPath $cdb)) { throw "cdb not found at $cdb" }
$symbols = "$PWD\target\debug;srv*$env:RUNNER_TEMP\symbols*https://msdl.microsoft.com/download/symbols"
$images = 'litebox-broker-userland.exe', 'litebox_runner_linux_on_windows_userland.exe'

# Prints `$Process` and its descendants in `$Processes`.
function Write-Tree([object[]]$Processes, [object]$Process, [int]$Depth) {
    $line = "$($Process.Name) pid=$($Process.ProcessId): $($Process.CommandLine)"
    Write-Host ('  ' * $Depth + $line.Substring(0, [Math]::Min($line.Length, 300)))
    # Bounded, as a reused process ID could make a cycle.
    if ($Depth -ge 8) { return }
    foreach ($child in $Processes | Where-Object ParentProcessId -EQ $Process.ProcessId) {
        Write-Tree $Processes $child ($Depth + 1)
    }
}

# Prints the process trees of the test, then the stacks of every broker and runner, including any
# whose parent is gone.
function Show-Stacks([string]$Reason) {
    Write-Host "::group::Stacks: $Reason"
    $processes = @(Get-CimInstance Win32_Process -Property Name, ProcessId, ParentProcessId, CommandLine)
    $roots = $processes | Where-Object {
        $_.Name -like 'loader-*.exe' -and $_.CommandLine -match "\b$test\b"
    }
    foreach ($root in $roots) { Write-Tree $processes $root 0 }
    foreach ($process in $processes | Where-Object Name -In $images) {
        Write-Host "=== $($process.Name) pid=$($process.ProcessId) parent=$($process.ParentProcessId)"
        # Noninvasive, so that the process carries on once the stacks are printed.
        $arguments = "-pv -p $($process.ProcessId) -y `"$symbols`" -lines -c `"~*k 50; q`""
        $debugger = Start-Process $cdb -ArgumentList $arguments -NoNewWindow -PassThru
        if (!$debugger.WaitForExit(180000)) {
            $debugger.Kill()
            Write-Warning "Timed out collecting the stacks of $($process.ProcessId)"
        }
    }
    Write-Host '::endgroup::'
}

# Build first, so that the runs only run: the test builds the broker itself otherwise.
cargo build --locked -p litebox_broker_userland --bin litebox-broker-userland
if ($LASTEXITCODE) { exit $LASTEXITCODE }
$selection = @('--locked', '--profile', 'ci', '-p', 'litebox_runner_linux_on_windows_userland', '--test', 'loader')
cargo nextest run @selection --no-run
if ($LASTEXITCODE) { exit $LASTEXITCODE }

$filter = "test(=$test)"
$threads = 1
if ($Mode -eq 'loaded') {
    foreach ($other in 'test_fork_with_windows_broker', 'test_fork_with_threads_with_windows_broker',
        'test_programs_with_windows_broker') {
        $filter += " or test(=$other)"
    }
    $threads = 4
}
# A hung run is killed after `BROKER_RUN_TIMEOUT` in `loader.rs`, and its failure output includes
# the check the guest was in. Before that, the profile's slow timeout reports it every minute.
cargo nextest run --color never @selection -E $filter --test-threads $threads --stress-duration 30m `
    --retries 0 --fail-fast --no-tests fail --status-level pass --failure-output immediate 2>&1 |
    ForEach-Object {
        $line = "$_"
        Write-Host $line
        if ($line -match "\bSLOW\b.*\b$test\b") { Show-Stacks $line.Trim() }
    }
$result = $LASTEXITCODE
exit $result
