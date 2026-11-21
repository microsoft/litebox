# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

param([Parameter(Mandatory)][ValidateSet('alone', 'with-python')][string]$Mode)

$ErrorActionPreference = 'Stop'
if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This investigation configures crash dumps on a disposable GitHub-hosted runner.'
}
$lldb = (Get-Item "$env:ProgramFiles\LLVM\bin\lldb.exe").FullName
$dumpDir = (New-Item -ItemType Directory -Path "$env:RUNNER_TEMP\node-crashes").FullName
$images = 'litebox-broker-userland.exe', 'litebox_runner_linux_on_windows_userland.exe'
foreach ($name in $images) {
    $key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$name"
    New-Item -Force $key | Out-Null
    New-ItemProperty $key -Name DumpFolder -PropertyType ExpandString -Value $dumpDir -Force | Out-Null
    New-ItemProperty $key -Name DumpType -PropertyType DWord -Value 1 -Force | Out-Null
}

$sampled = [System.Collections.Generic.HashSet[uint32]]::new()
function Show-NodeStacks {
    $processes = Get-CimInstance Win32_Process -Property Name,ProcessId,ParentProcessId,CommandLine
    $level = $processes | Where-Object {
        $_.Name -like 'run-*.exe' -and $_.CommandLine -match '\btest_node_with_rewriter\b'
    }
    while ($level) {
        foreach ($process in $level) {
            Write-Host "  $($process.Name) pid=$($process.ProcessId) parent=$($process.ParentProcessId)"
            if ($process.Name -in $images -and $sampled.Add($process.ProcessId)) {
                $argsLine = "--batch -p $($process.ProcessId) -o `"thread backtrace all`" -o `"process detach`""
                $debugger = Start-Process $lldb -ArgumentList $argsLine -NoNewWindow -PassThru
                if (!$debugger.WaitForExit(30000)) {
                    $debugger.Kill()
                    Write-Warning "Timed out collecting stacks for $($process.ProcessId)"
                    continue
                }
                if ($debugger.ExitCode -ne 0) { Write-Warning "cdb exited $($debugger.ExitCode)" }
            }
        }
        $parents = $level.ProcessId
        $level = $processes | Where-Object { $_.ParentProcessId -in $parents }
    }
}

$filter = 'test(=test_node_with_rewriter)'
if ($Mode -eq 'with-python') { $filter += ' or test(=test_runner_with_python)' }
cargo nextest run --color never --locked --profile ci -p litebox_runner_linux_on_windows_userland --test run `
    -E $filter --test-threads 2 --stress-duration 20m --retries 0 --fail-fast --no-tests fail `
    --status-level pass --failure-output immediate 2>&1 | ForEach-Object {
        $line = "$_"
        Write-Host $line
        if ($line -match '\bSLOW\b.*\btest_node_with_rewriter\b') { Show-NodeStacks }
    }
$result = $LASTEXITCODE
foreach ($dump in Get-ChildItem -LiteralPath $dumpDir -Filter '*.dmp') {
    Write-Host "Crash stacks: $($dump.Name)"
    & $lldb --batch -c $dump.FullName -o 'thread backtrace all'
}
exit $result
