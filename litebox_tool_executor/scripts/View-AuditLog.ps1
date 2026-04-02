# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Pretty-print LiteBox audit log JSON lines from stderr or a file.
#
# Usage:
#   # Tail a log file:
#   .\View-AuditLog.ps1 -Path target\litebox-audit.jsonl
#
#   # Pipe from executor stderr:
#   cargo run -p litebox_tool_executor -- --rootfs target\busybox-minimal.tar /bin/busybox echo hi 2>&1 |
#     Where-Object { $_ -match '^\{' } |
#     .\View-AuditLog.ps1
#
#   # Filter to security-relevant syscalls only:
#   .\View-AuditLog.ps1 -Path target\litebox-audit.jsonl -Filter "openat|connect|execve|unlinkat|socket"

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline)]
    [string]$InputLine,

    [string]$Path,

    [string]$Filter
)

begin {
    $colors = @{
        'openat'     = 'Cyan'
        'write'      = 'Gray'
        'read'       = 'Gray'
        'close'      = 'DarkGray'
        'mmap'       = 'DarkCyan'
        'mprotect'   = 'DarkCyan'
        'munmap'     = 'DarkCyan'
        'brk'        = 'DarkCyan'
        'execve'     = 'Yellow'
        'exit'       = 'DarkYellow'
        'exit_group' = 'DarkYellow'
        'clone'      = 'Magenta'
        'clone3'     = 'Magenta'
        'socket'     = 'Red'
        'connect'    = 'Red'
        'bind'       = 'Red'
        'listen'     = 'Red'
        'accept'     = 'Red'
        'unlinkat'   = 'Yellow'
        'mkdir'      = 'Green'
        'other'      = 'DarkGray'
    }

    function Format-Event($json) {
        try {
            $evt = $json | ConvertFrom-Json
        } catch {
            return
        }

        $name = $evt.syscall
        if ($Filter -and $name -notmatch $Filter) { return }

        $color = if ($colors.ContainsKey($name)) { $colors[$name] } else { 'White' }

        # Format arguments
        $argParts = @()
        foreach ($arg in $evt.args) {
            if ($null -ne $arg.fd)    { $argParts += "fd=$($arg.fd)" }
            if ($null -ne $arg.path)  { $argParts += "`"$($arg.path)`"" }
            if ($null -ne $arg.addr)  { $argParts += $arg.addr }
            if ($null -ne $arg.int)   { $argParts += "$($arg.int)" }
            if ($null -ne $arg.flags) { $argParts += $arg.flags }
        }
        $argStr = $argParts -join ', '

        # Format result
        if ($null -ne $evt.result.ok) {
            $resultStr = "= $($evt.result.ok)"
        } else {
            $resultStr = "ERR $($evt.result.err)"
        }

        Write-Host -NoNewline -ForegroundColor $color "$name"
        Write-Host -NoNewline "($argStr) "
        if ($null -ne $evt.result.err) {
            Write-Host -ForegroundColor Red $resultStr
        } else {
            Write-Host $resultStr
        }
    }
}

process {
    if ($InputLine) {
        if ($InputLine -match '^\{') {
            Format-Event $InputLine
        }
    }
}

end {
    if ($Path) {
        if (-not (Test-Path $Path)) {
            Write-Error "File not found: $Path"
            return
        }
        Get-Content $Path | ForEach-Object {
            if ($_ -match '^\{') {
                Format-Event $_
            }
        }
    }
}
