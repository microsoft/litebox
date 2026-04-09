# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Pretty-print LiteBox audit log JSON lines from a file or directory.
#
# Usage:
#   # View the latest audit log from a directory:
#   .\View-AuditLog.ps1 -Path target\litebox-audit
#
#   # View a specific log file:
#   .\View-AuditLog.ps1 -Path target\litebox-audit\2026-04-08T12-34-56.jsonl
#
#   # Filter to security-relevant syscalls only:
#   .\View-AuditLog.ps1 -Path target\litebox-audit -Filter "openat|connect|execve|unlinkat|socket"

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline)]
    [string]$InputLine,

    [string]$Path,

    [string]$Filter,

    ## Optional prefix string to prepend to each output line (e.g., "[A] ").
    [string]$Prefix = ""
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

        if ($Prefix) {
            Write-Host -NoNewline -ForegroundColor DarkGray $Prefix
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
            Write-Error "Not found: $Path"
            return
        }
        # If Path is a directory, use the most recent .jsonl file.
        $resolvedPath = $Path
        if (Test-Path $Path -PathType Container) {
            $latest = Get-ChildItem $Path -Filter '*.jsonl' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $latest) {
                Write-Error "No .jsonl files found in $Path"
                return
            }
            $resolvedPath = $latest.FullName
            Write-Host -ForegroundColor DarkGray "Reading: $resolvedPath"
        }
        Get-Content $resolvedPath | ForEach-Object {
            if ($_ -match '^\{') {
                Format-Event $_
            }
        }
    }
}
