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

    # Dedup state for repeated tcp_denied/udp_denied events.
    $script:lastDeniedKey = $null
    $script:lastDeniedCount = 0

    function Flush-Denied {
        if ($script:lastDeniedCount -gt 1) {
            if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
            Write-Host -ForegroundColor DarkRed "  (repeated $($script:lastDeniedCount - 1) more times)"
        }
        $script:lastDeniedKey = $null
        $script:lastDeniedCount = 0
    }

    function Format-Event($json) {
        try {
            $evt = $json | ConvertFrom-Json
        } catch {
            return
        }

        # Broker policy events (have "event" field instead of "syscall").
        if ($evt.event) {
            if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
            switch ($evt.event) {
                'policy_loaded' {
                    Write-Host -ForegroundColor Cyan "=== Sandbox Policy Loaded ==="
                    if ($evt.network_deny_all) {
                        if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
                        Write-Host -ForegroundColor Cyan "  Network: deny all except:"
                        foreach ($rule in $evt.network_allow) {
                            if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
                            Write-Host -ForegroundColor Green "    + $rule"
                        }
                        if (-not $evt.network_allow -or $evt.network_allow.Count -eq 0) {
                            if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
                            Write-Host -ForegroundColor Red "    (none - all network blocked)"
                        }
                    } else {
                        if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
                        Write-Host -ForegroundColor Yellow "  Network: allow all"
                    }
                }
                'dns_resolved' {
                    $ipList = $evt.ips -join ', '
                    Write-Host -ForegroundColor Cyan "DNS $($evt.hostname) -> $ipList"
                }
                'tcp_allowed' {
                    Flush-Denied
                    $target = if ($evt.hostname) { "$($evt.hostname) ($($evt.ip))" } else { "$($evt.ip)" }
                    Write-Host -ForegroundColor Green "+ TCP $target`:$($evt.port)"
                }
                'tcp_denied' {
                    $key = "$($evt.ip):$($evt.port)"
                    if ($key -eq $script:lastDeniedKey) {
                        $script:lastDeniedCount++
                        return
                    }
                    Flush-Denied
                    $script:lastDeniedKey = $key
                    $script:lastDeniedCount = 1
                    $target = if ($evt.hostname) { "$($evt.hostname) ($($evt.ip))" } else { "$($evt.ip)" }
                    Write-Host -ForegroundColor Red "X BLOCKED TCP $target`:$($evt.port)"
                }
                'udp_denied' {
                    $key = "udp:$($evt.ip):$($evt.port)"
                    if ($key -eq $script:lastDeniedKey) {
                        $script:lastDeniedCount++
                        return
                    }
                    Flush-Denied
                    $script:lastDeniedKey = $key
                    $script:lastDeniedCount = 1
                    $target = if ($evt.hostname) { "$($evt.hostname) ($($evt.ip))" } else { "$($evt.ip)" }
                    Write-Host -ForegroundColor Red "X BLOCKED UDP $target`:$($evt.port)"
                }
                'fs_denied' {
                    Write-Host -ForegroundColor Red "X FS DENIED $($evt.action): $($evt.path)"
                }
                default {
                    Write-Host -ForegroundColor DarkGray "[broker] $($evt.event): $json"
                }
            }
            return
        }

        $name = $evt.syscall
        Flush-Denied
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
        } elseif ($InputLine -match '^#') {
            if ($Prefix) { Write-Host -NoNewline -ForegroundColor DarkGray $Prefix }
            Write-Host -ForegroundColor DarkYellow $InputLine.Substring(2)
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
            } elseif ($_ -match '^#') {
                Write-Host -ForegroundColor DarkYellow $_.Substring(2)
            }
        }
    }
}
