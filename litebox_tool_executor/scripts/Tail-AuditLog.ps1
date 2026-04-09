# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Tail LiteBox audit logs and broker logs from a directory.
# Automatically discovers new session files and labels them [A], [B], etc.
#
# Usage:
#   .\Tail-AuditLog.ps1                                    # default directory
#   .\Tail-AuditLog.ps1 -Dir C:\src\litebox\target\audit   # custom directory
#   .\Tail-AuditLog.ps1 -Raw                               # raw JSON (no pretty-print)

[CmdletBinding()]
param(
    [string]$Dir = 'C:\src\litebox\target\litebox-audit',
    [switch]$Raw
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$formatter = Join-Path $scriptDir 'View-AuditLog.ps1'

Write-Host "Watching audit logs in: $Dir" -ForegroundColor DarkGray

$seen = @{}
$labels = @{}
$nextLabel = 0

while ($true) {
    if (Test-Path $Dir) {
        Get-ChildItem $Dir -Filter '*.jsonl' | Sort-Object Name | ForEach-Object {
            $p = $_.FullName

            # New session discovered.
            if (-not $seen.ContainsKey($p)) {
                $seen[$p] = (Get-Content $p).Count
                $lbl = [char]([int][char]'A' + ($nextLabel++ % 26))
                $labels[$p] = $lbl
                Write-Host "[$lbl] New session: $($_.Name)" -ForegroundColor Cyan

                # Initialize broker log tracking.
                $bp = $p -replace '\.jsonl$', '.broker.log'
                if (-not $seen.ContainsKey($bp)) { $seen[$bp] = 0 }
            }

            $lbl = $labels[$p]

            # Tail new audit lines.
            $lines = Get-Content $p
            if ($lines.Count -gt $seen[$p]) {
                $newLines = $lines[$seen[$p]..($lines.Count - 1)]
                if ($Raw) {
                    $newLines | ForEach-Object { Write-Host "[$lbl] $_" }
                } else {
                    $newLines | & $formatter -Prefix "[$lbl] "
                }
                $seen[$p] = $lines.Count
            }

            # Tail new broker log lines.
            $bp = $p -replace '\.jsonl$', '.broker.log'
            if (Test-Path $bp) {
                $bl = Get-Content $bp
                if ($bl.Count -gt $seen[$bp]) {
                    $bl[$seen[$bp]..($bl.Count - 1)] | ForEach-Object {
                        Write-Host "[$lbl] $_" -ForegroundColor DarkGray
                    }
                    $seen[$bp] = $bl.Count
                }
            }
        }
    }
    Start-Sleep -Milliseconds 250
}
