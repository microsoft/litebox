# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#Requires -Version 7.2

<#
.SYNOPSIS
Pulls a Windows image with Docker and prints its layer folders, as the containerd-shim HCS tests
take them in LITEBOX_TEST_WINDOWS_LAYERS.

.DESCRIPTION
Needs Docker's windowsfilter storage driver, and so administrator rights.

.EXAMPLE
$env:LITEBOX_TEST_WINDOWS_LAYERS = ./.github/tools/pull_windows_test_layers.ps1
#>

[CmdletBinding()]
param(
    [string]$Image = 'mcr.microsoft.com/windows/nanoserver:ltsc2025'
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# Docker's service sometimes stops during a GitHub runner's boot; starting it again recovers
# (https://github.com/actions/runner-images/issues/13729).
$deadline = (Get-Date).AddMinutes(3)
while ($true) {
    docker version *> $null
    if ($LASTEXITCODE -eq 0) { break }
    if ((Get-Date) -gt $deadline) { throw 'Docker did not start' }
    if ((Get-Service docker).Status -eq 'Stopped') { Start-Service docker -ErrorAction Continue }
    Start-Sleep -Seconds 5
}
foreach ($try in 1..3) {
    docker pull --quiet $Image | Out-Host
    if ($LASTEXITCODE -eq 0) { break }
    if ($try -eq 3) { throw "cannot pull $Image" }
    Start-Sleep -Seconds 10
}
$driver = docker info --format '{{.Driver}}'
if ($driver -ne 'windowsfilter') { throw "Docker's storage driver is $driver, not windowsfilter" }
$top = docker image inspect --format '{{.GraphDriver.Data.dir}}' $Image
if ($LASTEXITCODE -ne 0) { throw "cannot inspect $Image" }
# The parents, topmost first; a base layer has none.
$chain = Join-Path $top 'layerchain.json'
$parents = if (Test-Path $chain) { @(Get-Content -Raw $chain | ConvertFrom-Json | Where-Object { $_ }) } else { @() }
(@($top) + $parents) -join ';'
