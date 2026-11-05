# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

<#
.SYNOPSIS
Serves website/public from busybox httpd inside LiteBox on Windows, through the host's
containerd and the LiteBox containerd shim; the Windows counterpart of serve.sh.

.DESCRIPTION
Runs the busybox image's httpd in a container, with website/public served at /www and guest
port 80 published on ADDRESS:PORT (by default 127.0.0.1:18080). httpd runs `*.sh` files with
busybox `sh`, since the image has no bash. It uses dev_tools/run_containerd_shim_windows.ps1,
whose help lists what containerd needs; -Address, -BuildProfile, and -SkipBuild pass through.

The busybox image is pulled from Docker Hub's registry (anonymously, checked against its
digest) into target/litebox-shim/busybox.tar unless that exists.

.EXAMPLE
./website/serve.ps1 -SkipBuild -Address '\\.\pipe\containerd-litebox'
#>

[CmdletBinding()]
param(
    [string]$HostAddress = '127.0.0.1',
    [int]$Port = 18080,
    # Passed through to run_containerd_shim_windows.ps1.
    [string]$Address,
    [ValidateSet('debug', 'release')]
    [string]$BuildProfile = 'release',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$public = (Resolve-Path (Join-Path $PSScriptRoot 'public')).Path
$image = Join-Path $root 'target\litebox-shim\busybox.tar'

# Pulls the linux/amd64 busybox image, a single layer, as a root file system tar.
function Get-BusyboxRootfs([string]$Output) {
    $repository = 'library/busybox'
    $registry = "https://registry-1.docker.io/v2/$repository"
    $token = (Invoke-RestMethod "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repository}:pull").token
    $headers = @{
        Authorization = "Bearer $token"
        Accept        = 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
    }
    $index = Invoke-RestMethod "$registry/manifests/latest" -Headers $headers
    $platform = $index.manifests |
        Where-Object { $_.platform.os -eq 'linux' -and $_.platform.architecture -eq 'amd64' } |
        Select-Object -First 1
    $headers.Accept = 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
    $manifest = Invoke-RestMethod "$registry/manifests/$($platform.digest)" -Headers $headers
    if ($manifest.layers.Count -ne 1) { throw 'expected busybox to have one layer' }
    $layer = $manifest.layers[0].digest
    $compressed = "$Output.gz"
    New-Item -ItemType Directory -Force (Split-Path $Output) | Out-Null
    Invoke-WebRequest "$registry/blobs/$layer" -Headers @{ Authorization = "Bearer $token" } -OutFile $compressed
    if ('sha256:' + (Get-FileHash $compressed -Algorithm SHA256).Hash.ToLower() -ne $layer) {
        Remove-Item $compressed
        throw "busybox layer does not match its digest $layer"
    }
    $source = [System.IO.File]::OpenRead($compressed)
    try {
        $gzip = New-Object System.IO.Compression.GZipStream($source, [System.IO.Compression.CompressionMode]::Decompress)
        $target = [System.IO.File]::Create($Output)
        try { $gzip.CopyTo($target) } finally { $target.Dispose(); $gzip.Dispose() }
    } finally {
        $source.Dispose()
    }
    Remove-Item $compressed
}

if (-not (Test-Path $image)) {
    Write-Host "==> Pulling busybox into $image" -ForegroundColor Cyan
    Get-BusyboxRootfs $image
}

$run = @{ BuildProfile = $BuildProfile; SkipBuild = $SkipBuild }
if ($Address) { $run.Address = $Address }
$url = "http://${HostAddress}:$Port/"
Write-Host "==> Serving $public at $url; stop it with Ctrl+C or ``ctr tasks kill``" -ForegroundColor Cyan
& (Join-Path $root 'dev_tools\run_containerd_shim_windows.ps1') -RootfsTar $image `
    -Publish "${HostAddress}:${Port}:80" -Mount @{ $public = '/www' } -Command '/bin/sh', '-c', `
    'echo "*.sh:/bin/sh" > /tmp/httpd.conf && exec httpd -f -p 80 -h /www -c /tmp/httpd.conf' `
    @run
