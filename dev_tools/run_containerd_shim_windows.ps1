# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

<#
.SYNOPSIS
Builds, stages, and runs the LiteBox containerd shim (io.containerd.litebox.v1) on Windows, and
checks that the container's root archive lets the broker map files straight from it.

The host's existing containerd runs the container: only its runtime is LiteBox's shim, which runs
the container's Linux programs in a LiteBox broker on the host, rather than in a VM.

.DESCRIPTION
Steps, each of which can be skipped:

  1. Build containerd-shim-litebox-v1.exe and litebox-broker-userland.exe for Windows.
  2. Build the guest service, a static Linux binary that runs inside the container, in WSL.
  3. Stage all three in -InstallDir, where containerd must find the shim on its PATH.
  4. Get a Linux root file system tar: -RootfsTar, or `docker export` of -Image.
  5. Run -Command in a container with `ctr` and the host's containerd (at -Address), naming the
     shim by its path, so that containerd needs no configuration, and check the container's root
     archive while it runs: every non-empty file's data should start on a 4 KiB boundary. The
     container's OCI spec is generated, with the tar as its `root.path`, since `ctr` on Windows
     has no `--rootfs` and Windows snapshotters do not unpack Linux images.

-CheckArchive checks any tar archive and does nothing else.

Prerequisites for step 5 (verified with containerd 2.4.2 and no admin rights):

  * containerd running, as a service or as a user process (`containerd --config <file>`). As a
    user, disable the cimfs snapshotter, whose failure to format a VHD without admin rights takes
    containerd's metadata, and so every service, down with it; the shim needs no snapshotter:
        disabled_plugins = ['io.containerd.snapshotter.v1.cimfs', 'io.containerd.differ.v1.cimfs']
    and give it a pipe of its own with `[grpc] address = '\\.\pipe\containerd-litebox'`
    (then pass -Address).
  * A short LITEBOX_SHIM_STATE_ROOT in containerd's environment, which its shims inherit, such
    as `$env:USERPROFILE\.lbs`, if the default (`%TEMP%\containerd-shim-litebox`) is long: the
    broker's vsock socket lives below it, and Windows AF_UNIX paths hold at most 96 bytes.
  * Windows Defender may quarantine a build of the broker (Windows error 225); rebuild, or
    exclude the target directory.

.EXAMPLE
./dev_tools/run_containerd_shim_windows.ps1 -Image alpine

.EXAMPLE
./dev_tools/run_containerd_shim_windows.ps1 -RootfsTar C:\images\alpine.tar -Command '/bin/sh', '-c', 'ls /; sleep 10'

.EXAMPLE
./dev_tools/run_containerd_shim_windows.ps1 -CheckArchive $env:TEMP\containerd-shim-litebox\<hash>\rootfs.tar
#>

[CmdletBinding()]
param(
    # Cargo profile of the Windows binaries and the guest service.
    [ValidateSet('debug', 'release')]
    [string]$BuildProfile = 'release',
    # Where the shim, the broker, and the guest service are staged.
    [string]$InstallDir,
    # A Linux root file system tar (for example, from `docker export`).
    [string]$RootfsTar,
    # An image to export into a root file system tar, with Docker on Windows or in WSL.
    [string]$Image,
    # The command the container runs; it should outlive the archive check (a few seconds).
    [string[]]$Command = @('/bin/sh', '-c', 'echo hello from LiteBox; sleep 10'),
    # The container's ID for `ctr`.
    [string]$ContainerId = "litebox-$(Get-Random)",
    # The containerd namespace for `ctr`.
    [string]$Namespace = 'default',
    # The existing containerd's address, if not ctr's default (\\.\pipe\containerd-containerd).
    [string]$Address,
    # Name the shim by its runtime name, which containerd finds on its own PATH, instead of by
    # its path.
    [switch]$RuntimeByName,
    [switch]$SkipBuild,
    [switch]$SkipRun,
    # Only check that the tar archive at this path is page-aligned.
    [string]$CheckArchive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
if (-not $InstallDir) {
    $InstallDir = Join-Path $Root "target\litebox-shim\$BuildProfile"
}
$Runtime = 'io.containerd.litebox.v1'
$PageSize = 4096
$BlockSize = 512

function Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Reports how many of the regular files in the ustar archive at $Path start their data on a page
# boundary, as the broker needs to map them from the archive rather than copy them, and returns
# whether all non-empty ones do.
function Test-ArchiveAlignment([string]$Path) {
    # The shim may still be writing the archive; reading it denies writers, so wait for them.
    $stream = $null
    for ($attempt = 0; -not $stream; $attempt++) {
        try {
            $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
        } catch [System.IO.IOException] {
            if ($attempt -ge 120) { throw }
            Start-Sleep -Milliseconds 250
        }
    }
    try {
        $header = New-Object byte[] $BlockSize
        $position = [long]0
        $files = 0; $empty = 0; $aligned = 0; $padding = 0
        $unaligned = New-Object System.Collections.Generic.List[string]
        while ($position + $BlockSize -le $stream.Length) {
            $stream.Position = $position
            [void]$stream.Read($header, 0, $BlockSize)
            if (-not ($header | Where-Object { $_ -ne 0 } | Select-Object -First 1)) {
                break
            }
            $sizeField = [System.Text.Encoding]::ASCII.GetString($header, 124, 12).Trim([char]0, ' ')
            $size = if ($sizeField) { [Convert]::ToInt64($sizeField, 8) } else { 0 }
            $type = [char]$header[156]
            $name = [System.Text.Encoding]::ASCII.GetString($header, 0, 100).TrimEnd([char]0)
            $prefix = [System.Text.Encoding]::ASCII.GetString($header, 345, 155).TrimEnd([char]0)
            if ($prefix) { $name = "$prefix/$name" }
            $data = $position + $BlockSize
            if ($type -eq 'g' -and $size -eq 0) {
                $padding++
            } elseif ($type -eq '0' -or $header[156] -eq 0) {
                $files++
                if ($size -eq 0) {
                    $empty++
                } elseif ($data % $PageSize -eq 0) {
                    $aligned++
                } elseif ($unaligned.Count -lt 5) {
                    $unaligned.Add($name)
                }
            }
            $position = $data + [long][Math]::Ceiling($size / $BlockSize) * $BlockSize
        }
    } finally {
        $stream.Dispose()
    }
    $nonEmpty = $files - $empty
    Write-Host ("{0}: {1} regular files ({2} empty), {3} of {4} non-empty ones page-aligned, {5} padding headers" -f
        $Path, $files, $empty, $aligned, $nonEmpty, $padding)
    if ($aligned -ne $nonEmpty) {
        Write-Warning "unaligned files (which the broker snapshots or copies), for example: $($unaligned -join ', ')"
    }
    return $aligned -eq $nonEmpty
}

# Converts a Windows path to the path WSL sees it at.
function ConvertTo-WslPath([string]$Path) {
    (wsl -e wslpath -a ($Path -replace '\\', '/')).Trim()
}

if ($CheckArchive) {
    if (-not (Test-ArchiveAlignment $CheckArchive)) { exit 1 }
    exit 0
}

if (-not $SkipBuild) {
    Step "Building the shim and the broker for Windows ($BuildProfile)"
    $cargoProfile = @(if ($BuildProfile -eq 'release') { '--release' })
    & cargo build @cargoProfile -p litebox_containerd_shim -p litebox_broker_userland --manifest-path (Join-Path $Root 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

    Step 'Building the static guest service in WSL'
    # As the shim's tests build it: glibc, statically linked, in a target directory of its own so
    # that its flags keep the workspace's build cache. Linux file systems keep WSL builds fast.
    $wslRoot = ConvertTo-WslPath $Root
    $wslProfile = if ($BuildProfile -eq 'release') { '--release' } else { '' }
    $script = @"
set -euo pipefail
cd '$wslRoot'
export CARGO_TARGET_DIR=`$HOME/litebox-target/static-guest-service
RUSTFLAGS='-C target-feature=+crt-static' cargo build $wslProfile -p litebox_guest_service --target x86_64-unknown-linux-gnu
"@
    wsl -e bash -lc ($script -replace "`r", '')
    if ($LASTEXITCODE -ne 0) { throw 'building the guest service failed' }

    Step "Staging in $InstallDir"
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    $windowsTarget = Join-Path $Root "target\$BuildProfile"
    foreach ($binary in 'containerd-shim-litebox-v1.exe', 'litebox-broker-userland.exe') {
        Copy-Item (Join-Path $windowsTarget $binary) $InstallDir -Force
    }
    $guestService = "`$HOME/litebox-target/static-guest-service/x86_64-unknown-linux-gnu/$BuildProfile/litebox-guest-service"
    $wslInstallDir = ConvertTo-WslPath $InstallDir
    wsl -e bash -lc "cp $guestService '$wslInstallDir/litebox-guest-service'"
    if ($LASTEXITCODE -ne 0) { throw 'staging the guest service failed' }
    Get-ChildItem $InstallDir | Format-Table Name, Length -AutoSize | Out-Host
}

if ($SkipRun) { exit 0 }

if (-not $RootfsTar) {
    if (-not $Image) { throw 'give -RootfsTar or -Image' }
    $RootfsTar = Join-Path $Root "target\litebox-shim\$($Image -replace '[^A-Za-z0-9._-]', '_').tar"
    Step "Exporting $Image to $RootfsTar"
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $created = (docker create $Image).Trim()
        try { docker export -o $RootfsTar $created } finally { docker rm $created | Out-Null }
    } else {
        $wslTar = ConvertTo-WslPath $RootfsTar
        wsl -e bash -lc "set -e; c=`$(docker create '$Image'); trap 'docker rm `$c >/dev/null' EXIT; docker export -o '$wslTar' `$c"
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $RootfsTar)) { throw "cannot export $Image" }
}
$RootfsTar = (Resolve-Path $RootfsTar).Path

# containerd takes a runtime by name, finding its shim on containerd's own PATH, or by the shim's
# path, which needs nothing configured.
$shim = Join-Path $InstallDir 'containerd-shim-litebox-v1.exe'
$runtimeArgument = if ($RuntimeByName) { $Runtime } else { $shim }
$global = @('-n', $Namespace) + $(if ($Address) { @('--address', $Address) } else { @() })
$quoted = ($Command | ForEach-Object { if ($_ -match '\s') { "'$_'" } else { $_ } }) -join ' '

# The container's OCI spec: the tar as its root, and no network namespace of its own, since the
# guest uses the host's network through the broker.
$spec = Join-Path (Split-Path $RootfsTar) "$ContainerId.json"
[ordered]@{
    ociVersion = '1.1.0'
    process    = [ordered]@{
        terminal = $false
        user     = @{ uid = 0; gid = 0 }
        args     = @($Command)
        env      = @('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
        cwd      = '/'
    }
    root       = @{ path = $RootfsTar }
    hostname   = 'litebox'
    linux      = @{ namespaces = @(@{ type = 'pid' }, @{ type = 'ipc' }, @{ type = 'uts' }, @{ type = 'mount' }) }
} | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8NoBOM $spec

if (-not (Get-Command ctr -ErrorAction SilentlyContinue)) {
    Write-Warning "ctr is not on PATH, so no container runs. With the host's containerd running:"
    Write-Host @"
  ctr $($global -join ' ') run --rm --runtime $runtimeArgument --config $spec $ContainerId
"@
    if ($RuntimeByName) {
        Write-Host "  (with $InstallDir on containerd's PATH, for the service its system PATH)"
    }
    exit 0
}

Step "Running $quoted in $ContainerId with $runtimeArgument"
$ctr = Start-Process ctr -NoNewWindow -PassThru -ArgumentList (
    $global + @('run', '--rm', '--runtime', "`"$runtimeArgument`"", '--config', "`"$spec`"", $ContainerId))

# The shim keeps each container's root archive in its state root, which is the temporary
# directory of the user containerd runs as, unless LITEBOX_SHIM_STATE_ROOT says otherwise.
$stateRoots = @($env:LITEBOX_SHIM_STATE_ROOT, (Join-Path $env:TEMP 'containerd-shim-litebox'),
    (Join-Path $env:SystemRoot 'Temp\containerd-shim-litebox')) | Where-Object { $_ }
$archive = $null
for ($i = 0; $i -lt 60 -and -not $archive -and -not $ctr.HasExited; $i++) {
    Start-Sleep -Milliseconds 250
    $archive = $stateRoots | Where-Object { Test-Path $_ } |
        ForEach-Object { Get-ChildItem $_ -Recurse -Filter rootfs.tar -ErrorAction SilentlyContinue } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
$checked = $true
if ($archive) {
    Step 'Checking the container root archive'
    $checked = Test-ArchiveAlignment $archive.FullName
} else {
    Write-Warning "found no root archive under $($stateRoots -join ', ') while the container ran"
}
$ctr.WaitForExit()
Step "ctr exited with $($ctr.ExitCode)"
if ($ctr.ExitCode -ne 0 -or -not $checked) { exit 1 }
