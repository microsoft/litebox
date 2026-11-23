# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#Requires -Version 7.2

<#
.SYNOPSIS
Builds the programs of the Windows containerd-shim tests into -Destination, which the tests take
from LITEBOX_SHIM_TEST_FIXTURES.

.DESCRIPTION
Run it after a `cargo build` of the Windows crates. The broker and the runner are copies of that
build's, so that later Cargo builds cannot replace programs that tests run. The guest is built in
WSL's default distribution.

.EXAMPLE
./.github/tools/build_windows_shim_fixtures.ps1 $env:LITEBOX_SHIM_TEST_FIXTURES
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Destination
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$fixtures = New-Item -ItemType Directory -Force -Path $Destination
$rustflags = $env:RUSTFLAGS
Push-Location (Join-Path $PSScriptRoot '..\..')
try {
    # As the tests build it: musl with `rust-lld` needs no Linux link toolchain.
    $env:RUSTFLAGS = "$rustflags -C linker=rust-lld -C linker-flavor=ld.lld -C target-feature=+crt-static".Trim()
    cargo build --locked -p litebox_guest_service --target x86_64-unknown-linux-musl --target-dir target\static-guest-service
    if ($LASTEXITCODE -ne 0) { throw 'cargo build of the guest service failed' }

    Copy-Item -Destination $fixtures.FullName -Path @(
        'target\debug\litebox-broker-userland.exe'
        'target\debug\litebox_runner_linux_on_windows_userland.exe'
        'target\static-guest-service\x86_64-unknown-linux-musl\debug\litebox-guest-service'
    )
    wsl.exe --exec bash litebox_runner_linux_on_windows_userland/tests/build_windows_linux_guest.sh `
        litebox_containerd_shim/tests/guest.c "$($fixtures.FullName)\guest" static
    if ($LASTEXITCODE -ne 0) { throw 'building tests/guest.c in WSL failed' }
} finally {
    $env:RUSTFLAGS = $rustflags
    Pop-Location
}
