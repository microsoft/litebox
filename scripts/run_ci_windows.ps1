[CmdletBinding()]
param(
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This script only supports Windows."
}

$nextestVersion = "0.9.114"
$expandedWindowsCrates = @(
    "litebox_common_linux",
    "litebox_common_windows",
    "litebox_egress_proxy",
    "litebox_syscall_rewriter",
    "litebox_packager",
    "litebox_broker_protocol",
    "litebox_broker_transport",
    "litebox_broker_local_userland",
    "litebox_broker_core",
    "litebox_broker_local",
    "litebox_broker_host",
    "litebox_broker_transport_windows_userland",
    "litebox_broker_platform_windows_userland",
    "litebox_platform_windows_userland",
    "litebox_shim_linux",
    "litebox_shim_windows",
    "litebox_runner_linux_on_windows_userland",
    "litebox_runner_windows_userland"
)

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host "> $Command $($Arguments -join ' ')" -ForegroundColor Cyan
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$Command' failed with exit code $LASTEXITCODE."
    }
}

function Get-ExistingWorkspaceCrates {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Candidates,

        [Parameter(Mandatory = $true)]
        [hashtable]$WorkspacePackages
    )

    return @($Candidates | Where-Object { $WorkspacePackages.ContainsKey($_) })
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$previousRustFlags = [Environment]::GetEnvironmentVariable("RUSTFLAGS", "Process")
$previousRustDocFlags = [Environment]::GetEnvironmentVariable("RUSTDOCFLAGS", "Process")
Push-Location $repositoryRoot

try {
    if (-not $SkipSetup) {
        $toolchain = (Select-String -Path "rust-toolchain.toml" -Pattern '^\s*channel\s*=\s*"([^"]+)"').Matches.Groups[1].Value
        if (-not $toolchain) {
            throw "Could not determine the Rust channel from rust-toolchain.toml."
        }

        Invoke-CheckedCommand "rustup" @(
            "toolchain", "install", $toolchain,
            "--profile", "minimal",
            "--no-self-update",
            "--component", "rustfmt,clippy",
            "--target", "x86_64-pc-windows-msvc"
        )

        $installedNextestVersion = & cargo nextest --version 2>$null
        if ($LASTEXITCODE -ne 0 -or $installedNextestVersion -notmatch "cargo-nextest $([regex]::Escape($nextestVersion))(\s|$)") {
            Invoke-CheckedCommand "cargo" @(
                "install", "cargo-nextest",
                "--version", $nextestVersion,
                "--locked"
            )
        }
    }

    $metadataJson = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "'cargo metadata' failed with exit code $LASTEXITCODE."
    }

    $workspacePackages = @{}
    foreach ($package in ($metadataJson | ConvertFrom-Json).packages) {
        $workspacePackages[$package.name] = $true
    }

    if ($workspacePackages.ContainsKey("litebox_runner_windows_userland")) {
        $buildCrates = Get-ExistingWorkspaceCrates $expandedWindowsCrates $workspacePackages
        $testCrates = $buildCrates
        Write-Host "Using the expanded Windows CI package set." -ForegroundColor Green
    }
    else {
        $buildCrates = Get-ExistingWorkspaceCrates @(
            "litebox_runner_linux_on_windows_userland"
        ) $workspacePackages
        $testCrates = Get-ExistingWorkspaceCrates @(
            "litebox_runner_linux_on_windows_userland",
            "litebox_shim_linux"
        ) $workspacePackages
        Write-Host "Using the main Windows CI package set." -ForegroundColor Green
    }

    if ($buildCrates.Count -eq 0 -or $testCrates.Count -eq 0) {
        throw "No compatible Windows CI package set was found in this workspace."
    }

    $buildPackageArguments = foreach ($crate in $buildCrates) {
        "-p"
        $crate
    }
    $testPackageArguments = foreach ($crate in $testCrates) {
        "-p"
        $crate
    }

    $env:RUSTFLAGS = "-Dwarnings"
    $env:RUSTDOCFLAGS = "-Dwarnings"

    Invoke-CheckedCommand "cargo" @(
        "fmt", "--all", "--", "--check"
    )
    Invoke-CheckedCommand "cargo" (@(
        "clippy", "--locked", "--verbose", "--all-targets", "--all-features"
    ) + $buildPackageArguments)
    Invoke-CheckedCommand "cargo" (@(
        "build", "--locked", "--verbose"
    ) + $buildPackageArguments)
    Invoke-CheckedCommand "cargo" (@(
        "nextest", "run", "--locked", "--profile", "ci"
    ) + $testPackageArguments)
    Invoke-CheckedCommand "cargo" (@(
        "test", "--locked", "--verbose", "--doc"
    ) + $buildPackageArguments)
    Invoke-CheckedCommand "cargo" (@(
        "doc", "--locked", "--verbose", "--no-deps", "--all-features", "--document-private-items"
    ) + $buildPackageArguments)
}
finally {
    if ($null -eq $previousRustFlags) {
        Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    }
    else {
        $env:RUSTFLAGS = $previousRustFlags
    }

    if ($null -eq $previousRustDocFlags) {
        Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue
    }
    else {
        $env:RUSTDOCFLAGS = $previousRustDocFlags
    }

    Pop-Location
}
