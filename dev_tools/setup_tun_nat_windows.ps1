# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

<#
.SYNOPSIS
    Sets up NAT and IP routing for litebox WinTUN networking.

.DESCRIPTION
    The litebox runner creates the WinTUN adapter when it starts.
    This script configures the host-side networking:
      - Assigns IP 10.0.0.1/24 to the adapter
      - Enables IP routing
      - Creates a NAT rule

    Guest addresses (hardcoded in litebox/src/net/mod.rs):
      Guest IP:  10.0.0.2
      Gateway:   10.0.0.1

    Requires: Administrator privileges, WinTUN adapter already created
    by running the litebox runner once with --tun-device-name.

.PARAMETER Action
    'up' to configure networking, 'down' to tear it down.

.PARAMETER AdapterName
    WinTUN adapter name (default: litebox0). Must match the runner's
    --tun-device-name flag.

.EXAMPLE
    # Run as Administrator:
    .\dev_tools\setup_tun_nat_windows.ps1 -Action up
    .\dev_tools\setup_tun_nat_windows.ps1 -Action down
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('up','down')]
    [string]$Action,

    [string]$AdapterName = 'litebox0'
)

$ErrorActionPreference = 'Stop'

$TunAddr = '10.0.0.1'
$TunPrefix = 24
$TunSubnet = '10.0.0.0/24'
$NatName = 'LiteboxNAT'

function Require-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function Do-Up {
    Require-Admin

    # Tear down first if already configured (idempotent).
    $existingNat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
    if ($existingNat) {
        Write-Host "==> $NatName already exists, tearing down first"
        Do-Down
    }

    # Create the WinTUN adapter if it doesn't exist yet.
    $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
    if (-not $adapter) {
        $ScriptDir = Split-Path -Parent $MyInvocation.ScriptName
        $RepoRoot = (Resolve-Path "$ScriptDir\..").Path
        $CreateTool = Join-Path $RepoRoot 'target\release\wintun_create_adapter.exe'
        if (-not (Test-Path $CreateTool)) {
            Write-Error "wintun_create_adapter.exe not found at $CreateTool`nRun: cargo build --release -p wintun_create_adapter"
            exit 1
        }
        Write-Host "==> Creating WinTUN adapter '$AdapterName'"
        & $CreateTool $AdapterName
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        # Wait briefly for the adapter to appear in the networking stack.
        Start-Sleep -Seconds 2
    } else {
        Write-Host "==> Adapter '$AdapterName' already exists"
    }

    Write-Host "==> Assigning IP $TunAddr/$TunPrefix to $AdapterName"
    # Remove any existing IP on this adapter first.
    Get-NetIPAddress -InterfaceAlias $AdapterName -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $TunAddr -PrefixLength $TunPrefix | Out-Null

    Write-Host "==> Enabling IP routing"
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    Set-ItemProperty -Path $regPath -Name 'IPEnableRouter' -Value 1

    Write-Host "==> Creating NAT rule ($NatName) for $TunSubnet"
    New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $TunSubnet | Out-Null

    Write-Host "==> Done. Guest DNS: configure resolv.conf to use 8.8.8.8 / 1.1.1.1"
    Write-Host "    Runner flag: --tun-device-name $AdapterName"
}

function Do-Down {
    Require-Admin

    Write-Host "==> Tearing down TUN networking"

    # Remove NAT.
    $nat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
    if ($nat) {
        Write-Host "    Removing NAT rule $NatName"
        Remove-NetNat -Name $NatName -Confirm:$false
    }

    # Remove IP address.
    $ip = Get-NetIPAddress -InterfaceAlias $AdapterName -ErrorAction SilentlyContinue
    if ($ip) {
        Write-Host "    Removing IP from $AdapterName"
        $ip | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    }

    Write-Host "==> Done"
}

switch ($Action) {
    'up'   { Do-Up }
    'down' { Do-Down }
}
