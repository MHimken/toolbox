<#
.SYNOPSIS
    Detect compliance for Global Secure Access, Kerberos, and IPv4 preference settings.
.DESCRIPTION
    This script validates configured registry values for Global Secure Access client settings,
    Kerberos FarKdcTimeout, and IPv4 preference (DisabledComponents). The script runs on
    all device join states, but Entra-only blocks are skipped automatically on domain joined
    and hybrid joined devices.
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2026-07-27
    Version 1.0: Added configurable blocks, Entra-only scope, and FarKdcTimeout/IPv4 checks.

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#>

$ErrorActionPreference = 'Stop'

function Get-RegistryValueKind {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $item.GetValueKind($Name)
    } catch {
        return $null
    }
}

# Configurable options
$joinInfoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

# Example: disable only the IPv4 preference check by setting Enabled = $false in that block.
$registryChecks = @(
    @{
        Name = "GlobalSecureAccessClient"
        Enabled = $true
        EntraOnly = $false
        Path = "HKLM:\SOFTWARE\Microsoft\Global Secure Access Client"
        Settings = @{
            "HideSignOutButton"              = 0
            "HideDisablePrivateAccessButton" = 0
            "HideDisableButton"              = 0
            "RestrictNonPrivilegedUsers"     = 0
        }
    },
    @{
        Name = "Kerberos"
        Enabled = $true
        EntraOnly = $true
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        Settings = @{
            "FarKdcTimeout" = 0
        }
    },
    @{
        Name = "IPv4Preference"
        Enabled = $true
        EntraOnly = $false
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        Settings = @{
            "DisabledComponents" = 0x20
        }
    }
)

try {
    $isDomainJoined = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    $isEntraJoined = (Get-ChildItem -LiteralPath $joinInfoPath -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0

    Write-Output "APPLICABLE: Device is in scope for compliance checks."

    $enabledChecks = @($registryChecks | Where-Object { $_.Enabled })
    if ($enabledChecks.Count -eq 0) {
        Write-Output "COMPLIANT: No registry check blocks are enabled."
        exit 0
    }

    $nonCompliant = $false

    foreach ($check in $registryChecks) {
        if (-not $check.Enabled) {
            Write-Output "SKIPPED: Disabled check block '$($check.Name)'."
            continue
        }

        if ($check.EntraOnly -and ($isDomainJoined -or -not $isEntraJoined)) {
            Write-Output "SKIPPED: Block '$($check.Name)' applies to Entra joined (cloud-only) devices only."
            continue
        }

        foreach ($setting in $check.Settings.GetEnumerator()) {
            if (-not (Test-Path -LiteralPath $check.Path)) {
                Write-Output "NONCOMPLIANT: Missing registry path $($check.Path)."
                $nonCompliant = $true
                continue
            }

            $valueKind = Get-RegistryValueKind -Path $check.Path -Name $setting.Key
            if ($null -eq $valueKind) {
                Write-Output "NONCOMPLIANT: Missing value '$($setting.Key)' at $($check.Path)."
                $nonCompliant = $true
                continue
            }

            if ($valueKind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
                Write-Output "NONCOMPLIANT: '$($setting.Key)' at $($check.Path) is type $valueKind, expected DWord."
                $nonCompliant = $true
                continue
            }

            $currentValue = Get-ItemPropertyValue -LiteralPath $check.Path -Name $setting.Key -ErrorAction SilentlyContinue
            if ($null -eq $currentValue -or ([int]$currentValue -ne [int]$setting.Value)) {
                Write-Output "NONCOMPLIANT: '$($setting.Key)' at $($check.Path) is $currentValue, expected $($setting.Value)."
                $nonCompliant = $true
            }
        }
    }

    if (-not $nonCompliant) {
        Write-Output "COMPLIANT: All enabled checks passed."
        exit 0
    }

    Write-Output "NONCOMPLIANT: One or more checks failed."
    exit 1
} catch {
    Write-Output "ERROR: Detection failed. $($_.Exception.Message)"
    exit 1
}