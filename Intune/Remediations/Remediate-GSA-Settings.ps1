<#
.SYNOPSIS
    Remediate Global Secure Access, Kerberos, and IPv4 preference settings.
.DESCRIPTION
    This script sets configured registry values for Global Secure Access client settings,
    Kerberos FarKdcTimeout, and IPv4 preference (DisabledComponents). The script runs on
    all device join states, but Entra-only blocks are skipped automatically on domain joined
    and hybrid joined devices.
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2026-07-27
    Version 1.0: Added configurable blocks, Entra-only scope, and FarKdcTimeout/IPv4 remediation.

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

function Set-RegistryDwordValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [int]$Value
    )

    $valueKind = Get-RegistryValueKind -Path $Path -Name $Name
    if ($null -eq $valueKind) {
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        return "Created"
    }

    if ($valueKind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        return "RecreatedAsDword"
    }

    $currentValue = Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
    if ([int]$currentValue -ne $Value) {
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type DWord -Force | Out-Null
        return "Updated"
    }

    return "AlreadyCompliant"
}

# Configurable options
$joinInfoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"

# Example: disable only the IPv4 preference remediation by setting Enabled = $false in that block.
$registryRemediations = @(
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

    Write-Output "APPLICABLE: Device is in scope for remediation."

    $enabledRemediations = @($registryRemediations | Where-Object { $_.Enabled })
    if ($enabledRemediations.Count -eq 0) {
        Write-Output "SKIPPED: No registry remediation blocks are enabled."
        exit 0
    }

    foreach ($remediation in $registryRemediations) {
        if (-not $remediation.Enabled) {
            Write-Output "SKIPPED: Disabled remediation block '$($remediation.Name)'."
            continue
        }

        if ($remediation.EntraOnly -and ($isDomainJoined -or -not $isEntraJoined)) {
            Write-Output "SKIPPED: Block '$($remediation.Name)' applies to Entra joined (cloud-only) devices only."
            continue
        }

        if (-not (Test-Path -LiteralPath $remediation.Path)) {
            New-Item -Path $remediation.Path -Force | Out-Null
            Write-Output "REMEDIATED: Created registry path $($remediation.Path)."
        }

        foreach ($setting in $remediation.Settings.GetEnumerator()) {
            $result = Set-RegistryDwordValue -Path $remediation.Path -Name $setting.Key -Value ([int]$setting.Value)
            Write-Output "REMEDIATED: $($remediation.Name) '$($setting.Key)' = $($setting.Value) ($result)."
        }
    }

    Write-Output "COMPLIANT: Remediation completed successfully."
    exit 0
} catch {
    Write-Output "ERROR: Remediation failed. $($_.Exception.Message)"
    exit 1
}