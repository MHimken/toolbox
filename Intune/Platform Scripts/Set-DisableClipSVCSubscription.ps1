<#
.SYNOPSIS
    Disable the ClipSVC subscription functionality.
.DESCRIPTION
    This script configures DisableSubscription as a DWORD with the value 1 under
    the ClipSVC Parameters registry key.
.NOTES
Version: 1.0
Author: Martin Himken
Initial creation date: 27.08.26
Last change: 27.08.26
Changes: see changelog.md

Intune Platform Script settings:
* Run this script using the logged-on credentials: No
* Enforce script signature check: No
* Run script in 64-bit PowerShell: Yes
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
        return 'Created'
    }

    if ([string]$valueKind -ne 'DWord') {
        Remove-ItemProperty -LiteralPath $Path -Name $Name -Force -ErrorAction Stop
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        return 'RecreatedAsDword'
    }

    $currentValue = Get-ItemPropertyValue -LiteralPath $Path -Name $Name -ErrorAction Stop
    if ([int]$currentValue -ne $Value) {
        Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Type DWord -Force | Out-Null
        return 'Updated'
    }

    return 'AlreadyCompliant'
}

$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ClipSVC\Parameters'
$valueName = 'DisableSubscription'
$desiredValue = 1

try {
    if (-not (Test-Path -LiteralPath $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Output "Created registry path $registryPath."
    }

    $result = Set-RegistryDwordValue -Path $registryPath -Name $valueName -Value $desiredValue

    $verifyKind = Get-RegistryValueKind -Path $registryPath -Name $valueName
    $verifyValue = Get-ItemPropertyValue -LiteralPath $registryPath -Name $valueName -ErrorAction Stop
    if ([string]$verifyKind -ne 'DWord' -or [int]$verifyValue -ne $desiredValue) {
        throw "Verification failed. '$valueName' is type $verifyKind with value $verifyValue; expected DWORD $desiredValue."
    }

    Write-Output "SUCCESS: '$valueName' at $registryPath is DWORD $desiredValue ($result)."
    exit 0
} catch {
    Write-Output "ERROR: Configuration failed. $($_.Exception.Message)"
    exit 1
}