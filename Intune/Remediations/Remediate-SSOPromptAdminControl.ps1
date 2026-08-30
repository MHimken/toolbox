<#
.SYNOPSIS
    Remediate admin control of SSO prompts in Windows.
.DESCRIPTION
    This script configures the policy registry value for automatic acceptance of
    SSO permissions to the expected DWORD value.
.NOTES
Version: 1.1
Author: Martin Himken
Initial creation date: 23.08.26
Last change: 27.08.26
Changes: see changelog.md

Intune Remediation settings:
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
        return "Created"
    }

    if ([string]$valueKind -ne 'DWord') {
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

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AAD"
$valueName = "AutoAcceptSsoPermission"
$desiredValue = 1

try {
    Write-Output "APPLICABLE: Device is in scope for remediation."

    if (-not (Test-Path -LiteralPath $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Output "REMEDIATED: Created registry path $registryPath."
    }

    $result = Set-RegistryDwordValue -Path $registryPath -Name $valueName -Value $desiredValue
    Write-Output "REMEDIATED: '$valueName' at $registryPath set to $desiredValue ($result)."

    $verifyValue = Get-ItemPropertyValue -LiteralPath $registryPath -Name $valueName -ErrorAction Stop
    if ([int]$verifyValue -ne $desiredValue) {
        Write-Output "ERROR: Verification failed. '$valueName' is $verifyValue, expected $desiredValue."
        exit 1
    }

    Write-Output "COMPLIANT: Remediation completed successfully."
    exit 0
} catch {
    Write-Output "ERROR: Remediation failed. $($_.Exception.Message)"
    exit 1
}
