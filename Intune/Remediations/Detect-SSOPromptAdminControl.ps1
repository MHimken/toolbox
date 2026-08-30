<#
.SYNOPSIS
    Detect compliance for admin control of SSO prompts in Windows.
.DESCRIPTION
    This script validates that the policy registry value for automatic acceptance of
    SSO permissions is configured as expected.
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

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AAD"
$valueName = "AutoAcceptSsoPermission"
$expectedValue = 1

try {
    Write-Output "APPLICABLE: Device is in scope for compliance checks."

    if (-not (Test-Path -LiteralPath $registryPath)) {
        Write-Output "NONCOMPLIANT: Missing registry path $registryPath."
        exit 1
    }

    $valueKind = Get-RegistryValueKind -Path $registryPath -Name $valueName
    if ($null -eq $valueKind) {
        Write-Output "NONCOMPLIANT: Missing value '$valueName' at $registryPath."
        exit 1
    }

    if ([string]$valueKind -ne 'DWord') {
        Write-Output "NONCOMPLIANT: '$valueName' at $registryPath is type $valueKind, expected DWord."
        exit 1
    }

    $currentValue = Get-ItemPropertyValue -LiteralPath $registryPath -Name $valueName -ErrorAction SilentlyContinue
    if ($null -eq $currentValue -or ([int]$currentValue -ne $expectedValue)) {
        Write-Output "NONCOMPLIANT: '$valueName' at $registryPath is $currentValue, expected $expectedValue."
        exit 1
    }

    Write-Output "COMPLIANT: '$valueName' at $registryPath is $expectedValue."
    exit 0
} catch {
    Write-Output "ERROR: Detection failed. $($_.Exception.Message)"
    exit 1
}
