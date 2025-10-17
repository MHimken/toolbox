<#
.SYNOPSIS
    Detect if the WebClient service is disabled
.DESCRIPTION
    This script checks if the WebClient service is present and disabled.
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#>

$servicename = "WebClient"
$serviceOption = 'StartupType'
$serviceOptionValue = 'Disabled'
$ServiceObject = Get-Service -Name $servicename -ErrorAction SilentlyContinue

$checkarray = 0
if (($null -ne $ServiceObject) -and ($ServiceObject.$serviceOption -eq $serviceOptionValue)) {
    $checkarray++
}

if ($checkarray -ne 0) {
    Write-Host "Service is available and correctly configured"
    exit 0
} else {
    Write-Host "Service is not available or correctly configured"
    exit 1
}