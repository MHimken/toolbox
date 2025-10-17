<#
.SYNOPSIS
    Ensure "Network access: Do not allow storage of passwords and credentials for network authentication" is set to "Disabled"
.DESCRIPTION
    This script checks and sets the registry key to ensure that the policy "Network access: Do not allow storage of passwords and credentials for network authentication" is set to "Disabled".
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#> 
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") -ne $true) {
      New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -force | Out-Null
    }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'disabledomaincreds' -Value 0 -PropertyType DWord -Force
Write-Output "Network access: Do not allow storage of passwords and credentials for network authentication successfully set to Disabled."