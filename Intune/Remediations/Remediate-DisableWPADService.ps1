<#
.SYNOPSIS
    Ensure "Automatic proxy configuration" is set to "Disabled"
.DESCRIPTION
    This script sets the registry key to ensure that the policy "Automatic proxy configuration" is set to "Disabled".
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#> 
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\") -ne $true) {
      New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -force | Out-Null
    }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Value 1 -PropertyType DWord -Force
Write-Output "Remediation completed successfully."
exit 0