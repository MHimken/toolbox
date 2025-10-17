<#
.SYNOPSIS
    Ensure "Automatic proxy configuration" is set to "Disabled"
.DESCRIPTION
    This script checks if the "Automatic proxy configuration" policy is set to "Disabled".
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#> 
try {
    if (-not(Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\")) {
        Write-Output "The registry path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp does not exist."
        exit 1
    }
    if ((Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -ErrorAction SilentlyContinue) -ne 1) {
        Write-Output "The registry value 'DisableWpad' is not set to 1."
        exit 1
    }
} catch { 
    exit 1 
}
exit 0