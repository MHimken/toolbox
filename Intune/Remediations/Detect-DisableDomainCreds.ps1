<#
.SYNOPSIS
    Ensure "Network access: Do not allow storage of passwords and credentials for network authentication" is set to "Disabled"
.DESCRIPTION
    This script checks if the "Network access: Do not allow storage of passwords and credentials for network authentication" policy is set to "Disabled".
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#> 
try {
    if (-not(Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
        Write-Output "The registry path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa does not exist."
        exit 1
    }
    if ((Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'disabledomaincreds' -ErrorAction SilentlyContinue) -eq 2) {
        Write-Output "The registry value 'disabledomaincreds' is set to 2."
    } else {
        Write-Output "The registry value 'disabledomaincreds' is not set to 2."
        exit 1
    }
} catch { 
    exit 1 
}
exit 0