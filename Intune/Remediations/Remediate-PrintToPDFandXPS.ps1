<#
.SYNOPSIS
Script remediates a common blocker for feature Upgrades with Windows 11.
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Remediate-PrintToPDForXPS

Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 

try {
    Disable-WindowsOptionalFeature -FeatureName "Printing-PrintToPDFServices-Features" -ErrorAction Stop
    Disable-WindowsOptionalFeature -FeatureName "Printing-XPSServices-Features" -ErrorAction Stop
    Write-Host "Removal of features successful"

} catch {
    Write-Error "Removal of features failed"
}