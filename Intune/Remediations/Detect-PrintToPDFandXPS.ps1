<#
.SYNOPSIS
Script detects a common blocker for feature Upgrades with Windows 11.
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Detect-PrintToPDForXPS

Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes
#> 
$PrintToPDF = (Get-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features").State -eq "Enabled"
$XPS = (Get-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features").State -eq "Enabled"

if ($PrintToPDF -or $XPS) {
    Exit 1
} else {
    Write-Host "Microsoft Outlook (New) not found."
    Exit 0
}