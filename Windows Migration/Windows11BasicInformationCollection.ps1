#Requires -RunAsAdministrator
<#
.SYNOPSIS
This script collects basic information to verify the readiness for a Windows 11 installation. 
.DESCRIPTION
The script is _not_ intended to verify anything. The idea being that you have a database that can then verify compatibility against.
TPM and SecureBoot are requested to see, if they're already enabled, not to verify if they're available. 
.NOTES
Initial Creation date: 05.12.24
Last Update: 05.12.24
Version: 1.0
#>
$ModelManufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Model,Manufacturer
$SKU = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('EditionID')
$OSVersion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('LCUVer')
$TPM = -not (Get-Tpm).ManufacturerVersionFull20.Contains('not supported')
$SecureBoot = Confirm-SecureBootUEFI

$ResultObject = [PSCustomObject]@{
    Manufacturer      = $ModelManufacturer.Manufacturer
    Model  = $ModelManufacturer.Model
    SKU     = $SKU
    OSVersion = $OSVersion
    TPM    = $TPM
    'Secure Boot' = $SecureBoot
}

return $ResultObject