<#
.SYNOPSIS
This script can be used (not just in Intune tbh) to make something/someone wait. 
.DESCRIPTION
This was created to make a Win32 app that can wait a specified amount of time.
Don't forget that IME runs as a 32bit process and the registry check must therefore run as follows:
Key Path: HKEY_LOCAL_MACHINE\Software\MHimken
Value Name: Win32AppWaited
Detection Method: Value exists
Associated with a 32-bit app on 64-bit clients: Yes
"Uninstall" can be done using:
powershell.exe -executionpolicy bypass Win32App-Wait.ps1 -Uninstall
.EXAMPLE
    The following example would run for 5 minutes and set the registry key.
    .\Win32App-Wait.ps1 -Length 5
    
    In Intune that'd be:
    powershell.exe -executionpolicy bypass -file Win32App-Wait.ps1 -Length 5
.EXAMPLE
    The following example would run for 5 minutes and set the registry key.
    .\Win32App-Wait.ps1 -Length 5 -Unit Hours
    In Intune that'd be:
    powershell.exe -executionpolicy bypass -file Win32App-Wait.ps1 -Length 5 -Unit Hours
.NOTES
    Version: 1.0
    Author: Martin Himken
    Original script name: Win32App-Wait.ps1
    Initial 15.04.2025
    Last Update: 17.04.2025
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [int]$Length,
    $Unit = "Minutes",
    [switch]$Uninstall
)
function Start-CustomSleep {
    switch ($Unit) {
        "Seconds" { $SecondsCalculated = $Length }
        "Minutes" { $SecondsCalculated = $Length * 60 }
        "Hours" { $SecondsCalculated = $Length * 3600 }
        "Milliseconds" { $SecondsCalculated = $Length / 1000 }
    }
    Start-Sleep -Seconds $SecondsCalculated #Would love to use -Duration, but that's PS7+)
}
if (-not($Uninstall)) {
    Start-CustomSleep
    New-Item -Path "HKLM:\SOFTWARE\MHimken\" -Force | Out-Null 
    New-ItemProperty -Path "HKLM:\SOFTWARE\MHimken\" -Name "Win32AppWaited" -PropertyType DWORD -Value 1 | Out-Null
} else {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\MHimken\" -Name "Win32AppWaited" -Force | Out-Null
}
Exit 0