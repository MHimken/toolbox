<#
.SYNOPSIS
    Remediate if the WebClient service is anything but disabled
.DESCRIPTION
    This script will disable the WebClient service.
.NOTES
    Author: Martin Himken (SVA)
    Date Created: 2025-09-25
    Version 1.0: Initial version

    Run this script using the logged-on credentials: No
    Enforce script signature check: No
    Run script in 64-bit PowerShell: Yes
#>
if(Get-Service -Name "WebClient" -ErrorAction SilentlyContinue) {
    $service = Get-Service -Name "WebClient"
    if($service.Status -ne 'Stopped') {
        Stop-Service -Name "WebClient" -Force
    }
}
$servicename = "WebClient"
$serviceOption = 'StartupType'
$serviceOptionValue = 'Disabled'
$SetServiceSplat = @{
	Name = $ServiceName
	$serviceOption = $serviceOptionValue
}

Set-Service @SetServiceSplat
Write-Output "Remediation completed successfully."
exit 0