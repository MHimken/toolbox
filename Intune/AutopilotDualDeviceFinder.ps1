<#
.SYNOPSIS
This script will find devices in your tenant that exist more than twice.
.DESCRIPTION
If you want to analyse how many devices are hybrid _and_ entra joined and both are linked to an autopilot object in your tenant 
this script is for you. It will go by displayName. The runtime for a tenant with 20.000 devices is roughly 45 seconds. 
#>
$CertificateThumbprint = ""
$ClientID = ""
$TenantId = ""
$NumberOfDays = "-60" #Number of days that a machine has had to been active
if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId
}

function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $nextLink = ''
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}
$DateMinus60Days = Get-date (Get-Date).AddDays($NumberOfDays) -Format 'yyyy-MM-ddThh:mm:ssZ'
$AllDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$filter=(operatingSystem eq 'Windows') and (approximateLastSignInDateTime ge $DateMinus60Days)"
if ($AllDevices.'@odata.nextLink') {
    $AllDevices = Get-nextLinkData -OriginalObject $AllDevices
}
$DupeNames = ($AllDevices.value | Group-Object -Property displayName | Where-Object { $_.count -gt 1 }).Name
$ToBeDeleted = [System.Collections.ArrayList]::new()
foreach ($DupeName in $DupeNames) {
    $PhysicalIDs = ($AllDevices.Value | Where-Object { $_.displayname -eq $DupeName }).physicalIds
    if ($PhysicalIDs) {
        $AutopilotIDs = $PhysicalIDs | Select-String -Pattern '[ZTDID]:' -SimpleMatch
        if ($AutopilotIDs) {
            $AutopilotIDs = ($AutopilotIDs).line.Substring(8.36)
        }
    }
    if ($AutopilotIDs.Count -eq 2) {
        $EntraDevice = $AllDevices.value | Where-Object { $_.displayname -eq $DupeName -and $_.trustType -eq 'AzureAd' }
        $HybridDevice = $AllDevices.value | Where-Object { $_.displayname -eq $DupeName -and $_.trustType -eq 'ServerAd' }
        if ($HybridDevice.approximateLastSignInDateTime -ge $EntraDevice.approximateLastSignInDateTime) {
            $ToBeDeleteObject = [PSCustomObject]@{
                DeviceName             = $EntraDevice.displayName
                EntraDeviceID          = $EntraDevice.deviceId
                EntraDeviceLastSignIn  = $EntraDevice.approximateLastSignInDateTime
                HybridDeviceID         = $HybridDevice.deviceId
                HybridDeviceLastSignIn = $HybridDevice.approximateLastSignInDateTime
            }
            $ToBeDeleted.add($ToBeDeleteObject) | Out-Null
        }
    }
}
$ToBeDeleted