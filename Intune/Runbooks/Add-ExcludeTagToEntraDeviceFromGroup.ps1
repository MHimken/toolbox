<#
.SYNOPSIS:
This runbook adds one extension attribute to Entra ID devices based on their membership in specified groups.
.DESCRIPTION:
This script updates the extension attributes of devices in Entra ID with primary user information from Intune.
Required scopes: Device.ReadWrite.All, User.Read.All, and DeviceManagementManagedDevices.Read.All.
Set up a runbook in Azure Automation with the necessary permissions to run this script.
.PARAMETER NumberOfDays
The number of days to look back for the last Intune sync. If the device has not synced within this time frame, it will be excluded from the update.
.NOTES
    Version: 1.0
    Versionname: Add-ExcludeTagToEntraDeviceFromGroup-Runbook
    Intial creation date: 25.11.2025
    Last change date: 05.12.2025
    Latest changes: Initial Version
    Author: Martin Himken
    ToDo:
    * Finish Readme.md and add it to this script
#>

param(
    [string[]]$AutopatchExcludeGroupID = @("b5e9d446-7d95-4698-8399-03bb75cce6e6"), # Autopatch Exclude Group IDs (optional)
    [string]$TenantAPIToUse = "/beta" # API version to use (default: /beta)
)
# Stop editing here
# Connect to Microsoft Graph using the Azure Automation Run As Account
if (-not(Get-MGContext)) {
    Connect-AzAccount -Identity
    $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -AsSecureString
    if (-not($token)) {
        Write-Output "No access token for Microsoft Graph with Azure Run As Account"
        Exit 1
    }
    try {
        Write-Output "No Microsoft Graph context found, connecting with Azure Run As Account"
        Connect-MgGraph -AccessToken ($token.Token) -NoWelcome
    } catch {
        Write-Output "No connection to Microsoft Graph with Azure Run As Account $($_.Exception.Message)"
        Exit 1
    }
    $requiredScopes = @(
        "Device.ReadWrite.All",
        "GroupMember.Read.All",
        "Group.Read.All"
    )
    $context = Get-MgContext
    $missingScopes = @()
    foreach ($scope in $requiredScopes) {
        if (-not ($context.Scopes -contains $scope)) {
            $missingScopes += $scope
        }
    }
    if ($missingScopes.Count -gt 0) {
        Write-Output "Missing required Graph API permissions: $($missingScopes -join ', ')"
        Exit 1
    }
    Write-Output "Connected to Microsoft Graph with Azure Run As Account"
} else {
    Write-Output "Microsoft Graph context found, using existing connection"
}
function Add-BatchRequestObjectToQueue {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body
    )
    $ID = $Script:BatchRequests.count
    $BatchObject = [PSCustomObject]@{
        id      = $ID
        method  = $Method
        URL     = $URL
        headers = $Headers
        body    = $Body
    }
    $Script:BatchRequests.add($BatchObject) | Out-Null
}
function Invoke-BatchRequest {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body,
        [switch]$Finalize
    )
    if ($Method -and $URL) {
        Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    }
    if ($Script:BatchRequests.count -eq 20 -or $Finalize) {
        $BatchRequestBody = [PSCustomObject]@{ requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10
        #$Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
        $PrepareJob = [PSCustomObject]@{
            ID                = $Script:BatchRequestsQueue.Count
            Name              = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide = @($JSONRequests)
        }
        $Script:BatchRequestsQueue.Add($PrepareJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return #$Results
}
function Get-nextLinkData {
    <#
    .SYNOPSIS
    This function retrieves all pages of data from a Microsoft Graph API request that supports pagination.
    .DESCRIPTION
    The function takes an original object that contains a '@odata.nextLink' property and retrieves all pages of data until there are no more pages left.
    #>
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $Results.'@odata.count' += $Request.'@odata.count'
        $nextLink = $Request.'@odata.nextLink'
    }
    $Results.'@odata.nextLink' = $null
    return $Results
}
function Initialize-Script {
    $Script:EntraDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/devices/?`$expand=registeredOwners(`$select=id,name)&`$filter=(OperatingSystem eq 'Windows')&`$select=id,deviceId,DisplayName,extensionAttributes" -ErrorAction Stop
    if ($Script:EntraDevices.'@odata.nextLink') {
        Write-Output "Getting next link for Entra devices"
        $Script:EntraDevices = Get-nextLinkData -OriginalObject $Script:EntraDevices
    }
    Write-Output "Found $($Script:EntraDevices.value.count) Entra devices."
    if ($AutopatchExcludeGroupID) {
        foreach ($Group in $AutopatchExcludeGroupID) {
            $Script:AutopatchExcludeMembers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/groups/$Group/members?`$select=id" -ErrorAction Stop
            Write-Output "Getting members of Autopatch Exclude Group $Group"
            $Script:AutopatchExcludeMembers = Get-nextLinkData -OriginalObject $Script:AutopatchExcludeMembers
        }
        Write-Output "Found $($Script:AutopatchExcludeMembers.value.count) members in Autopatch Exclude Groups."
    }
    # Find all devices with extensionAttribute10 set to AutopatchExcluded
    $Script:ExtensionAttribute10Set = $Script:EntraDevices.Value | Where-Object { $_.extensionAttributes.extensionAttribute10 -eq "AutopatchExcluded" }
    Write-Output "Found $($Script:ExtensionAttribute10Set.count) devices with extensionAttribute10 set to AutopatchExcluded."
    $Script:ExtensionAttribute10SetLookup = @{}
    foreach ($Device in $Script:ExtensionAttribute10Set) {
        $Script:ExtensionAttribute10SetLookup[$Device.id.ToString()] = $Device
    }
    $Script:deviceLookup = @{}
    foreach ($EntraDevice in $Script:EntraDevices.Value) {
        $Script:deviceLookup[$EntraDevice.id.ToString()] = $EntraDevice
    }
    $Script:AutopatchExcludeLookup = @{}
    foreach ($Device in $Script:AutopatchExcludeMembers.value) {
        $Script:AutopatchExcludeLookup[$Device.id.ToString()] = $Device
    }
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
}
function Initialize-Cleanup {
    $counter = 0
    foreach ($EntraDevice in $Script:ExtensionAttribute10Set) {
        $IsMember = $Script:AutopatchExcludeLookup.ContainsKey($EntraDevice.id.ToString())
        if ($IsMember) {
            continue
        } else {
            Write-Output "Device $($EntraDevice.DisplayName) $($EntraDevice.id) is not a member of Autopatch Exclude Groups, removing tag."
            $Body = @{
                extensionAttributes = @{
                    extensionAttribute1  = $EntraDevice.extensionAttributes.extensionAttribute1
                    extensionAttribute2  = $EntraDevice.extensionAttributes.extensionAttribute2
                    extensionAttribute3  = $EntraDevice.extensionAttributes.extensionAttribute3
                    extensionAttribute4  = $EntraDevice.extensionAttributes.extensionAttribute4
                    extensionAttribute5  = $EntraDevice.extensionAttributes.extensionAttribute5
                    extensionAttribute6  = $EntraDevice.extensionAttributes.extensionAttribute6
                    extensionAttribute7  = $EntraDevice.extensionAttributes.extensionAttribute7
                    extensionAttribute8  = $EntraDevice.extensionAttributes.extensionAttribute8
                    extensionAttribute9  = $EntraDevice.extensionAttributes.extensionAttribute9
                    extensionAttribute10 = $null
                    extensionAttribute11 = $EntraDevice.extensionAttributes.extensionAttribute11
                    extensionAttribute12 = $EntraDevice.extensionAttributes.extensionAttribute12
                    extensionAttribute13 = $EntraDevice.extensionAttributes.extensionAttribute13
                    extensionAttribute14 = $EntraDevice.extensionAttributes.extensionAttribute14
                    extensionAttribute15 = $EntraDevice.extensionAttributes.extensionAttribute15
                }
            }
            Write-Output "Removed Autopatch Exclude Tag from device $($EntraDevice.DisplayName) $($EntraDevice.id)."
            $params = @{
                Method  = "PATCH"
                URL     = "/devices/$($EntraDevice.id)"
                Body    = $Body
                Headers = @{
                    "Content-Type" = "application/json"
                }
            }    
            if ($Script:ExtensionAttribute10Set.value.count - $counter -gt 1) {
                Invoke-BatchRequest @params
            } else {
                Invoke-BatchRequest -SendNow @params
            }
        }
        $counter++
    }
}
function Initialize-SettingExtensionAttributes {
    $counter = 0
    foreach ($Device in $Script:AutopatchExcludeMembers.value) {
        if ($Script:ExtensionAttribute10SetLookup.ContainsKey($Device.id.ToString())) {
            Write-Output "Device $($Device.id) already has Autopatch Exclude Tag, skipping."
            continue
        }
        $EntraDevice = $Script:deviceLookup[$Device.id.ToString()]
        if (-not $EntraDevice) {
            Write-Output "Device $($Device.id) not found in Entra devices, skipping."
            continue
        } else {
            $Body = @{
                extensionAttributes = @{
                    extensionAttribute1  = $EntraDevice.extensionAttributes.extensionAttribute1
                    extensionAttribute2  = $EntraDevice.extensionAttributes.extensionAttribute2
                    extensionAttribute3  = $EntraDevice.extensionAttributes.extensionAttribute3
                    extensionAttribute4  = $EntraDevice.extensionAttributes.extensionAttribute4
                    extensionAttribute5  = $EntraDevice.extensionAttributes.extensionAttribute5
                    extensionAttribute6  = $EntraDevice.extensionAttributes.extensionAttribute6
                    extensionAttribute7  = $EntraDevice.extensionAttributes.extensionAttribute7
                    extensionAttribute8  = $EntraDevice.extensionAttributes.extensionAttribute8
                    extensionAttribute9  = $EntraDevice.extensionAttributes.extensionAttribute9
                    extensionAttribute10 = "AutopatchExcluded"
                    extensionAttribute11 = $EntraDevice.extensionAttributes.extensionAttribute11
                    extensionAttribute12 = $EntraDevice.extensionAttributes.extensionAttribute12
                    extensionAttribute13 = $EntraDevice.extensionAttributes.extensionAttribute13
                    extensionAttribute14 = $EntraDevice.extensionAttributes.extensionAttribute14
                    extensionAttribute15 = $EntraDevice.extensionAttributes.extensionAttribute15
                }
            }
            $params = @{
                Method  = "PATCH"
                URL     = "/devices/$($EntraDevice.id)"
                Body    = $Body
                Headers = @{
                    "Content-Type" = "application/json"
                }
            }    
            if ($Script:AutopatchExcludeMembers.value.count - $counter -gt 1) {
                Invoke-BatchRequest @params
            } else {
                Invoke-BatchRequest -Finalize @params
            }
        }
        $counter++
    }
}
Write-Output "Processing Intune devices and Entra devices to add primary user information to extension attributes."
Initialize-Script
Initialize-Cleanup
Initialize-SettingExtensionAttributes

if ($Script:BatchRequestsQueue) {
    $JobResult = $Script:BatchRequestsQueue | ForEach-Object -ThrottleLimit 20 -AsJob -Parallel {
        $TenantAPIToUse = $using:TenantAPIToUse
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $_.ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
    }
}
else{
    Write-Output "No batch requests to process."
    Exit 0
}

# Wait for all jobs to complete
while ((Get-Job | Where-Object { $_.name -match "Job" }).state -eq "Running") {
    Start-Sleep -Seconds 1
}
$AnalyzeJobs = Get-Job | Where-Object { $_.name -match "Job" }
$ChildJobs = $AnalyzeJobs.ChildJobs
$Script:BatchResults = @{}
foreach ($Result in $ChildJobs) {
    $FailCounter = 0
    $MatchResultIDToBatchID = $Result.Id - 2
    if ($Result.Error) {
        Write-Output "Error in batch request job $($Result.Id): $($Result.Error)"
        $FailCounter++
        continue
    }
    $Script:BatchResults[$MatchResultIDToBatchID] = Receive-Job -Job $Result -ErrorAction SilentlyContinue
    foreach ($BatchJobResult in $Script:BatchResults[$MatchResultIDToBatchID].responses) {
        if ($BatchJobResult.status -ne 204) {
            Write-Output "Failed to update device $($BatchJobResult.id) - Status: $($BatchJobResult.status), Error: $($BatchJobResult.body)"
            $FailCounter++
        }
    }
    Write-Output "Batch request $($MatchResultIDToBatchID) completed with $($Script:BatchResults[$MatchResultIDToBatchID].responses.count) responses."
    if ($FailCounter -gt 0) {
        Write-Output "$FailCounter requests failed in batch request $($MatchResultIDToBatchID)."
    }
}
Get-Job | Remove-Job -Force