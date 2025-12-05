<#
.SYNOPSIS:
This runbook adds primary user information to the extension attributes of Entra ID devices.
.DESCRIPTION:
This script updates the extension attributes of devices in Entra ID with primary user information from Intune.
Required scopes: Device.ReadWrite.All, User.Read.All, and DeviceManagementManagedDevices.Read.All.
Set up a runbook in Azure Automation with the necessary permissions to run this script.
.PARAMETER NumberOfDays
The number of days to look back for the last Intune sync. If the device has not synced within this time frame, it will be excluded from the update.
.NOTES
    Version: 1.5
    Versionname: Add-PrimaryUserInfoToDevice-Runbook
    Intial creation date: 05.07.2025
    Last change date: 25.11.2025
    Latest changes: Refactored some code to improve performance and readability
    Author: Martin Himken
    Shoutouts:
    - Paul Contreras for the blog on how to set up the AA account with graph permissions
    https://thesysadminchannel.com/graph-api-using-a-managed-identity-in-an-automation-runbook/
    - Adam Gross for the original idea and the extension attributes script
    https://github.com/AdamGrossTX/MMSFLL2024DemoContent/blob/main/AutomationBuildingBlocks/ExtensionAttributes.ps1
    ToDo:
    * Finish Readme.md and add it to this script
#>

param(
    [int]$NumberOfDays = 365, # Number of Days to Look Back for Last Intune Sync
    [string[]]$AutopatchExcludeGroupID = @("3073bff3-1625-499f-8f73-6874c7bd0153") # Autopatch Exclude Group IDs (optional)
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
        "DeviceManagementManagedDevices.Read.All",
        "User.Read.All",
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
}
else{
    Write-Output "Microsoft Graph context found, using existing connection"
}
# Initialize some variables
$Script:BatchRequests = [System.Collections.ArrayList]::new()
$Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
$DateMinusNumberofDays = (Get-Date).AddDays(-$NumberOfDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
$TenantAPIToUse = "/beta" # Change to /v1.0 if you want to use the stable API version
 # Change to your Autopatch Exclude Group ID
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
        [switch]$SendNow,
        [switch]$Retry
    )
    if ($Retry) {
        Write-Output "Retrying batch request..."
        $JSONRequests = $Script:BatchRequestsAnalyze | ConvertTo-Json -Depth 10
        $Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
        $Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()
    }
    Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    if ($Script:BatchRequests.count -eq 20 -or $SendNow) {
        $BatchRequestBody = [PSCustomObject]@{requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10
        $ThreadedJob = [PSCustomObject]@{
            Name                 = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide    = @($JSONRequests, $TenantAPIToUse)
            ScriptBlockToProvide = {
                param($JSONRequests, $TenantAPIToUse)
                try {
                    $Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
                } catch {
                    $Results = $null
                }
                return $Results
            }
        }
        $Script:BatchRequestsQueue.Add($ThreadedJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
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
    $Script:IntuneDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/ManagedDevices/?`$select=id,model,notes,AzureADDeviceId,userId,deviceName&`$filter=(OperatingSystem eq 'Windows') and (lastSyncDateTime ge $DateMinusNumberofDays)" -ErrorAction Stop
    if ($Script:IntuneDevices.'@odata.nextLink') {
        Write-Output "Getting next link for Intune devices"
        $Script:IntuneDevices = Get-nextLinkData -OriginalObject $Script:IntuneDevices
    }
    $Script:EntraUsers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/?`$select=id,displayName,jobTitle,department,companyName,country,officeLocation&`$filter=(accountEnabled eq true) and (userType eq 'Member')" -ErrorAction Stop
    if ($Script:EntraUsers.'@odata.nextLink') {
        Write-Output "Getting next link for Entra users"
        $Script:EntraUsers = Get-nextLinkData -OriginalObject $Script:EntraUsers
    }
    $Script:EntraDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$expand=registeredOwners(`$select=id,name)&`$filter=(accountEnabled eq true) and (OperatingSystem eq 'Windows')&`$select=id,deviceId,DisplayName" -ErrorAction Stop
    if ($Script:EntraDevices.'@odata.nextLink') {
        Write-Output "Getting next link for Entra devices"
        $Script:EntraDevices = Get-nextLinkData -OriginalObject $Script:EntraDevices
    }
    if($AutopatchExcludeGroupID){
        foreach ($Group in $AutopatchExcludeGroupID){
            $Script:AutopatchExcludeMembers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups/$Group/members?`$select=id" -ErrorAction Stop
            Write-Output "Getting members of Autopatch Exclude Group $Group"
            $Script:AutopatchExcludeMembers = Get-nextLinkData -OriginalObject $Script:AutopatchExcludeMembers
        }
        Write-Output "Found $($Script:AutopatchExcludeMembers.value.count) members in Autopatch Exclude Groups."
    }
}

Write-Output "Processing Intune devices and Entra devices to add primary user information to extension attributes."
Initialize-Script
Write-Output "Found $($Script:IntuneDevices.value.count) Intune devices, $($Script:EntraUsers.value.count) Entra users, and $($Script:EntraDevices.value.count) Entra devices."
$counter = 0
#Prepare a merged object to use for the batch request
$deviceLookup = @{}
$userLookup = @{}
$AutopatchExcludeLookup = @{}
foreach ($EntraDevice in $Script:EntraDevices.Value) {
    $deviceLookup[$EntraDevice.DeviceID.ToString()] = $EntraDevice
}
foreach ($EntraUser in $Script:EntraUsers.value) {
    $userLookup[$EntraUser.id.ToString()] = $EntraUser
}
foreach ($AutoPatchExcludeMember in $Script:AutopatchExcludeMembers.value) {
    $AutopatchExcludeLookup[$AutoPatchExcludeMember.id.ToString()] = $AutoPatchExcludeMember
}
$Output = @{}
foreach ($IntuneDevice in $Script:IntuneDevices.Value) {
    if (-not $deviceLookup.Contains($IntuneDevice.AzureADDeviceId.ToString())) {
        continue
    } else {
        if ($AutopatchExcludeGroupID) {
            $IsInAutopatchExcludeGroup = $AutopatchExcludeLookup.Contains($IntuneDevice.azureADDeviceId.ToString())
            if ($IsInAutopatchExcludeGroup) {
                $AutopatchTag = "AutopatchExcluded"
            }
        }
        $EntraUser = $userLookup[$IntuneDevice.userId.ToString()]
        $EntraDevice = $deviceLookup[$IntuneDevice.AzureADDeviceId.ToString()]
        $Body = @{
            extensionAttributes = 
            @{
                extensionAttribute1  = $EntraUser.country
                extensionAttribute2  = $EntraUser.officeLocation
                extensionAttribute3  = $EntraUser.department
                extensionAttribute4  = $EntraUser.jobTitle
                extensionAttribute5  = $EntraUser.companyName
                extensionAttribute6  = $IntuneDevice.model
                extensionAttribute7  = $IntuneDevice.notes
                extensionAttribute10 = $AutopatchTag
            }
        }
        $Message = "Updated device $($EntraDevice.DisplayName) $($EntraDevice.id) with user $($EntraUser.displayName)"
        $Output[$EntraDevice.id] = $Message
        $params = @{
            Method  = "PATCH"
            URL     = "/devices/$($EntraDevice.id)"
            Body    = $Body
            Headers = @{
                "Content-Type" = "application/json"
            }
        }    
        if ($Script:IntuneDevices.value.count - $counter -gt 1) {
            Invoke-BatchRequest @params
        } else {
            Invoke-BatchRequest -SendNow @params
        }
        $counter++
    }
}
$JobResult = $Script:BatchRequestsQueue | ForEach-Object -ThrottleLimit 20 -AsJob -Parallel {
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$($_.ArgumentToProvide[1])/`$batch" -Body $_.ArgumentToProvide[0] -ContentType 'application/json' -ErrorAction Stop
}
# Wait for all jobs to complete
while ((Get-Job | Where-Object { $_.name -match "Job" }).state -eq "Running") {
    Start-Sleep -Seconds 1
}
$AnalyzeJobs = Get-Job | Where-Object { $_.name -match "Job" }
$Script:BatchResults = @{}
foreach ($Result in $AnalyzeJobs) {
    $Script:BatchResults[$Result.Id] = Receive-Job -Job $Result -ErrorAction SilentlyContinue
    Remove-Job -Job $Result -Force
    $FailCounter = 0
    foreach ($JobResult in $Script:BatchResults[$Result.Id].responses) {
        if ($JobResult.status -ne 204) {
            Write-Output "Failed to update device $($JobResult.id) - Status: $($JobResult.status), Error: $($JobResult.body)"
            $FailCounter++
        }
    }
    Write-Output "Batch request $($Result.Id) completed with $($Script:BatchResults[$Result.Id].responses.count) responses."
    Write-Output "Failed to update $FailCounter devices in batch request $($Result.Id)."
}
$Output.Values | ForEach-Object { Write-Output $_ }