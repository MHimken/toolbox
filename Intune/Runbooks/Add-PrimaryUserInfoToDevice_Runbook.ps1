<#
.SYNOPSIS:
This runbook adds primary user information to the extension attributes of Entra ID devices.
.DESCRIPTION:
This script updates the extension attributes of devices in Entra ID with primary user information from Intune.
Required scopes: Device.ReadWrite.All, User.Read.All, and DeviceManagementManagedDevices.Read.All.
Set up a runbook in Azure Automation with the necessary permissions to run this script.
.NOTES
    Version: 1.0
    Versionname: Add-PrimaryUserInfoToDevice-Runbook
    Intial creation date: 05.07.2025
    Last change date: 05.08.2025
    Latest changes: Initial Version
    Author: Martin Himken
    Shoutouts: 
    - Adam Gross for the original idea and the extension attributes script
    https://github.com/AdamGrossTX/MMSFLL2024DemoContent/blob/main/AutomationBuildingBlocks/ExtensionAttributes.ps1
    ToDo: 
    * Make Invoke-MgGraphRequest into a batch operation to update multiple devices at once - this should increase speed
    * Add throttling to the script to avoid hitting the API limits
    * Finish Readme.md and add it to this script
#>
#You can change these values to match your environment
$NumberOfDays = 365 # Number of Days to Look Back for Last Intune Sync

# Stop editing here
Connect-AzAccount -Identity
$token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
if (-not($token)) {
    Write-Output "No access token for Microsoft Graph with Azure Run As Account"
    Exit 1
}   
try {
    if (-not(Get-MGContext)) {
        Write-Output "No Microsoft Graph context found, connecting with Azure Run As Account"
        Connect-MgGraph -AccessToken ($token.Token | ConvertTo-SecureString -AsPlainText -Force) -NoWelcome
    }
} catch {
    Write-Output "No connection to Microsoft Graph with Azure Run As Account $($_.Exception.Message)"
    Exit 1
}
Write-Output "Connected to Microsoft Graph with Azure Run As Account"
# Initialize some variables
$Script:BatchRequests = [System.Collections.ArrayList]::new()
$Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
$DateMinusNumberofDays = (Get-Date).AddDays(-$NumberOfDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
$TenantAPIToUse = "/beta" # Change to /v1.0 if you want to use the stable API version
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
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop | Out-Null
        $Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()
    }
    Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    if ($Script:BatchRequests.count -eq 20 -or $SendNow) {
        $BatchRequestBody = [PSCustomObject]@{requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10
        $ThreadedJob = [PSCustomObject]@{
            Name                 = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide    = @($JSONRequests, $TenantAPIToUse)
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
$IntuneDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/ManagedDevices/?`$select=id,model,notes,AzureADDeviceId,userId,deviceName&`$filter=(OperatingSystem eq 'Windows') and (lastSyncDateTime ge $DateMinusNumberofDays)" -ErrorAction Stop
if ($IntuneDevices.'@odata.nextLink') {
    Write-Output "Getting next link for Intune devices"
    $IntuneDevices = Get-nextLinkData -OriginalObject $IntuneDevices
}
$EntraUsers = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/?`$select=id,displayName,jobTitle,department,companyName,country,officeLocation&`$filter=(accountEnabled eq true) and (userType eq 'Member')" -ErrorAction Stop
if ($EntraUsers.'@odata.nextLink') {
    Write-Output "Getting next link for Entra users"
    $EntraUsers = Get-nextLinkData -OriginalObject $EntraUsers
}
$EntraDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/devices/?`$expand=registeredOwners(`$select=id,name)&`$filter=(accountEnabled eq true) and (OperatingSystem eq 'Windows')&`$select=id,deviceId,DisplayName" -ErrorAction Stop
if ($EntraDevices.'@odata.nextLink') {
    Write-Output "Getting next link for Entra devices"
    $EntraDevices = Get-nextLinkData -OriginalObject $EntraDevices
}
Write-Output "Processing Intune devices and Entra devices to add primary user information to extension attributes."
Write-Output "Found $($IntuneDevices.value.count) Intune devices, $($EntraUsers.value.count) Entra users, and $($EntraDevices.value.count) Entra devices."
$counter = 0
#Prepare a merged object to use for the batch request
$deviceLookup = @{}
$userLookup = @{}
foreach ($EntraDevice in $EntraDevices.Value) {
    $deviceLookup[$EntraDevice.DeviceID.ToString()] = $EntraDevice
}
foreach ($EntraUser in $EntraUsers.value) {
    $userLookup[$EntraUser.id.ToString()] = $EntraUser
}
$Output = @{}
foreach ($IntuneDevice in $IntuneDevices.Value) {
    if (-not $deviceLookup.Contains($IntuneDevice.AzureADDeviceId.ToString())) {
        continue
    } else {
        $EntraUser = $userLookup[$IntuneDevice.userId.ToString()]
        $EntraDevice = $deviceLookup[$IntuneDevice.AzureADDeviceId.ToString()]
        $Body = @{
            extensionAttributes = 
            @{
                extensionAttribute1 = $EntraUser.country
                extensionAttribute2 = $EntraUser.officeLocation
                extensionAttribute3 = $EntraUser.department
                extensionAttribute4 = $EntraUser.jobTitle
                extensionAttribute5 = $EntraUser.companyName
                extensionAttribute6 = $IntuneDevice.model
                extensionAttribute7 = $IntuneDevice.notes
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
        if ($IntuneDevices.value.count - $counter -gt 1) {
            Invoke-BatchRequest @params
        } else {
            Invoke-BatchRequest -SendNow @params
        }
        $counter++
    }
}
#Multi-Threading does not work in the Azure Automation Runbook environment, so we use foreach -parallel instead
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