#Requires -Module Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
THIS SCRIPT IS NOT DONE!
RUNBOOK WILL RUN OUT OF MEMORY FOR MORE THAN A COUPLE THOUSAND USERS! Test this before you do something with it.
IT'S ALREADY ON THE TODO!
.SYNOPSIS
    Repair Primary User assignment for Intune managed devices based on sign-in data.
.DESCRIPTION
    This script connects to Microsoft Graph using the Azure Automation Run As Account, retrieves Intune managed devices and their logged-on users, analyzes sign-in data to determine the most appropriate primary user for each device, and prepares batch requests to update the primary user assignments accordingly.
.PARAMETER TenantAPIToUse
    Specifies the Microsoft Graph API version to use (default is "beta").
.PARAMETER ThrottleLimit
    Specifies the throttle limit for parallel processing (default is 50 parallel jobs).
.NOTES
    Version: 1.0
    Versionname: Repair-PrimaryUserRunbook.ps1
    Intial creation date: 07.12.2025
    Last change date: 20.03.2026
    Latest changes: Initial Version
    Author: Martin Himken
    ToDos:
        - Cleanup code
        - Split requesting sign-in logs into smaller chunks of a handful of days to avoid memory issues in large environments
#>
param(
    [string]$TenantAPIToUse = "beta",
    [int]$ThrottleLimit = 5,
    [int]$DaysToLookBack = 28 # make this divisible by 7 for better performance when retrieving sign-in data in weekly chunks
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
        "AuditLog.Read.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "User.Read.All"
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
        $PrepareJob = [PSCustomObject]@{
            ID                = $Script:BatchRequestsQueue.Count
            Name              = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide = @($JSONRequests)
        }
        $Script:BatchRequestsQueue.Add($PrepareJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return
}
function Submit-BatchRequests {
    <#
    .SYNOPSIS
        Processes the batch requests in the queue.
    #>
    $Script:BatchRequestsQueue | ForEach-Object -AsJob -ThrottleLimit $ThrottleLimit -Parallel {
        $TenantAPIToUse = if (-not($TenantAPIToUse)) { 'beta' }
        $URI = "https://graph.microsoft.com/$TenantAPIToUse/`$batch"
        Invoke-MgGraphRequest -Method POST -Uri $URI -Body $_.ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
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
        Write-Output "Retrieving next page of data from $nextLink"
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $Results.'@odata.count' += $Request.'@odata.count'
        $nextLink = $Request.'@odata.nextLink'
        Start-Sleep -Milliseconds 500 # Add a short delay to avoid hitting throttling limits
    }
    $Results.'@odata.nextLink' = $null
    return $Results
}
function Initialize-Script {
    $Script:LogPrefix = "RepairPrimaryUser"
    Write-Output "Retrieving Entra users and Intune managed devices..."
    $Script:EntraUsers = Invoke-MGGraphRequest -Method GET -Uri "https://graph.microsoft.com/$TenantAPIToUse/users?`$select=id,userPrincipalName,displayName"
    if ($Script:EntraUsers.'@odata.nextLink') {
        Write-Output "Getting next link for Entra users"
        $Script:EntraUsers = Get-nextLinkData -OriginalObject $Script:EntraUsers
    }
    
    $Script:IntuneDevices = Invoke-MGGraphRequest -Method GET -Uri "https://graph.microsoft.com/$TenantAPIToUse/deviceManagement/managedDevices?`$filter=(OperatingSystem eq 'Windows') and (managedDeviceOwnerType eq 'Company')&`$select=id,azureADDeviceId,deviceName,userId,usersLoggedOn"
    if ($Script:IntuneDevices.'@odata.nextLink') {
        Write-Output "Getting next link for Intune devices"
        $Script:IntuneDevices = Get-nextLinkData -OriginalObject $Script:IntuneDevices
    }
    $Script:EntraUsersLookup = @{}
    foreach ($User in $Script:EntraUsers.value) {
        $Script:EntraUsersLookup[$User.id.ToString()] = $User
    }
    $Script:IntuneDevicesLookup = @{}
    foreach ($Device in $Script:IntuneDevices.value) {
        $Script:IntuneDevicesLookup[$Device.id.ToString()] = $Device
    }
    if ((Get-MgContext).AuthType -ne "accessToken") {
        $Script:Output = [System.Collections.ArrayList]::new()
        $Script:Runbook = $true
    }
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
}
function Get-SignInData {
    <#
    .SYNOPSIS
        Retrieves sign-in data from Microsoft Graph API for the specified time range and application filter.
    .DESCRIPTION
        This function retrieves sign-in data for Windows Sign In events. Due to resource constraints in Azure Automation, the function can be configured to retrieve a limited number of pages of sign-in data. The retrieved data is then processed to create a lookup for device sign-ins and user activity.
    .PARAMETER NumberOfPagesToRetrieve
        Specifies the number of pages of sign-in data to retrieve. Each page contains a set number of records as defined by the Graph API. Setting this parameter can help manage memory usage in environments with a large number of sign-in events.
    .NOTES
    Todos:
        - Test
    #>

    param(
        [int]$NumberOfDaysToLookBack = 28
    )
    $Script:SignInDataLookup = @{}
    $Script:DeviceTransformLookup = @{}
    if (-not($Script:NumberOfRunsRequired) -and $NumberOfDaysToLookBack -gt 4) {
        $Script:NumberOfRunsRequired = $NumberOfDaysToLookBack / 4
        Write-output "Number of runs required to retrieve sign-in data in 7-day chunks: $($Script:NumberOfRunsRequired)"
    }
    for ($i = 0; $i -lt $Script:NumberOfRunsRequired; $i++) {
        $DateCutoff = (Get-Date).AddDays( - ($DaysToLookBack - ($i * 7))).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $DateCurrent = (Get-Date).AddDays( - ($DaysToLookBack - (($i + 1) * 7))).ToString("yyyy-MM-ddTHH:mm:ssZ")
        Write-Output "Retrieving sign-in data from $DateCutoff to $DateCurrent"
        $Script:SignInData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/auditLogs/signIns/?`$filter=createdDateTime ge $DateCutoff and createdDateTime le $DateCurrent and appDisplayName eq 'Windows Sign In'&?select=userDisplayName,userId,deviceDetail"
        # Show amount of pages estimated to retrieve based on '@odata.count' and amount of records per page
        $RecordsPerPage = 100 # Graph API default page size
        $TotalRecords = $Script:SignInData.'@odata.count'
        $EstimatedPages = [math]::Ceiling($TotalRecords / $RecordsPerPage)
        Write-Output "Estimated pages to retrieve: $EstimatedPages"
        if ($Script:SignInData.'@odata.nextLink') {
            Write-Output "Getting next link for Sign-In data - this will take a while. Run $($i + 1) of $($Script:NumberOfRunsRequired)"
            $Script:SignInData = Get-nextLinkData -OriginalObject $Script:SignInData
        }
        $Script:SignInDataGrouped = $Script:SignInData.value | Group-Object -Property userId -AsHashTable
        foreach ($SignIn in $Script:SignInData.value) {
            $DeviceID = $SignIn.deviceDetail.deviceId
            $UserDisplayName = $SignIn.userDisplayName
            if (-not $Script:DeviceTransformLookup.ContainsKey($DeviceID)) {
                $CustomObject = [PSCustomObject]@{
                    UserName = $UserDisplayName
                    userId   = $SignIn.userId
                    count    = 1
                }
                $Script:DeviceTransformLookup[$DeviceID] = @($CustomObject)
            } else {
                if ($Script:DeviceTransformLookup[$DeviceID] | Where-Object { $_.userId -eq $SignIn.userId }) {
                    $ExistingObject = $Script:DeviceTransformLookup[$DeviceID] | Where-Object { $_.userId -eq $SignIn.userId }
                    $ExistingObject.count++
                    continue
                }
                $CustomObject = [PSCustomObject]@{
                    UserName = $UserDisplayName
                    userId   = $SignIn.userId
                    count    = 1
                }
                $Script:DeviceTransformLookup[$DeviceID] += $CustomObject
            }
        }
        # Sort DeviceTransformLookup so that the user with the most sign-ins for each device is first in the list
        $Script:DeviceTransformLookup[$DeviceID] = $Script:DeviceTransformLookup[$DeviceID] | Sort-Object -Property count -Descending
        Clear-Variable -Name SignInData, SignInDataGrouped -Force
    }
}
function Find-PrimaryUser {
    $DevicesWithUsers = $Script:IntuneDevices.value | Where-Object { $_.usersLoggedOn.Count -gt 0 }
    foreach ($Device in $DevicesWithUsers) {
        if ($Script:DeviceTransformLookup[$Device.azureADDeviceId]) {
            $TopUser = $Script:DeviceTransformLookup[$Device.azureADDeviceId][0]
            $SecondUser = if ($Script:DeviceTransformLookup[$Device.azureADDeviceId].Count -gt 1) { $Script:DeviceTransformLookup[$Device.azureADDeviceId][1] } else { $null }
            if ($SecondUser -and $TopUser.count -eq $SecondUser.count) {
                #Select a user at random if there is a tie in sign-in counts
                $RandomIndex = Get-Random -Minimum 0 -Maximum 2
                $TopUser = $Script:DeviceTransformLookup[$Device.azureADDeviceId][$RandomIndex] 
            }
        } else {
            #Write-Output "No sign-in data for device $($Device.deviceName) ($($Device.id)) - skipping primary user calculation"
            continue
        }
        $CurrentPrimaryUser = $Device.userId
        $CalculatedPrimaryUser = $TopUser.userId
        if ($CurrentPrimaryUser -ne $CalculatedPrimaryUser) {
            $Method = "POST"
            $Headers = @{
                'Content-Type' = 'application/json'
            }
            $Body = @{
                '@odata.id' = "https://graph.microsoft.com/beta/users/$CalculatedPrimaryUser/"
            }
            if ($Script:Runbook) {
                Write-Output "Device $($Device.deviceName) - Current Primary User: $($Script:EntraUsersLookup[$CurrentPrimaryUser].displayName) ($($CurrentPrimaryUser)) -> New Primary User: $($Script:EntraUsersLookup[$CalculatedPrimaryUser].displayName) ($($CalculatedPrimaryUser))"
            } else {
                $OutputObject = [PSCustomObject]@{
                    DeviceName                    = $Device.deviceName
                    DeviceID                      = $Device.id
                    CurrentPrimaryUser            = $CurrentPrimaryUser
                    UserNameCurrentPrimaryUser    = $Script:EntraUsersLookup[$CurrentPrimaryUser].displayName
                    CalculatedPrimaryUser         = $CalculatedPrimaryUser
                    UserNameCalculatedPrimaryUser = $Script:EntraUsersLookup[$CalculatedPrimaryUser].displayName
                }
                $Script:Output.Add($OutputObject) | Out-Null
            }
            Invoke-BatchRequest -Method $Method -URL "/deviceManagement/managedDevices/$($Device.id)/users/`$ref" -Headers $Headers -Body $Body
            
        } else {
            #Write-Output "Device $($Device.deviceName) - Current Primary User is correct ($($Script:EntraUsersLookup[$CurrentPrimaryUser].displayName) ($($CurrentPrimaryUser))) - no update needed"
        }   
    }
    Invoke-BatchRequest -Finalize
}
# Start coding!
Initialize-Script
Get-SignInData -NumberOfDaysToLookBack $DaysToLookBack
Find-PrimaryUser

Write-Output "Prepared $($Script:BatchRequestsQueue.Count) batches (20 each) requests to update primary users."
Submit-BatchRequests
$JobStatus = (Get-Job -IncludeChildJob -State Running).count -gt 0
while ($JobStatus) {
    Start-Sleep -Seconds 60
    $JobStatus = (Get-Job -IncludeChildJob -State Running).count -gt 0
}
$JobOutputs = (Get-Job -IncludeChildJob).output
$counter = 0
foreach ($Result in $JobOutputs) {
    Write-Output "Device $($Result.DeviceName) - Current Primary User: $($Script:EntraUsersLookup[$Result.CurrentPrimaryUser].displayName) ($($Result.CurrentPrimaryUser)) -> New Primary User: $($Script:EntraUsersLookup[$Result.CalculatedPrimaryUser].displayName) ($($Result.CalculatedPrimaryUser))"
    $Method = "POST"
    $URL = "/deviceManagement/managedDevices/$($Result.DeviceID)/users/`$ref"
    $Body = @{
        '@odata.id' = "https://graph.microsoft.com/beta/users/$($Result.CalculatedPrimaryUser)"
    }
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers -Body $Body
    $counter++
    if (($JobOutputs.count - $counter) -eq 0) {
        Invoke-BatchRequest -Finalize
    }
}
Get-Job | Remove-Job -Force # Uncomment to clean up jobs - we might want to keep RAM costs low in Azure Automation