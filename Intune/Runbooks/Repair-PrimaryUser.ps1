# THIS SCRIPT IS NOT DONE!
#Requires -Module Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
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
    Last change date: 13.01.2026
    Latest changes: Initial Version
    Author: Martin Himken
#>
param(
    [string]$TenantAPIToUse = "beta",
    [int]$ThrottleLimit = 40
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
        Invoke-MgGraphRequest -Method POST -Uri $URI -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
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
    
    $DateCutoff = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ") #30 is the maximum that makes sense for primary user calculation, plus the Graph API might time out with longer timeframes
    $DateCurrent = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") 
    $Script:SignInData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/auditLogs/signIns/?`$filter=createdDateTime ge $DateCutoff and createdDateTime le $DateCurrent and appDisplayName eq 'Windows Sign In'&?select=userDisplayName,userId,deviceDetail"
    if ($Script:SignInData.'@odata.nextLink') {
        Write-Output "Getting next link for Sign-In data - this will take a while..."
        $Script:SignInData = Get-nextLinkData -OriginalObject $Script:SignInData
    }
    $Script:SignInDataLookup = @{}
    $Script:SignInDataGrouped = $Script:SignInData.value | group-object -Property userId -AsHashTable
    $Script:DeviceTransformLookup = @{}
    foreach ($SignIn in $Script:SignInData.value) {
        $DeviceIDs = $SignIn.deviceDetail.deviceId
        $UserDisplayName = $SignIn.userDisplayName
        foreach ($DeviceID in $DeviceIDs) {
            $ExistingCustomObjects = [System.Collections.ArrayList]::new()
            if (-not $Script:DeviceTransformLookup.ContainsKey($DeviceID)) {
                $Script:DeviceTransformLookup[$DeviceID] = @()
                $Counter = 1
            } else {
                if ($Script:DeviceTransformLookup[$DeviceID] | Where-Object { $_.userId -eq $SignIn.userId }) {
                    $Counter = ($Script:DeviceTransformLookup[$DeviceID] | Where-Object { $_.userId -eq $SignIn.userId }).counter + 1
                }
                $ExistingCustomObjects.AddRange($Script:DeviceTransformLookup[$DeviceID])
            }
        }
        $CustomObject = [PSCustomObject]@{
            UserName = $UserDisplayName
            userId   = $SignIn.userId
            count    = $Counter
        }
        #$ExistingCustomObjects.Add($CustomObject)
        $Script:DeviceTransformLookup[$DeviceID].ExistingCustomObjects.add($CustomObject)
    }

    $Script:EntraUsersLookup = @{}
    foreach ($User in $Script:EntraUsers.value) {
        $Script:EntraUsersLookup[$User.id.ToString()] = $User
    }
    $Script:IntuneDevicesLookup = @{}
    foreach ($Device in $Script:IntuneDevices.value) {
        $Script:IntuneDevicesLookup[$Device.id.ToString()] = $Device
    }
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
}
function Find-PrimaryUser {
    $DevicesWithUsers = $Script:IntuneDevices.value | Where-Object { $_.usersLoggedOn.Count -gt 0 }
    foreach ($Device in $DevicesWithUsers) {
        $CurrentPrimaryUserID = $Device.userId
        $TopUsers = $Device.usersLoggedOn | Where-Object { $_.lastLogOnDateTime -gt (Get-Date).AddDays(-30) } | Sort-Object -Property LastLoggedOn -Descending | Select-Object -First 10
        if ($TopUsers.Count -eq 0) {
            continue
        }
        if ($Device.usersLoggedOn.count -eq 1) {
            if ($TopUsers.userID -eq $CurrentPrimaryUserID) {
                continue
            }
        }
        # Get the sign-in counts for the users logged on to the device
        $UserCounts = @{}
        foreach ($User in $TopUsers) {
            $DeviceUserSignIns = $Script:DeviceTransformLookup[$Device.azureADDeviceId]
            if ($DeviceUserSignIns) {
                $CountDeviceMatches = ($DeviceUserSignIns | Where-Object { $_.userId -eq $User.userID }).count 
            } else {
                $CountDeviceMatches = 0
            }
            $UserCounts[$User.userID] = $CountDeviceMatches
        }     
    }
    <#| ForEach-Object -AsJob -ThrottleLimit $ThrottleLimit -Parallel {
        $AllEntraUsers = $using:EntraUsersLookup
        $Device = $_
        $CurrentPrimaryUserID = $Device.userId
        $TopUsers = $Device.usersLoggedOn | Where-Object { $_.lastLogOnDateTime -gt (Get-Date).AddDays(-30) } | Sort-Object -Property LastLoggedOn -Descending | Select-Object -First 10
        if ($TopUsers.Count -eq 0) {
            #$SkipReason = "No users with sign-ins in the last 30 days"
            continue
        }
        if ($Device.usersLoggedOn.count -eq 1) {
            if ($TopUsers.userID -eq $CurrentPrimaryUserID) {
                #$SkipReason = "Only one user logged on, and it's the current primary user"
                continue
            }
        }
        if (-not $SkipReason) {
            # Get the sign-in counts for the users logged on to the device
            $UserCounts = @{}
            foreach ($User in $TopUsers) {
                $CountDeviceMatches = ($SignInData | Where-Object { $_.deviceId -eq $Device.azureADDeviceId }).count 
                $UserCounts[$User.userID] = $CountDeviceMatches
                #Write-Output "User $($User.userID) has $CountDeviceMatches sign-ins on device $($Device.deviceName)"
            }
            #$NewPrimaryUser = $UserCounts | Measure-Object -Property Value -Maximum
            $NewPrimaryUser = $UserCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1
            if ($NewPrimaryUser.Value -eq 0) {
                #$SkipReason = "No sign-ins found for any user on this device"
                continue
            }
            if ($NewPrimaryUser.Key -eq $CurrentPrimaryUserID) {
                #$SkipReason = "Calculated primary user is the same as the current primary user"
                continue
            }
            $CompleteDeviceInformation = [PSCustomObject]@{
                DeviceName                = $Device.deviceName
                CurrentPrimaryUser        = $CurrentPrimaryUserID
                CurrentPrimaryUserName    = $AllEntraUsers[$CurrentPrimaryUserID].displayName
                CalculatedPrimaryUser     = $NewPrimaryUser.Key
                CalculatedPrimaryUserName = $AllEntraUsers[$NewPrimaryUser.Key].displayName
                DeviceID                  = $Device.id
                #SkipReason                = $SkipReason
            }
            $CompleteDeviceInformation
        }
   }   #>
}
# Start coding!
Initialize-Script
Find-PrimaryUser
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
# Get-Job | Remove-Job -Force # Uncomment to clean up jobs - we might want to keep RAM costs low in Azure Automation
Write-Output "Prepared $counter batch requests to update primary users."
Submit-BatchRequests