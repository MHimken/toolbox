# THIS SCRIPT IS NOT DONE!
#Requires -Module Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
.NOTES
    Version: 1.0
    Versionname: Repair-PrimaryUserRunbook.ps1
    Intial creation date: 07.12.2025
    Last change date: 07.12.2025
    Latest changes: Initial Version
    Author: Martin Himken
    ToDo:
#>
param(
    [string]$TenantAPIToUse = "beta"
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
        "DeviceManagementManagedDevices.Read.All",
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
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
}
function Find-PrimaryUser {
    # Filter for devices that have users logged on
    $DevicesWithUsers = $Script:IntuneDevices.value | Where-Object { $_.usersLoggedOn.Count -gt 0 }
    $Script:PrimaryUserResults = [System.Collections.ArrayList]::new()
    foreach ($Device in $DevicesWithUsers) {
        $CurrentPrimaryUserID = $Device.userId
        Write-Output "Processing device $($Device.deviceName) with current primary user ID $($CurrentPrimaryUserID)"
        # Get the top 10 users logged on to the device, this is to limit the amount of data request from graph later
        #$Device.usersLoggedOn.lastLogOnDateTime
        $TopUsers = $Device.usersLoggedOn | Where-Object { $_.lastLogOnDateTime -gt (Get-Date).AddDays(-30) } | Sort-Object -Property LastLoggedOn -Descending | Select-Object -First 10
        if ($TopUsers.Count -eq 0) {
            #Write-Output "No users logged on to device $($Device.deviceName) in the last 30 days, skipping"
            continue
        }
        if ($Device.usersLoggedOn.count -eq 1) {
            if ($TopUsers.userID -eq $CurrentPrimaryUserID) {
                #Write-Output "Device $($Device.deviceName) already has the correct primary user assigned: $($Script:EntraUsersLookup[$CurrentPrimaryUserID].displayName) ($CurrentPrimaryUserID)"
                continue
            }
        }

        # Get the sign-in counts for the users logged on to the device
        $UserCounts = @{}
        #$DateCutoff = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ") #30 is the maximum that makes sense for primary user calculation, plus the Graph API might time out with longer timeframes
        foreach ($User in $TopUsers) {
            #$SignInData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$TenantAPIToUse/auditLogs/signIns/?`$filter=userId eq '$($User.userID)' and createdDateTime ge $($DateCutoff) and appDisplayName eq 'Windows Sign In'&?select=deviceDetail"
            $SignInData = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$TenantAPIToUse/auditLogs/signIns/?`$filter=userId eq '$($User.userID)'&?select=deviceDetail").value.deviceDetail
            $CountDeviceMatches = ($SignInData | Where-Object { $_.deviceId -eq $Device.azureADDeviceId }).count 
            $UserCounts[$User.userID] = $CountDeviceMatches
            #Write-Output "User $($User.userID) has $CountDeviceMatches sign-ins on device $($Device.deviceName)"
        }
        #$NewPrimaryUser = $UserCounts | Measure-Object -Property Value -Maximum
        $NewPrimaryUser = $UserCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1
        if ($NewPrimaryUser.Value -eq 0) {
            #Write-Output "No sign-in data found for the users on device $($Device.deviceName), skipping"
            continue
        }
        if ($NewPrimaryUser.Key -eq $CurrentPrimaryUserID) {
            #Write-Output "Device $($Device.deviceName) already has the correct primary user assigned: $($Script:EntraUsersLookup[$CurrentPrimaryUserID].displayName) ($CurrentPrimaryUserID)"
            continue
        }
        $CompleteDeviceInformation = [PSCustomObject]@{
            CurrentPrimaryUser    = $CurrentPrimaryUserID
            CalculatedPrimaryUser = $NewPrimaryUser.Key
            DeviceName            = $Device.deviceName
            DeviceID              = $Device.id
            UsersLoggedOn         = $Device.usersLoggedOn.userID
        }
        $Script:PrimaryUserResults.Add($CompleteDeviceInformation) | Out-Null
    }
}
# Start coding!
Initialize-Script
Find-PrimaryUser
foreach ($Result in $Script:PrimaryUserResults) {
    Write-Output "Device $($Result.DeviceName) - Current Primary User: $($Script:EntraUsersLookup[$Result.CurrentPrimaryUser].displayName) ($($Result.CurrentPrimaryUser)) -> New Primary User: $($Script:EntraUsersLookup[$Result.CalculatedPrimaryUser].displayName) ($($Result.CalculatedPrimaryUser))"
    # Prepare the batch request to update the primary user
    $Body = @{
        "@odata.id" = "https://graph.microsoft.com/beta/users/$($Result.CalculatedPrimaryUser)"
    }
    $JSONBody = $Body | ConvertTo-Json -Depth 10
    Invoke-BatchRequest -Method POST -URL "/deviceManagement/managedDevices/$($Result.DeviceID)/users/`$ref" -Body $JSONBody
}