<#
.SYNOPSIS
    Adds an Entra device to a configurable group after resolving the device from a webhook-provided EntraDeviceID.
.DESCRIPTION
    This runbook reuses the managed identity Microsoft Graph connection pattern used throughout the toolbox.
    It supports three execution modes:
    - Dry run mode when DryRun is true (analyze only, no add/remove)
    - Scheduled cleanup mode when EntraDeviceID is not provided (cleanup only)
    - Webhook mode when EntraDeviceID is provided (cleanup + add if needed)
.LINK
    c:\Git\toolbox\toolbox\Intune\Other\Send-EntraDeviceIDToWebhookDuringESP.ps1
.PARAMETER EntraDeviceID
    The device ID from Entra (AadDeviceID) received from the webhook.
    If not set, the script runs in scheduled cleanup mode.
.PARAMETER WebhookData
    Optional Azure Automation webhook input object. If provided, RequestBody is parsed and
    EntraDeviceID is read from RequestBody.EntraDeviceID.
.PARAMETER GroupID
    The Entra group ID to add the device to.
.PARAMETER RetryCount
    How many times to retry the Entra device lookup when the device is not found.
.PARAMETER RetryDelaySeconds
    How many seconds to wait between lookup retries.
.PARAMETER RemoveDevicesOlderThanDays
    Remove group members if their Intune enrolledDateTime is older than this number of days.
.PARAMETER DryRun
    If true, analyze and report what would change without modifying group membership.
.PARAMETER TenantAPIToUse
    The Microsoft Graph API version to use. Default is /beta.
.NOTES
    Version: 1.0
    Versionname: Add-EntraDeviceToGroupFromWebhook-Runbook
    Initial creation date: 06.08.2026
    Last change date: 06.08.2026
    Author: Martin Himken
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GroupID,
    [string]$EntraDeviceID,
    [object]$WebhookData,
    [int]$RetryCount = 5,
    [int]$RetryDelaySeconds = 10,
    [int]$RemoveDevicesOlderThanDays = 7,
    [bool]$DryRun = $false,
    [string]$TenantAPIToUse = "/beta"
)
# Stop editing here

if ($WebhookData) {
    Write-Output "WebhookData input detected. Parsing RequestBody."
    $WebhookObject = $WebhookData

    if ($WebhookObject -is [string]) {
        try {
            $WebhookObject = $WebhookObject | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Output "WebhookData string could not be parsed as JSON. Error: $($_.Exception.Message)"
            Exit 1
        }
    }

    $RequestBodyRaw = $null
    if ($WebhookObject.PSObject.Properties.Name -contains 'RequestBody') {
        $RequestBodyRaw = $WebhookObject.RequestBody
    }

    if (-not([string]::IsNullOrWhiteSpace([string]$RequestBodyRaw))) {
        $RequestBodyObject = $null
        try {
            if ($RequestBodyRaw -is [string]) {
                $RequestBodyObject = $RequestBodyRaw | ConvertFrom-Json -ErrorAction Stop
            } else {
                $RequestBodyObject = $RequestBodyRaw
            }
        } catch {
            Write-Output "WebhookData.RequestBody could not be parsed as JSON. Error: $($_.Exception.Message)"
            Exit 1
        }

        if ([string]::IsNullOrWhiteSpace($EntraDeviceID) -and $RequestBodyObject.PSObject.Properties.Name -contains 'EntraDeviceID') {
            $EntraDeviceID = [string]$RequestBodyObject.EntraDeviceID
            Write-Output "EntraDeviceID extracted from WebhookData.RequestBody."
        }
    } else {
        Write-Output "WebhookData.RequestBody is empty."
    }
}

$ExecutionMode = "Scheduled"
if ($DryRun) {
    $ExecutionMode = "DryRun"
} elseif (-not([string]::IsNullOrWhiteSpace($EntraDeviceID))) {
    $ExecutionMode = "Webhook"
}
Write-output "Execution mode: $ExecutionMode"

if ($ExecutionMode -eq "Webhook") {
    # Validate the incoming device identifier before contacting Microsoft Graph.
    try {
        [guid]::Parse($EntraDeviceID) | Out-Null
    } catch {
        Write-Output "EntraDeviceID '$EntraDeviceID' is not a valid GUID."
        Exit 1
    }
}

# Connect to Microsoft Graph using the Azure Automation Run As Account
if (-not(Get-MGContext)) {
    Connect-AzAccount -Identity | Out-Null
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
        "Device.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "GroupMember.ReadWrite.All",
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

function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink -ErrorAction Stop
        $Results.value += $Request.value
        $Results.'@odata.count' += $Request.'@odata.count'
        $nextLink = $Request.'@odata.nextLink'
    }
    $Results.'@odata.nextLink' = $null
    return $Results
}

function Get-EntraDeviceByDeviceId {
    param(
        [string]$DeviceId,
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 10
    )

    $Attempt = 0
    $Device = $null
    while ($Attempt -lt $MaxAttempts -and -not($Device)) {
        $Attempt++
        Write-Output "Looking up Entra device by deviceId $DeviceId. Attempt $Attempt of $MaxAttempts."
        try {
            $Response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com$TenantAPIToUse/devices/?`$filter=(deviceId eq '$DeviceId')&`$select=id,deviceId,displayName" -ErrorAction Stop
            if ($Response.'@odata.nextLink') {
                $Response = Get-nextLinkData -OriginalObject $Response
            }
            if ($Response.value -and $Response.value.Count -gt 0) {
                $Device = $Response.value[0]
                break
            }
        } catch {
            Write-Output "Device lookup attempt $Attempt failed: $($_.Exception.Message)"
        }
        if (-not($Device) -and $Attempt -lt $MaxAttempts) {
            Write-Output "Device not found yet. Waiting $DelaySeconds seconds before retry."
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    return $Device
}

function Get-GroupMembers {
    param(
        [string]$Id
    )

    $Members = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/groups/$Id/members/?`$select=id,deviceId,displayName" -ErrorAction Stop
    if ($Members.'@odata.nextLink') {
        Write-Output "Getting next link for group members"
        $Members = Get-nextLinkData -OriginalObject $Members
    }
    return $Members
}

function Get-IntuneManagedDeviceLookup {
    $ManagedDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com$TenantAPIToUse/deviceManagement/managedDevices/?`$select=id,deviceName,enrolledDateTime,azureADDeviceId" -ErrorAction Stop
    if ($ManagedDevices.'@odata.nextLink') {
        Write-Output "Getting next link for Intune managed devices"
        $ManagedDevices = Get-nextLinkData -OriginalObject $ManagedDevices
    }

    $Lookup = @{}
    foreach ($ManagedDevice in $ManagedDevices.value) {
        if ($ManagedDevice.azureADDeviceId) {
            $Lookup[$ManagedDevice.azureADDeviceId.ToString().ToLowerInvariant()] = $ManagedDevice
        }
    }

    return [PSCustomObject]@{
        Lookup      = $Lookup
        DeviceCount = $ManagedDevices.value.Count
    }
}

function Remove-DeviceFromGroupMemberReference {
    param(
        [string]$GroupObjectId,
        [string]$MemberObjectId
    )

    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com$TenantAPIToUse/groups/$GroupObjectId/members/$MemberObjectId/`$ref" -ErrorAction Stop | Out-Null
}

Write-Output "Processing mode=$ExecutionMode for group $GroupID."
$Script:EntraDevice = $null
if ($ExecutionMode -eq "Webhook") {
    Write-Output "Processing EntraDeviceID $EntraDeviceID."
    $Script:EntraDevice = Get-EntraDeviceByDeviceId -DeviceId $EntraDeviceID -MaxAttempts $RetryCount -DelaySeconds $RetryDelaySeconds
}
$Script:GroupMembers = Get-GroupMembers -Id $GroupID
$Script:IntuneManagedDeviceLookupData = Get-IntuneManagedDeviceLookup
$IntuneManagedDeviceLookup = $Script:IntuneManagedDeviceLookupData.Lookup

if ($Script:EntraDevice) {
    Write-Output "Found Entra device $($Script:EntraDevice.displayName) with object ID $($Script:EntraDevice.id)."
} else {
    if ($ExecutionMode -eq "Webhook") {
        Write-Output "Device with EntraDeviceID $EntraDeviceID was not found after $RetryCount attempts."
    }
}

$MemberLookup = @{}
foreach ($Member in $Script:GroupMembers.value) {
    $MemberLookup[$Member.id.ToString()] = $Member
}

$Summary = [ordered]@{
    ExecutionMode               = $ExecutionMode
    GroupMembersInGroup          = $Script:GroupMembers.value.Count
    IncomingDeviceFoundInEntra   = 0
    IncomingDeviceAlreadyInGroup = 0
    WouldAdd                     = 0
    WouldRemove                  = 0
    Added                        = 0
    Removed                      = 0
    IntuneDevicesQueried         = $Script:IntuneManagedDeviceLookupData.DeviceCount
}

if ($Script:EntraDevice) {
    $Summary.IncomingDeviceFoundInEntra = 1
    if ($MemberLookup.ContainsKey($Script:EntraDevice.id.ToString())) {
        $Summary.IncomingDeviceAlreadyInGroup = 1
    } else {
        $Summary.WouldAdd = 1
    }
}

$CleanupCandidates = [System.Collections.ArrayList]::new()
if ($RemoveDevicesOlderThanDays -gt 0) {
    $EnrollmentCutoff = (Get-Date).AddDays(-$RemoveDevicesOlderThanDays)
    foreach ($Member in $Script:GroupMembers.value) {
        if (-not($Member.deviceId)) {
            continue
        }
        $DeviceIdKey = $Member.deviceId.ToString().ToLowerInvariant()
        if (-not($IntuneManagedDeviceLookup.ContainsKey($DeviceIdKey))) {
            continue
        }

        $IntuneDevice = $IntuneManagedDeviceLookup[$DeviceIdKey]
        if (-not($IntuneDevice.enrolledDateTime)) {
            continue
        }

        $EnrolledDateTime = [datetime]$IntuneDevice.enrolledDateTime
        if ($EnrolledDateTime -lt $EnrollmentCutoff) {
            $Summary.WouldRemove++
            $CleanupCandidates.Add([PSCustomObject]@{
                    GroupMemberObjectId = $Member.id
                    EntraDisplayName    = $Member.displayName
                    IntuneDeviceName    = $IntuneDevice.deviceName
                    EnrolledDateTime    = $EnrolledDateTime
                }) | Out-Null
        }
    }
}

if ($DryRun) {
    Write-Output "DryRun enabled. No changes will be made."
    Write-Output "DryRun summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) incomingFound=$($Summary.IncomingDeviceFoundInEntra) alreadyInGroup=$($Summary.IncomingDeviceAlreadyInGroup) wouldAdd=$($Summary.WouldAdd) wouldRemove=$($Summary.WouldRemove) intuneDevicesQueried=$($Summary.IntuneDevicesQueried)"
    Exit 0
}

if ($CleanupCandidates.Count -gt 0) {
    foreach ($Candidate in $CleanupCandidates) {
        try {
            Remove-DeviceFromGroupMemberReference -GroupObjectId $GroupID -MemberObjectId $Candidate.GroupMemberObjectId
            $Summary.Removed++
            Write-Output "Removed stale group member $($Candidate.EntraDisplayName) enrolledDateTime=$($Candidate.EnrolledDateTime.ToString('s'))."
        } catch {
            Write-Output "Failed to remove stale group member objectId=$($Candidate.GroupMemberObjectId). Error: $($_.Exception.Message)"
        }
    }
}

if (-not($Script:EntraDevice)) {
    if ($ExecutionMode -eq "Webhook") {
        Write-Output "Summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) incomingFound=$($Summary.IncomingDeviceFoundInEntra) alreadyInGroup=$($Summary.IncomingDeviceAlreadyInGroup) wouldAdd=$($Summary.WouldAdd) removed=$($Summary.Removed)"
        Exit 1
    }

    Write-Output "Scheduled cleanup completed."
    Write-Output "Summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) wouldRemove=$($Summary.WouldRemove) removed=$($Summary.Removed) intuneDevicesQueried=$($Summary.IntuneDevicesQueried)"
    Exit 0
}

if ($Summary.IncomingDeviceAlreadyInGroup -eq 1) {
    Write-Output "Device $($Script:EntraDevice.displayName) is already a member of group $GroupID."
    Write-Output "Summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) incomingFound=$($Summary.IncomingDeviceFoundInEntra) alreadyInGroup=$($Summary.IncomingDeviceAlreadyInGroup) wouldAdd=$($Summary.WouldAdd) removed=$($Summary.Removed)"
    Exit 0
}

try {
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/groups/$GroupID/members/`$ref" -Body (@{
            '@odata.id' = "https://graph.microsoft.com/v1.0/devices/$($Script:EntraDevice.id)"
        } | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop
    $Summary.Added++
    Write-Output "Successfully added device $($Script:EntraDevice.displayName) ($($Script:EntraDevice.id)) to group $GroupID."
    Write-Output "Summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) incomingFound=$($Summary.IncomingDeviceFoundInEntra) alreadyInGroup=$($Summary.IncomingDeviceAlreadyInGroup) added=$($Summary.Added) removed=$($Summary.Removed)"
    Exit 0
} catch {
    Write-Output "Failed to add device $($Script:EntraDevice.displayName) to group $GroupID. Error: $($_.Exception.Message)"
    Write-Output "Summary: mode=$($Summary.ExecutionMode) groupMembers=$($Summary.GroupMembersInGroup) incomingFound=$($Summary.IncomingDeviceFoundInEntra) alreadyInGroup=$($Summary.IncomingDeviceAlreadyInGroup) added=$($Summary.Added) removed=$($Summary.Removed)"
    Exit 1
}