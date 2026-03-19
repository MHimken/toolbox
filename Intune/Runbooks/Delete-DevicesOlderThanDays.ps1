<#
.SYNOPSIS
    This runbook will remove all devices in Entra ID older than a specified number of days.
.DESCRIPTION
    The runbook connects to Entra ID using the Microsoft Graph PowerShell module, retrieves all devices, and removes those that are older than the specified threshold in days.
.PARAMETER DaysOld
    The number of days to use as the threshold for removing devices. Devices older than this number of days will be removed.
.PARAMETER ExportToCSV
    Switch to export the list of devices to a CSV file before deletion. Only works in local execution, not in Azure Automation.
.PARAMETER FilePath
    The directory path where the CSV file will be saved if ExportToCSV is specified. Default is C:\Temp\. Only works in local execution, not in Azure Automation.
.PARAMETER ThrottleLimit
    The maximum number of concurrent batch requests to submit to Microsoft Graph. Default is 5.
.PARAMETER TenantAPIToUse
    The Microsoft Graph API version to use. Default is 'beta'.
.EXAMPLE
    .\Delete-DevicesOlderThanDays.ps1 -DaysOld 90
    This command will remove all devices in Entra ID that are older than 90 days.
.NOTES
    Version: 1.0
    Versionname: Delete-DevicesOlderThanDays
    Initial creation date: 20.03.2026
    Last change date: 20.03.2026
    Latest changes: Initial Version
    ToDo:
        - Cleanup
#>
param (
    [Parameter(Mandatory = $true)]
    [int]$DaysOld,
    [switch]$ExportToCSV,
    [ValidateSet("Windows", "iOS", "Android", "macOS")]
    [string]$OSType, #this limits the script to only one target instead of all.
    [System.IO.DirectoryInfo]$FilePath = "C:\Temp\",
    [int]$ThrottleLimit = 5,
    [string]$TenantAPIToUse = 'beta'
)
if (-not(Get-MGContext)) {
    Connect-AzAccount -Identity
    $Script:token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -AsSecureString
    if (-not($Script:token)) {
        Write-Output "No access token for Microsoft Graph with Azure Run As Account"
        Exit 1
    }
    try {
        Write-Output "No Microsoft Graph context found, connecting with Azure Run As Account"
        Connect-MgGraph -AccessToken ($Script:token.Token) -NoWelcome
    } catch {
        Write-Output "No connection to Microsoft Graph with Azure Run As Account $($_.Exception.Message)"
        Exit 1
    }
    $requiredScopes = @(
        "Device.ReadWrite.All",
        "BitlockerKey.Read.All",
        "DeviceLocalCredential.Read.All"
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
    $DateCutoff = (Get-Date).AddDays(-$DaysOld).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Output "Date cutoff for device deletion is set to: $DateCutoff"
    $Script:GraphAPIBaseURL = "https://graph.microsoft.com/$TenantAPIToUse"
    $Script:AllEntraDevices = Invoke-MgGraphRequest -Uri "$Script:GraphAPIBaseURL/devices/?`$expand=registeredOwners&`$select=id,displayName,deviceId,approximateLastSignInDateTime,createdDateTime,enrollmentProfileName,physicalIds,accountEnabled,operatingSystem$(if($OSType){"&`$filter=operatingSystem eq '$OSType'"})" -ErrorAction Stop
    if ($Script:AllEntraDevices.'@odata.nextLink') {
        Write-Output "Found more than 1000 Entra devices, retrieving next link data"
        $Script:AllEntraDevices = Get-nextLinkData -OriginalObject $Script:AllEntraDevices
    }
    #Filter out Servers by OS Version
    
    $Script:AllEntraDevicesHashTable = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTable[$Device.deviceId] = $Device
    }
    $Script:AllEntraDevicesHashTableByID = @{}
    foreach ($Device in $Script:AllEntraDevices.value) {
        $Script:AllEntraDevicesHashTableByID[$Device.id] = $Device
    }
    if ($ExportToCSV) {
        $Script:CsvFilePath = Join-Path -Path $FilePath.FullName -ChildPath "EntraDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    $Script:LogPrefix = "DeleteDevicesOlderThan$DaysOld"

}
function Export-ToCsv {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data
    )
    if (Test-Path -Path $Script:CsvFilePath) {
        Write-Output "File $($Script:CsvFilePath) already exists. Overwriting."
        Remove-Item -Path $Script:CsvFilePath -Force
    }
    $Data | Export-Csv -Path $Script:CsvFilePath -NoTypeInformation -Encoding UTF8 -Delimiter ';' -NoClobber -Force
    Write-Output "Exported data to CSV file at: $($Script:CsvFilePath)"
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
    }
    if ($Body) {
        #A body is only required for POST, PATCH, and PUT requests
        $BatchObject | Add-Member -MemberType NoteProperty -Name 'body' -Value $null -Force
        $BatchObject.body = $Body
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
    foreach ($BatchRequest in $Script:BatchRequestsQueue) {
        $Script:BatchJobs = Start-ThreadJob -Name "RemoveEntraDevice-$($BatchRequest.Name)" -ThrottleLimit $ThrottleLimit -ScriptBlock {
            param($ArgumentToProvide, $TenantAPIToUse)
            $TenantAPIToUse = if ($TenantAPIToUse) { $TenantAPIToUse } else { 'beta' }
            $URI = "https://graph.microsoft.com/$TenantAPIToUse/`$batch"
            Invoke-MgGraphRequest -Method POST -Uri $URI -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
        } -ArgumentList @($BatchRequest.ArgumentToProvide, $TenantAPIToUse)
        Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000) # Random delay to avoid throttling
    }
    Write-Output "Batch requests submitted."
}
function Remove-EntraDevice {
    param (
        [string]$ID
    )
    $ObjectID = $Script:AllEntraDevicesHashTable[$ID].id
    $Method = 'DELETE'
    $URL = "/devices/$ObjectID"
    $Headers = @{
        'Content-Type' = 'application/json'
    }
    Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
}
function Remove-DeprecatedDevices {
    foreach ($Device in $Script:AllEntraDevicesToRemove) {
        Write-Output "Removing device: $($Device.displayName) with Device ID: $($Device.deviceId) Last Sign-In: $($Device.approximateLastSignInDateTime)"
        Remove-EntraDevice -ID $Device.deviceId
    }
}
function Get-LAPSKeys {
    param (
        [string]$DeviceID
    )
    $LAPSKeys = $null
    $headers = @{
        'ocp-client-name'    = 'Backup LAPS Key'
        'ocp-client-version' = '1.0'
        'client-request-id'  = [Guid]::NewGuid().ToString()
    }
    $URILaps = "$($Script:GraphAPIBaseURL)/directory/deviceLocalCredentials/$DeviceID/?`$select=credentials"
    $ResponseLAPS = Invoke-MgGraphRequest -Method GET -Uri $URILaps -Headers $headers
    $PasswordFromBase64 = ($ResponseLAPS.credentials).PasswordBase64
    $LAPSKeys = $PasswordFromBase64 | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) }
    return $LAPSKeys
}
function Backup-BitlockerKey {
    param (
        [string]$DeviceID
    )
    $headers = @{
        'ocp-client-name'    = 'Backup Bitlocker Key'
        'ocp-client-version' = '1.0'
        'User-Agent'         = 'Microsoft Graph PowerShell SDK'
    }
    if (-not($Script:AllRecoveryKeys)) {
        $Script:AllRecoveryKeys = Invoke-MgGraphRequest -Method GET -Uri "$($Script:GraphAPIBaseURL)/informationProtection/bitlocker/recoveryKeys/" -Headers $headers
        if ($Script:AllRecoveryKeys.'@odata.nextLink') {
            Write-Output "Found more than 1000 Bitlocker recovery keys, retrieving next link data"
            $Script:AllRecoveryKeys = Get-nextLinkData -OriginalObject $Script:AllRecoveryKeys
        }
    }
    #Get the BitLocker recovery passwords for all recovery ids found
    $Script:BitLockerHashtable = @{}
    foreach($RecoveryKeyID in $Script:AllRecoveryKeys.value){
        $RecoveryPassword = Invoke-MgGraphRequest -Method GET -Uri "$($Script:GraphAPIBaseURL)/informationProtection/bitlocker/recoveryKeys/$($RecoveryKeyID.id)/?`$select=key"
        $KeyObject = @{
            key = $RecoveryPassword.key
            id  = $RecoveryKeyID.id
        }
        if ($Script:BitLockerHashtable.ContainsKey($RecoveryKeyID.deviceId)) {
            $Script:BitLockerHashtable[$RecoveryKeyID.deviceId] += $KeyObject
        } else {
            $Script:BitLockerHashtable[$RecoveryKeyID.deviceId] = @($KeyObject)
        }
    }
}
function Find-DevicesToRemove {
    $TotalDevices = $Script:AllEntraDevices.value.Count
    Write-Output "Starting analysis of devices older than $DaysOld days. Found $TotalDevices devices to analyze"
    $Script:AllEntraDevicesToRemove = [System.Collections.ArrayList]::new()
    foreach ($Device in $Script:AllEntraDevices.value) {
        $DeletionReason = @()
        $DateCutoff = (Get-Date).AddDays(-$DaysOld)
        if ($Device.approximateLastSignInDateTime) {
            if ($Device.approximateLastSignInDateTime -lt $DateCutoff) {
                $DeletionReason += "LastSignInDateAboveThreshold"
            }
        } else {
            $DeletionReason += "NoLastSignInDate"
            if ($Device.physicalIds -and $Device.physicalIds -contains "ZTDId") {
                if (($null -eq $Device.enrollmentProfileName -or $Device.enrollmentProfileName -eq "Unknown") -and $Device.accountEnabled -eq $false) {
                    continue
                }
                if ($Device.enrollmentProfileName -and $Device.accountEnabled -eq $true) {
                    $DeletionReason += "PreviouslyEnrolledAndEnabled"
                }
            }
        }
        if ($DeletionReason) {
            $DeviceToRemove = [PSCustomObject]@{
                displayName                   = $Device.displayName
                deviceId                      = $Device.deviceId
                approximateLastSignInDateTime = $Device.approximateLastSignInDateTime
                createdDateTime               = $Device.createdDateTime
                enrollmentProfileName         = $Device.enrollmentProfileName
                operatingSystem               = $Device.operatingSystem
                accountEnabled                = $Device.accountEnabled
                ReasonToDelete                = $DeletionReason -join ", "
                LAPSPasswords                 = (Get-LAPSKeys -DeviceID $Device.deviceId) -join "`n"
                BitlockerKeys                 = if($Device.operatingSystem -eq "Windows") { ($Script:BitLockerHashtable[$Device.deviceId] | ForEach-Object { $_.key }) -join "`n" } else { "N/A" }
                BitLockerKeyIDs               = if($Device.operatingSystem -eq "Windows") { ($Script:BitLockerHashtable[$Device.deviceId] | ForEach-Object { $_.id }) -join "`n" } else { "N/A" }
            }
            $Script:AllEntraDevicesToRemove.add($DeviceToRemove) | Out-Null
        }
    }
}

# Start Coding!
Initialize-Script

Write-Output "Finding devices older than $DaysOld days for removal."
if($OSType -eq "Windows" -or $Script:AllEntraDevices.value.operatingSystem -contains "Windows"){
    Write-Output "Targeting only Windows devices for removal."
    Backup-BitlockerKey
} else {
    Write-Output "Targeting only $OSType devices for removal."
}
Find-DevicesToRemove
if ($ExportToCSV -and -not($Script:token)) {
    Write-Output "Exporting Entra devices to CSV before deletion."
    Export-ToCsv -Data $Script:AllEntraDevicesToRemove
}

Remove-DeprecatedDevices

Submit-BatchRequests

Write-Output "Device deletion process completed."