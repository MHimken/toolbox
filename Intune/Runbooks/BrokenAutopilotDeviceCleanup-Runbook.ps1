#Requires -Modules Az.Accounts, Microsoft.Graph.Authentication
#Requires -Version 7.0
<#
.SYNOPSIS
    Runbook version of the Broken Autopilot Device Cleanup logic for Azure Automation.
.DESCRIPTION
    This runbook analyzes Autopilot, Entra, and Intune device records to determine whether they should be retained, disabled, or removed based on inactivity.
    It supports scheduled execution, webhook-driven execution, and a safe dry-run mode that logs the intended actions without changing Microsoft Graph objects.
    The logic is written to match the workbook pattern used by the toolbox runbooks, but it is adapted to Azure Automation managed identity authentication.
.PARAMETER WebhookData
    Optional Azure Automation webhook payload containing the incoming serial numbers used as cleanup candidates.
    The payload may contain a direct SerialNumbers array, a SerialNumber string, or a RequestBody object with the same properties.
.PARAMETER NumberOfDaysBeforeDeletion
    Number of days before a device is considered for deletion. Default is -180.
.PARAMETER NumberOfDaysBeforeDisable
    Number of days before a device is considered for disabling. Default is -90.
.PARAMETER EntraDeviceDisableAction
    Action to use for Entra devices in the disable window. Default is "Disable".
.PARAMETER EntraDeviceDeleteAction
    Action to use for Entra devices in the delete window. Default is "Remove".
.PARAMETER IntuneDeviceDisableAction
    Action to use for Intune devices in the disable window. Default is "Retire".
.PARAMETER IntuneDeviceDeleteAction
    Action to use for Intune devices in the delete window. Default is "Remove".
.PARAMETER EnableCleanup
    If set, the script will apply the recommended cleanup actions. If not set, it only analyzes.
.PARAMETER DryRun
    If set, the script logs the planned changes but avoids making Graph requests.
.PARAMETER TenantAPIToUse
    The Microsoft Graph API version to use. Default is "beta".
.PARAMETER LogPrefix
    Prefix used for logging. Default is "BAD-C-Runbook".
.EXAMPLE
    .\BrokenAutopilotDeviceCleanup-Runbook.ps1 -EnableCleanup -DryRun
    Runs the cleanup analysis in dry-run mode without modifying any device objects.
.EXAMPLE
    # Azure Automation webhook payload example
    # { "SerialNumbers": ["ABC123", "DEF456"] }
.NOTES
    Version: 1.0
    Versionname: BrokenAutopilotDeviceCleanup-Runbook
    Initial creation date: 11.08.2026
    Last change date: 11.08.2026
    Latest changes: Initial runbook version, Azure Automation managed identity support, and dry-run handling.
    Author: Martin Himken
    Purpose: Run the Autopilot cleanup logic in Microsoft Azure Automation and support inspection before destructive changes.
    Required Graph scopes:
        DryRun mode (read-only): Device.Read.All (or ReadWrite.All), DeviceManagementManagedDevices.Read.All (or ReadWrite.All), User.Read.All
        Full run (EnableCleanup, no DryRun): Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All, User.Read.All
    To do:
        - Add more resilient Graph retry handling
        - Add optional export of device recovery data (LAPS/BitLocker)
        - Extend the webhook payload parser for more automation inputs
#>
param(
    [object]$WebhookData,
    [int]$NumberOfDaysBeforeDeletion = -180,
    [int]$NumberOfDaysBeforeDisable = -90,
    [ValidateSet('Retain', 'Disable', 'Remove')]
    [string]$EntraDeviceDisableAction = 'Disable',
    [ValidateSet('Retain', 'Disable', 'Remove')]
    [string]$EntraDeviceDeleteAction = 'Remove',
    [ValidateSet('Retain', 'Retire', 'Wipe', 'Remove')]
    [string]$IntuneDeviceDisableAction = 'Retire',
    [ValidateSet('Retain', 'Retire', 'Wipe', 'Remove')]
    [string]$IntuneDeviceDeleteAction = 'Remove',
    [switch]$EnableCleanup,
    [switch]$DryRun,
    [string]$TenantAPIToUse = 'beta',
    [string]$LogPrefix = 'BAD-C-Runbook'
)

function Write-RunbookLog {
    param(
        [string]$Message,
        [string]$Component = 'Runbook',
        [ValidateSet('1', '2', '3')][int]$Type = 1
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Color = 'White'
    switch ($Type) {
        1 { $Color = 'White' }
        2 { $Color = 'Yellow' }
        3 { $Color = 'Red' }
    }

    Write-Host "[$Timestamp] [$Component] [$Type] $Message" -ForegroundColor $Color
}
function Initialize-Script {
    $Script:DeleteDate = (Get-Date).AddDays($NumberOfDaysBeforeDeletion)
    $Script:DisableDate = (Get-Date).AddDays($NumberOfDaysBeforeDisable)
    $Script:EntraDeviceDeleteAction = $EntraDeviceDeleteAction
    $Script:EntraDeviceDisableAction = $EntraDeviceDisableAction
    $Script:IntuneDeviceDeleteAction = $IntuneDeviceDeleteAction
    $Script:IntuneDeviceDisableAction = $IntuneDeviceDisableAction
}
function Get-nextLinkData {
    param($OriginalObject)

    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink -ErrorAction Stop
        $Results.value += $Request.value
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}

function Get-RequiredGraphScopeSets {
    # DryRun only reads data, so read-only scope alternatives are acceptable there.
    if ($DryRun) {
        return @(
            @{ Description = 'Device.Read.All or Device.ReadWrite.All'; Alternatives = @('Device.Read.All', 'Device.ReadWrite.All') },
            @{ Description = 'DeviceManagementManagedDevices.Read.All or .ReadWrite.All'; Alternatives = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.ReadWrite.All') },
            @{ Description = 'User.Read.All'; Alternatives = @('User.Read.All') }
        )
    }

    return @(
        @{ Description = 'Device.ReadWrite.All'; Alternatives = @('Device.ReadWrite.All') },
        @{ Description = 'DeviceManagementManagedDevices.ReadWrite.All'; Alternatives = @('DeviceManagementManagedDevices.ReadWrite.All') },
        @{ Description = 'DeviceManagementManagedDevices.PrivilegedOperations.All'; Alternatives = @('DeviceManagementManagedDevices.PrivilegedOperations.All') },
        @{ Description = 'User.Read.All'; Alternatives = @('User.Read.All') }
    )
}

function Connect-RunbookGraph {
    if (-not (Get-MgContext)) {
        Write-RunbookLog -Message 'No Graph context found. Connecting with managed identity.' -Component 'Auth'
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            $Token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
            Connect-MgGraph -AccessToken $Token.Token -NoWelcome -ErrorAction Stop | Out-Null
        }
        catch {
            Write-RunbookLog -Message "Failed to connect with managed identity: $($_.Exception.Message)" -Component 'Auth' -Type 3
            throw
        }
    }
    else {
        Write-RunbookLog -Message 'Microsoft Graph context already connected.' -Component 'Auth'
    }

    $Context = Get-MgContext
    $MissingScopes = @()
    foreach ($ScopeSet in (Get-RequiredGraphScopeSets)) {
        $Satisfied = $false
        foreach ($Alternative in $ScopeSet.Alternatives) {
            if ($Context.Scopes -contains $Alternative) {
                $Satisfied = $true
                break
            }
        }
        if (-not $Satisfied) {
            $MissingScopes += $ScopeSet.Description
        }
    }

    if ($MissingScopes.Count -gt 0) {
        Write-RunbookLog -Message "Missing Graph scopes: $($MissingScopes -join ', ')" -Component 'Auth' -Type 3
        throw "Missing required Microsoft Graph scopes: $($MissingScopes -join ', ')"
    }

    Write-RunbookLog -Message 'Microsoft Graph connection verified successfully.' -Component 'Auth'
}

function Get-WebhookSerialNumbers {
    param([object]$Payload)

    $Serials = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not $Payload) {
        return $Serials
    }

    $Candidate = $Payload
    try {
        if ($Payload -is [string]) {
            $Candidate = $Payload | ConvertFrom-Json -ErrorAction Stop
        }
    }
    catch {
        Write-RunbookLog -Message "Webhook payload is not valid JSON: $($_.Exception.Message)" -Component 'Webhook' -Type 3
        return $Serials
    }

    if ($Candidate -and $Candidate.PSObject.Properties.Name -contains 'RequestBody') {
        $Body = $Candidate.RequestBody
        if ($Body -is [string]) {
            try {
                $Candidate = $Body | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                Write-RunbookLog -Message "Webhook RequestBody is not valid JSON: $($_.Exception.Message)" -Component 'Webhook' -Type 3
                $Candidate = $null
            }
        }
        else {
            $Candidate = $Body
        }
    }

    if (-not $Candidate) {
        return $Serials
    }

    $NamesToCheck = @('SerialNumbers', 'SerialNumber', 'Serials', 'DeviceSerialNumbers')
    foreach ($Name in $NamesToCheck) {
        if ($Candidate.PSObject.Properties.Name -contains $Name) {
            $Value = $Candidate.$Name
            if ($Value -is [array] -or $Value -is [System.Collections.IEnumerable]) {
                foreach ($Item in $Value) {
                    if ($null -ne $Item) {
                        $Trimmed = [string]$Item
                        if (-not [string]::IsNullOrWhiteSpace($Trimmed)) {
                            $Serials.Add($Trimmed.Trim()) | Out-Null
                        }
                    }
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace([string]$Value)) {
                $Serials.Add(([string]$Value).Trim()) | Out-Null
            }
        }
    }

    if ($Serials.Count -eq 0) {
        foreach ($Property in $Candidate.PSObject.Properties) {
            if ($Property.Name -match 'Serial') {
                $Value = $Property.Value
                if ($Value -is [array] -or $Value -is [System.Collections.IEnumerable]) {
                    foreach ($Item in $Value) {
                        if ($null -ne $Item) {
                            $Trimmed = [string]$Item
                            if (-not [string]::IsNullOrWhiteSpace($Trimmed)) {
                                $Serials.Add($Trimmed.Trim()) | Out-Null
                            }
                        }
                    }
                }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$Value)) {
                    $Serials.Add(([string]$Value).Trim()) | Out-Null
                }
            }
        }
    }

    return $Serials
}

function Get-AutopilotDevices {
    param([string]$ApiVersion)

    $Uri = "https://graph.microsoft.com/$ApiVersion/deviceManagement/windowsAutopilotDeviceIdentities/"
    $Response = Invoke-MgGraphRequest -Uri $Uri -ErrorAction Stop
    if ($Response.'@odata.nextLink') {
        $Response = Get-nextLinkData -OriginalObject $Response
    }

    $Lookup = @{}
    foreach ($Device in $Response.value) {
        $Serial = $Device.serialNumber
        if (-not [string]::IsNullOrWhiteSpace($Serial)) {
            $Lookup[$Serial.Trim()] = $Device
        }
    }

    return $Lookup
}

function Get-EntraDevices {
    param([string]$ApiVersion)

    $Uri = "https://graph.microsoft.com/$ApiVersion/devices/?`$expand=registeredOwners&`$filter=(operatingSystem eq 'Windows' or operatingSystem eq 'Unknown')&`$select=id,displayName,deviceId,approximateLastSignInDateTime,createdDateTime,enrollmentProfileName,physicalIds,accountEnabled"
    $Response = Invoke-MgGraphRequest -Uri $Uri -ErrorAction Stop
    if ($Response.'@odata.nextLink') {
        $Response = Get-nextLinkData -OriginalObject $Response
    }

    $ByDeviceId = @{}
    $ByObjectId = @{}
    foreach ($Device in $Response.value) {
        if (-not [string]::IsNullOrWhiteSpace($Device.deviceId)) {
            $ByDeviceId[$Device.deviceId] = $Device
        }
        if (-not [string]::IsNullOrWhiteSpace($Device.id)) {
            $ByObjectId[$Device.id] = $Device
        }
    }

    return [pscustomobject]@{
        ByDeviceId = $ByDeviceId
        ByObjectId = $ByObjectId
        Value      = $Response.value
    }
}

function Get-IntuneDevices {
    param([string]$ApiVersion)

    $Uri = "https://graph.microsoft.com/$ApiVersion/deviceManagement/managedDevices/?`$select=id,deviceName,azureADDeviceId,serialNumber,manufacturer,model,userId,lastSyncDateTime&`$filter=(operatingSystem eq 'Windows')"
    $Response = Invoke-MgGraphRequest -Uri $Uri -ErrorAction Stop
    if ($Response.'@odata.nextLink') {
        $Response = Get-nextLinkData -OriginalObject $Response
    }

    $ByAzureId = @{}
    $BySerial = @{}
    foreach ($Device in $Response.value) {
        if (-not [string]::IsNullOrWhiteSpace($Device.azureADDeviceId)) {
            $ByAzureId[$Device.azureADDeviceId] = $Device
        }
        if (-not [string]::IsNullOrWhiteSpace($Device.serialNumber)) {
            $BySerial[$Device.serialNumber.Trim()] = $Device
        }
    }

    return [pscustomobject]@{
        ByAzureId = $ByAzureId
        BySerial  = $BySerial
        Value     = $Response.value
    }
}

function Get-Users {
    param([string]$ApiVersion)

    $Uri = "https://graph.microsoft.com/$ApiVersion/users/?`$select=id,displayName,mail,userPrincipalName"
    $Response = Invoke-MgGraphRequest -Uri $Uri -ErrorAction Stop
    if ($Response.'@odata.nextLink') {
        $Response = Get-nextLinkData -OriginalObject $Response
    }

    $Lookup = @{}
    foreach ($User in $Response.value) {
        $Lookup[$User.id] = $User
    }

    return $Lookup
}

function Get-IntuneCleanupAction {
    param(
        [object]$IntuneDevice
    )

    if (-not $IntuneDevice) { return 'Not Found' }
    if (-not $IntuneDevice.lastSyncDateTime) { return 'Retain' }

    try {
        $LastSync = [datetime]$IntuneDevice.lastSyncDateTime
    }
    catch {
        return 'Retain'
    }

    if ($LastSync -le $Script:DeleteDate) { return $Script:IntuneDeviceDeleteAction }
    if ($LastSync -le $Script:DisableDate) { return $Script:IntuneDeviceDisableAction }
    return 'Retain'
}

function Get-EntraCleanupAction {
    param(
        [object]$EntraDevice
    )

    if (-not $EntraDevice) { return 'Not Found' }
    if (-not $EntraDevice.approximateLastSignInDateTime) {
        if ($EntraDevice.accountEnabled -eq $false) { return 'Disabled' }
        return 'Retain'
    }

    try {
        $LastSignIn = [datetime]$EntraDevice.approximateLastSignInDateTime
    }
    catch {
        if ($EntraDevice.accountEnabled -eq $false) { return 'Disabled' }
        return 'Retain'
    }

    if ($LastSignIn -le $Script:DeleteDate) { return $Script:EntraDeviceDeleteAction }
    if ($LastSignIn -le $Script:DisableDate) {
        if ($EntraDevice.accountEnabled -eq $false) { return 'Disabled' }
        return $Script:EntraDeviceDisableAction
    }

    if ($EntraDevice.accountEnabled -eq $false) { return 'Disabled' }
    return 'Retain'
}

function Initialize-CleanupPlan {
    param(
        [hashtable]$AutopilotDevices,
        [hashtable]$EntraByDeviceId,
        [hashtable]$IntuneBySerial,
        [hashtable]$Users,
        [hashtable]$CSVSerialMap
    )

    $Plan = [System.Collections.ArrayList]::new()
    foreach ($Device in $AutopilotDevices.Values) {
        $Serial = if ($Device.serialNumber) { $Device.serialNumber.Trim() } else { $null }
        $AutopilotEID = $Device.azureAdDeviceId
        $EntraFromAutopilot = if ($AutopilotEID) { $EntraByDeviceId[$AutopilotEID] } else { $null }
        $IntuneDevice = if ($Serial) { $IntuneBySerial[$Serial] } else { $null }

        $CsvMarkedForRemoval = $false
        if ($CSVSerialMap -and $Serial -and $CSVSerialMap.ContainsKey($Serial)) {
            $CsvMarkedForRemoval = $true
        }

        $AutopilotAction = if ($CsvMarkedForRemoval) { 'Remove' } else { 'Retain' }
        $AutopilotEntraAction = Get-EntraCleanupAction -EntraDevice $EntraFromAutopilot
        $IntuneAction = if ($IntuneDevice) { Get-IntuneCleanupAction -IntuneDevice $IntuneDevice } else { 'Not Found' }

        $EntraFromIntune = $null
        $IntuneEntraAction = 'Not Applicable'
        if ($IntuneDevice -and $IntuneDevice.azureADDeviceId) {
            $EntraFromIntune = $EntraByDeviceId[$IntuneDevice.azureADDeviceId]
            $IntuneEntraAction = Get-EntraCleanupAction -EntraDevice $EntraFromIntune
        }

        $SameEntraObject = $false
        if ($EntraFromAutopilot -and $EntraFromIntune) {
            $SameEntraObject = ($EntraFromAutopilot.deviceId -eq $EntraFromIntune.deviceId)
        }

        $Plan.Add([pscustomobject]@{
                SerialNumber                     = $Serial
                AutopilotDisplayName             = $Device.displayName
                AutopilotObjectId                = $Device.id
                IntuneDeviceId                   = if ($IntuneDevice) { $IntuneDevice.id } else { $null }
                IntuneLastSync                   = if ($IntuneDevice) { $IntuneDevice.lastSyncDateTime } else { $null }
                EntraDeviceIdFromAutopilot       = if ($EntraFromAutopilot) { $EntraFromAutopilot.deviceId } else { $null }
                EntraDisplayNameFromAutopilot    = if ($EntraFromAutopilot) { $EntraFromAutopilot.displayName } else { $null }
                EntraDeviceIdFromIntune          = if ($EntraFromIntune) { $EntraFromIntune.deviceId } else { $null }
                SameEntraObject                  = $SameEntraObject
                AutopilotAction                  = $AutopilotAction
                IntuneAction                     = $IntuneAction
                EntraActionFromAutopilot         = $AutopilotEntraAction
                EntraActionFromIntune            = $IntuneEntraAction
                CsvMarkedForRemoval              = $CsvMarkedForRemoval
                IntunePrimaryUser                = if ($IntuneDevice -and $IntuneDevice.userId -and $Users.ContainsKey($IntuneDevice.userId)) { $Users[$IntuneDevice.userId].DisplayName } else { $null }
                IntunePrimaryUserUPN             = if ($IntuneDevice -and $IntuneDevice.userId -and $Users.ContainsKey($IntuneDevice.userId)) { $Users[$IntuneDevice.userId].UserPrincipalName } else { $null }
            }) | Out-Null
    }

    return $Plan
}


function Invoke-DeviceCleanup {
    param(
        [System.Collections.ArrayList]$Plan,
        [switch]$AllowChanges
    )

    foreach ($Item in $Plan) {
        if ($Item.IntuneAction -eq 'Retire' -and $Item.IntuneDeviceId) {
            if (-not $AllowChanges) {
                Write-RunbookLog -Message "DRY RUN: would retire Intune device $($Item.IntuneDeviceId) for serial $($Item.SerialNumber)" -Component 'Cleanup' -Type 2
            }
            else {
                Write-RunbookLog -Message "Retiring Intune device $($Item.IntuneDeviceId) for serial $($Item.SerialNumber)" -Component 'Cleanup'
                try {
                    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/$TenantAPIToUse/deviceManagement/managedDevices/$($Item.IntuneDeviceId)/retire" -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RunbookLog -Message "Failed to retire Intune device $($Item.IntuneDeviceId): $($_.Exception.Message)" -Component 'Cleanup' -Type 3
                }
            }
        }

        if ($Item.IntuneAction -eq 'Remove' -and $Item.IntuneDeviceId) {
            if (-not $AllowChanges) {
                Write-RunbookLog -Message "DRY RUN: would remove Intune device $($Item.IntuneDeviceId) for serial $($Item.SerialNumber)" -Component 'Cleanup' -Type 2
            }
            else {
                Write-RunbookLog -Message "Removing Intune device $($Item.IntuneDeviceId) for serial $($Item.SerialNumber)" -Component 'Cleanup'
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/$TenantAPIToUse/deviceManagement/managedDevices/$($Item.IntuneDeviceId)" -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RunbookLog -Message "Failed to remove Intune device $($Item.IntuneDeviceId): $($_.Exception.Message)" -Component 'Cleanup' -Type 3
                }
            }
        }

        if ($Item.EntraActionFromAutopilot -eq 'Disable' -and $Item.EntraDeviceIdFromAutopilot) {
            if (-not $AllowChanges) {
                Write-RunbookLog -Message "DRY RUN: would disable Entra device $($Item.EntraDeviceIdFromAutopilot) for serial $($Item.SerialNumber)" -Component 'Cleanup' -Type 2
            }
            else {
                Write-RunbookLog -Message "Disabling Entra device $($Item.EntraDeviceIdFromAutopilot) for serial $($Item.SerialNumber)" -Component 'Cleanup'
                try {
                    $ObjectId = (Get-EntraDevices -ApiVersion $TenantAPIToUse).ByDeviceId[$Item.EntraDeviceIdFromAutopilot].id
                    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/$TenantAPIToUse/devices/$ObjectId" -Body (@{ accountEnabled = $false } | ConvertTo-Json -Depth 10) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RunbookLog -Message "Failed to disable Entra device $($Item.EntraDeviceIdFromAutopilot): $($_.Exception.Message)" -Component 'Cleanup' -Type 3
                }
            }
        }

        if ($Item.EntraActionFromAutopilot -eq 'Remove' -and $Item.EntraDeviceIdFromAutopilot) {
            if (-not $AllowChanges) {
                Write-RunbookLog -Message "DRY RUN: would remove Entra device $($Item.EntraDeviceIdFromAutopilot) for serial $($Item.SerialNumber)" -Component 'Cleanup' -Type 2
            }
            else {
                Write-RunbookLog -Message "Removing Entra device $($Item.EntraDeviceIdFromAutopilot) for serial $($Item.SerialNumber)" -Component 'Cleanup'
                try {
                    $ObjectId = (Get-EntraDevices -ApiVersion $TenantAPIToUse).ByDeviceId[$Item.EntraDeviceIdFromAutopilot].id
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/$TenantAPIToUse/devices/$ObjectId" -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RunbookLog -Message "Failed to remove Entra device $($Item.EntraDeviceIdFromAutopilot): $($_.Exception.Message)" -Component 'Cleanup' -Type 3
                }
            }
        }

        if ($Item.AutopilotAction -eq 'Remove' -and $Item.AutopilotObjectId) {
            if (-not $AllowChanges) {
                Write-RunbookLog -Message "DRY RUN: would remove Autopilot object $($Item.AutopilotObjectId) for serial $($Item.SerialNumber)" -Component 'Cleanup' -Type 2
            }
            else {
                Write-RunbookLog -Message "Removing Autopilot object $($Item.AutopilotObjectId) for serial $($Item.SerialNumber)" -Component 'Cleanup'
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/$TenantAPIToUse/deviceManagement/windowsAutopilotDeviceIdentities/$($Item.AutopilotObjectId)" -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-RunbookLog -Message "Failed to remove Autopilot object $($Item.AutopilotObjectId): $($_.Exception.Message)" -Component 'Cleanup' -Type 3
                }
            }
        }
    }
}

Write-RunbookLog -Message "Starting Broken Autopilot Device Cleanup runbook." -Component 'Main'
try {
    Connect-RunbookGraph
    Initialize-Script

    $ExecutionMode = 'Scheduled'
    if ($DryRun) {
        $ExecutionMode = 'DryRun'
    }

    Write-RunbookLog -Message "Execution mode: $ExecutionMode" -Component 'Main'

    $CsvSerialList = @{}
    $IncomingSerials = Get-WebhookSerialNumbers -Payload $WebhookData
    if ($IncomingSerials.Count -gt 0) {
        foreach ($Serial in $IncomingSerials) {
            $CsvSerialList[$Serial.Trim()] = $true
        }
        Write-RunbookLog -Message "Loaded $($CsvSerialList.Count) serials from webhook input." -Component 'Main'
    }
    else {
        Write-RunbookLog -Message "No serials were found in the incoming webhook payload." -Component 'Main' -Type 2
    }

    $AutopilotLookup = Get-AutopilotDevices -ApiVersion $TenantAPIToUse
    $EntraData = Get-EntraDevices -ApiVersion $TenantAPIToUse
    $IntuneData = Get-IntuneDevices -ApiVersion $TenantAPIToUse
    $Users = Get-Users -ApiVersion $TenantAPIToUse

    $Plan = Initialize-CleanupPlan -AutopilotDevices $AutopilotLookup -EntraByDeviceId $EntraData.ByDeviceId -IntuneBySerial $IntuneData.BySerial -Users $Users -CSVSerialMap $CsvSerialList

    $Actionable = $Plan | Where-Object {
        $_.AutopilotAction -ne 'Retain' -or
        $_.IntuneAction -ne 'Retain' -or
        $_.EntraActionFromAutopilot -ne 'Retain' -or
        $_.EntraActionFromIntune -ne 'Retain'
    }

    $Actionable | Format-Table -AutoSize | Out-String | Write-Host

    if (-not $EnableCleanup) {
        Write-RunbookLog -Message "Analysis completed. Cleanup was not requested. $($Actionable.Count) actionable devices were identified." -Component 'Main'
        exit 0
    }

    if ($DryRun) {
        Write-RunbookLog -Message "Dry-run enabled. No Microsoft Graph changes will be submitted." -Component 'Main' -Type 2
    }

    Write-RunbookLog -Message "Cleanup requested. Processing $($Actionable.Count) actionable devices." -Component 'Main'
    Invoke-DeviceCleanup -Plan $Actionable -AllowChanges:(-not $DryRun)
    Write-RunbookLog -Message 'Cleanup processing finished.' -Component 'Main'
    exit 0
}
catch {
    Write-RunbookLog -Message "Runbook failed: $($_.Exception.Message)" -Component 'Main' -Type 3
    exit 1
}
