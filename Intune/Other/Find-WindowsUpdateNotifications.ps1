[CmdletBinding()]
param(
    [string[]]$InputPath = @('C:\ProgramData\USOShared\Logs\User'),
    [string]$OutputPath,
    [switch]$IncludeRawEvents,
    [switch]$TestRun,
    [switch]$SkipElevation,
    [switch]$HideReport,
    [string[]]$UpdateStatusFilter,
    [switch]$IncludeSamAccountName,
    [int]$SessionLookbackDays = 30,
    [int]$SessionCorrelationWindowMinutes = 240,
    [int]$RestartCorrelationWindowMinutes = 120,
    [int]$AttemptSplitGapMinutes = 15,
    [int]$InstallResultCorrelationWindowMinutes = 720
)

function Test-IsAdministrator {
    if (-not $IsWindows) {
        return $false
    }

    $WindowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $WindowsPrincipal = [Security.Principal.WindowsPrincipal]::new($WindowsIdentity)
    return $WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedTestRun {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BoundParameters
    )

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'Unable to relaunch script with elevation because script path is unknown.'
    }

    $HostExecutable = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $ArgumentList = [System.Collections.Generic.List[string]]::new()
    $ArgumentList.Add('-NoProfile')
    $ArgumentList.Add('-ExecutionPolicy')
    $ArgumentList.Add('Bypass')
    $ArgumentList.Add('-File')
    $ArgumentList.Add($PSCommandPath)

    foreach ($Entry in $BoundParameters.GetEnumerator()) {
        $Name = [string]$Entry.Key
        $Value = $Entry.Value

        if ($Name -in @('SkipElevation')) {
            continue
        }

        if ($Value -is [switch]) {
            if ($Value.IsPresent) {
                $ArgumentList.Add("-$Name")
            }
            continue
        }

        if ($null -eq $Value) {
            continue
        }

        if ($Value -is [System.Array]) {
            foreach ($ArrayItem in $Value) {
                $ArgumentList.Add("-$Name")
                $ArgumentList.Add([string]$ArrayItem)
            }
            continue
        }

        $ArgumentList.Add("-$Name")
        $ArgumentList.Add([string]$Value)
    }

    if (-not $ArgumentList.Contains('-TestRun')) {
        $ArgumentList.Add('-TestRun')
    }

    $ArgumentList.Add('-SkipElevation')

    Write-Host 'Starting elevated test run for local Security log correlation...' -ForegroundColor Yellow
    $Process = Start-Process -FilePath $HostExecutable -ArgumentList $ArgumentList -Verb RunAs -Wait -PassThru
    exit $Process.ExitCode
}

function ConvertTo-HumanReadableUpdateRows {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Updates,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSamAccountName
    )

    return @(
        foreach ($Update in $Updates) {
            $StatusSummary = if ($Update.UpdateStatusValues.Count -gt 0) {
                ($Update.UpdateStatusValues -join '; ')
            } else {
                'NoStatusSignal'
            }

            $AttentionSummary = if ($Update.AttentionReasons.Count -gt 0) {
                ($Update.AttentionReasons -join '; ')
            } else {
                'NoAttentionSignal'
            }

            $NotificationConfidence = if ($Update.NotificationConfidence) {
                $Update.NotificationConfidence
            } else {
                'Unknown'
            }

            $NotificationDisplayed = if ($Update.NotificationDisplayedState) {
                $Update.NotificationDisplayedState
            } else {
                'Unknown'
            }

            $NotificationType = if ($Update.NotificationType) {
                $Update.NotificationType
            } else {
                'Unknown'
            }

            $UpdateSuccessfulDisplay = switch ($Update.UpdateSuccessful) {
                'Yes' { '✅' }
                'No' { '❌' }
                default { '❔' }
            }

            $InstallEvidenceDisplay = switch ($Update.InstallEvidenceFromWUClient) {
                'Installed' { '✅ Installed (WUClient)' }
                'Failed' { '❌ Failed (WUClient)' }
                'Seen' { '🟨 Seen (WUClient)' }
                'NoKbMatch' { 'No KB Match (WUClient)' }
                default { 'No Evidence (WUClient)' }
            }

            [PSCustomObject]@{
                AttemptNumber         = $Update.AttemptNumber
                FirstSeen             = $Update.FirstSeen
                LastSeen              = $Update.LastSeen
                Title                 = $Update.Title
                UpdateSuccessful      = $UpdateSuccessfulDisplay
                InstallEvidenceFromWUClient = $InstallEvidenceDisplay
                InstallEvidenceAt     = $Update.InstallEvidenceAt
                NotificationType      = $NotificationType
                NotificationDisplayed = $NotificationDisplayed
                NotificationAt        = $Update.NotificationDisplayedAt
                NotificationNotShownAt = $Update.NotificationNotShownAt
                NotificationNotShownSignal = $Update.NotificationNotShownSignal
                NotificationNotProcessedReason = $Update.NotificationNotProcessedReason
                SessionLockStateAtNotification = $Update.SessionLockStateAtNotification
                NotificationConfidence = $NotificationConfidence
                ExclusivityInterpretation = $Update.ExclusivityInterpretation
                UpdateSuccessAt       = $Update.UpdateSuccessSignalAt
                UpdateSuccessSignalType = $Update.UpdateSuccessSignalType
                ClickedByUser         = if ($Update.UserClickedAt) { 'Yes' } else { 'No' }
                ClickAt               = $Update.UserClickedAt
                ClickSignal           = $Update.ClickSignal
                RelatedRestart        = $Update.RelatedRestart
                RelatedRestartAt      = $Update.RestartEventAt
                UserName              = $Update.UserName
                UserPrincipal         = $Update.UserPrincipal
                UserSid               = $Update.UserSid
                SamAccountName        = if ($IncludeSamAccountName) { $Update.SamAccountName } else { $null }
                UpdateStatusSummary   = $StatusSummary
                AttentionSummary      = $AttentionSummary
                EventCount            = $Update.EventCount
            }
        }
    )
}

function Show-HumanReadableReport {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows
    )

    if (-not $Rows -or $Rows.Count -eq 0) {
        Write-Warning 'No updates were parsed to display in the report.'
        return
    }

    $OutGridViewCommand = Get-Command Out-GridView -ErrorAction SilentlyContinue
    if ($OutGridViewCommand) {
        $Rows | Out-GridView -Title 'Windows Update Notification Correlation Report'
        return
    }

    $Rows | Sort-Object -Property NotificationAt, FirstSeen -Descending | Format-Table -AutoSize | Out-Host
}

function Get-LocalRegistryUserIdentities {
    $Identities = [System.Collections.Generic.List[object]]::new()

    $ComputerSystemUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    if (-not [string]::IsNullOrWhiteSpace($ComputerSystemUser)) {
        $Sam = $ComputerSystemUser.Split('\')[-1]
        $Identities.Add([PSCustomObject]@{
            Sid            = $null
            UserPrincipal  = $ComputerSystemUser
            SamAccountName = $Sam
            Source         = 'ComputerSystem'
        })
    }

    $SidPattern = '^S-1-(5-21|12-1)-'
    $HkuKeys = Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSChildName -match $SidPattern -and $_.PSChildName -notmatch '_Classes$'
        }

    foreach ($HkuKey in $HkuKeys) {
        $SidValue = $HkuKey.PSChildName
        $UserPrincipal = $null
        try {
            $SecurityIdentifier = [Security.Principal.SecurityIdentifier]::new($SidValue)
            $UserPrincipal = $SecurityIdentifier.Translate([Security.Principal.NTAccount]).Value
        } catch {
            $UserPrincipal = $null
        }

        $VolatileEnvironmentPath = "Registry::HKEY_USERS\$SidValue\Volatile Environment"
        $VolatileEnvironment = Get-ItemProperty -LiteralPath $VolatileEnvironmentPath -ErrorAction SilentlyContinue
        if ($VolatileEnvironment -and $VolatileEnvironment.USERNAME) {
            $DomainPart = if ($VolatileEnvironment.USERDOMAIN) { $VolatileEnvironment.USERDOMAIN } else { $env:COMPUTERNAME }
            $UserPrincipal = "$DomainPart\$($VolatileEnvironment.USERNAME)"
        }

        $Sam = $null
        if (-not [string]::IsNullOrWhiteSpace($UserPrincipal)) {
            $Sam = $UserPrincipal.Split('\')[-1]
        }

        $Identities.Add([PSCustomObject]@{
            Sid            = $SidValue
            UserPrincipal  = $UserPrincipal
            SamAccountName = $Sam
            Source         = 'Registry'
        })
    }

    return @(
        $Identities |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.Sid) -or -not [string]::IsNullOrWhiteSpace($_.UserPrincipal) } |
            Sort-Object -Property Source, UserPrincipal, Sid -Unique
    )
}

function Test-UpdateStatusMatch {
    param(
        [Parameter(Mandatory = $true)]
        $Update,
        [Parameter(Mandatory = $false)]
        [string[]]$StatusFilter
    )

    if (-not $StatusFilter -or $StatusFilter.Count -eq 0) {
        return $true
    }

    $Values = @($Update.UpdateStatusValues | Where-Object { $_ })
    if ($Values.Count -eq 0) {
        return $false
    }

    foreach ($Filter in $StatusFilter) {
        if ([string]::IsNullOrWhiteSpace($Filter)) {
            continue
        }

        foreach ($Value in $Values) {
            if ($Value -like $Filter -or $Value -eq $Filter) {
                return $true
            }
        }
    }

    return $false
}

function ConvertFrom-FileTimeToLocalDateTime {
    param(
        [Parameter(Mandatory = $true)]
        [long]$FileTime
    )

    return ([datetime]::SpecifyKind([datetime]'1601-01-01', [System.DateTimeKind]::Utc).AddTicks($FileTime)).ToLocalTime()
}

if ($TestRun -and -not $SkipElevation -and $IsWindows -and -not (Test-IsAdministrator)) {
    Start-ElevatedTestRun -BoundParameters $PSBoundParameters
}

function Get-XmlNodeText {
    param(
        [Parameter(Mandatory = $false)]
        $Node
    )

    if ($null -eq $Node) {
        return $null
    }

    if ($Node -is [string]) {
        return $Node
    }

    if ($null -ne $Node.'#text') {
        return [string]$Node.'#text'
    }

    if ($null -ne $Node.InnerText) {
        return [string]$Node.InnerText
    }

    return [string]$Node
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory = $false)]
        $EventRecordXml
    )

    $EventDataMap = @{}
    $DataNodes = @($EventRecordXml.EventData.Data)

    foreach ($DataNode in $DataNodes) {
        if ($null -eq $DataNode) {
            continue
        }

        $DataName = if ($null -ne $DataNode.Name) { [string]$DataNode.Name } elseif ($null -ne $DataNode.name) { [string]$DataNode.name } else { $null }
        if ([string]::IsNullOrWhiteSpace($DataName)) {
            continue
        }

        $EventDataMap[$DataName] = Get-XmlNodeText -Node $DataNode
    }

    return $EventDataMap
}

function Get-EventTimestamp {
    param(
        [Parameter(Mandatory = $false)]
        $EventRecordXml
    )

    $TimeCreated = $null

    if ($EventRecordXml.System.TimeCreated.SystemTime) {
        $TimeCreated = $EventRecordXml.System.TimeCreated.SystemTime
    } elseif ($EventRecordXml.TimeCreated.SystemTime) {
        $TimeCreated = $EventRecordXml.TimeCreated.SystemTime
    } elseif ($EventRecordXml.System.TimeCreated.'#text') {
        $TimeCreated = $EventRecordXml.System.TimeCreated.'#text'
    }

    if ([string]::IsNullOrWhiteSpace([string]$TimeCreated)) {
        return $null
    }

    try {
        return ([datetime]::Parse([string]$TimeCreated, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToLocalTime()
    } catch {
        return $null
    }
}

function ConvertTo-NullableInt {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [int]$Value
    } catch {
        return $null
    }
}

function Get-EventPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord,
        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    if ($EventRecord.Properties.Count -le $Index) {
        return $null
    }

    return $EventRecord.Properties[$Index].Value
}

function Import-NotificationXml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Input path not found: $Path"
    }

    $ResolvedItem = Get-Item -LiteralPath $Path

    if ($ResolvedItem.PSIsContainer) {
        throw "Expected a file path, not a directory: $Path"
    }

    if ($ResolvedItem.Extension -ieq '.etl') {
        $Tracerpt = Get-Command tracerpt -ErrorAction SilentlyContinue
        if (-not $Tracerpt) {
            throw 'tracerpt is required to convert ETL files to XML on this system.'
        }

        $TempXmlPath = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid().ToString() + '.xml')
        & tracerpt $ResolvedItem.FullName -o $TempXmlPath -of XML -LR | Out-Null

        if (-not (Test-Path -LiteralPath $TempXmlPath)) {
            throw "tracerpt did not produce XML output for $Path"
        }

        try {
            return [xml](Get-Content -LiteralPath $TempXmlPath -Raw)
        } finally {
            Remove-Item -LiteralPath $TempXmlPath -Force -ErrorAction SilentlyContinue
        }
    }

    return [xml](Get-Content -LiteralPath $ResolvedItem.FullName -Raw)
}

function Get-NotificationSourceFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    $Files = foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) {
            $Item = Get-Item -LiteralPath $Path
            if ($Item.PSIsContainer) {
                Get-ChildItem -LiteralPath $Item.FullName -File |
                    Where-Object {
                        $_.Name -like 'UpdateUx*.etl' -or
                        $_.Name -like 'MoNotifications*.etl' -or
                        $_.Extension -ieq '.xml'
                    } |
                    Sort-Object -Property FullName
            } else {
                $Item
            }
        }
    }

    return @($Files | Where-Object { $_.Extension -match '\.(etl|xml)$' } | Sort-Object -Property LastWriteTime, FullName)
}

function Get-LocalUserSessions {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,
        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    $t1 = $StartTime.ToUniversalTime().ToString('s')
    $t2 = $EndTime.ToUniversalTime().ToString('s')
    $FilterXPath = "*[System[TimeCreated[@SystemTime>'$t1' and @SystemTime<'$t2'] and (EventID=4624 or EventID=4634 or EventID=4647)]]"

    try {
        $SecurityEvents = Get-WinEvent -LogName 'Security' -FilterXPath $FilterXPath -ErrorAction Stop | Sort-Object -Property TimeCreated
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return [object[]]@()
        }
        Write-Warning "Failed to query Security event log for session correlation. $_"
        return [object[]]@()
    }

    $RelevantLogonTypes = @(2, 7, 10, 11)
    $OpenSessions = @{}
    $ClosedSessions = [System.Collections.Generic.List[object]]::new()

    foreach ($SecurityEvent in $SecurityEvents) {
        $UserName = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 5)
        $Domain = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 6)
        $Sid = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 4)
        $LogonId = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 7)
        $LogonType = ConvertTo-NullableInt -Value (Get-EventPropertyValue -EventRecord $SecurityEvent -Index 8)
        $LogonProcess = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 9)
        $AuthenticationPackage = [string](Get-EventPropertyValue -EventRecord $SecurityEvent -Index 10)

        if ([string]::IsNullOrWhiteSpace($LogonId)) {
            continue
        }

        if ($SecurityEvent.Id -eq 4624) {
            if ($RelevantLogonTypes -notcontains $LogonType) {
                continue
            }

            $SessionKey = "$LogonId|$UserName|$Domain"
            $OpenSessions[$SessionKey] = [PSCustomObject]@{
                SessionKey             = $SessionKey
                LogonId                = $LogonId
                UserName               = $UserName
                Domain                 = $Domain
                UserPrincipal          = if ([string]::IsNullOrWhiteSpace($Domain)) { $UserName } else { "$Domain\$UserName" }
                Sid                    = $Sid
                LogonType              = $LogonType
                LogonTypeLabel         = switch ($LogonType) {
                    2 { 'Interactive' }
                    7 { 'Unlock' }
                    10 { 'RemoteInteractive' }
                    11 { 'CachedInteractive' }
                    default { 'Other' }
                }
                SessionStart           = $SecurityEvent.TimeCreated
                SessionEnd             = $null
                LogonProcess           = $LogonProcess
                AuthenticationPackage  = $AuthenticationPackage
                StartEventId           = $SecurityEvent.Id
                EndEventId             = $null
            }
            continue
        }

        $Match = $OpenSessions.GetEnumerator() | Where-Object {
            $_.Value.LogonId -eq $LogonId -and $_.Value.UserName -eq $UserName -and $_.Value.Domain -eq $Domain
        } | Select-Object -First 1

        if ($null -eq $Match) {
            continue
        }

        $Session = $Match.Value
        $Session.SessionEnd = $SecurityEvent.TimeCreated
        $Session.EndEventId = $SecurityEvent.Id
        $ClosedSessions.Add($Session)
        $OpenSessions.Remove($Match.Key)
    }

    foreach ($Session in $OpenSessions.Values) {
        $ClosedSessions.Add($Session)
    }

    return [object[]]@($ClosedSessions | Sort-Object -Property SessionStart, SessionEnd)
}

function Get-LocalRestartEvents {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,
        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    $t1 = $StartTime.ToUniversalTime().ToString('s')
    $t2 = $EndTime.ToUniversalTime().ToString('s')
    $FilterXPath = "*[System[TimeCreated[@SystemTime>'$t1' and @SystemTime<'$t2'] and (EventID=1074 or EventID=1076 or EventID=6005 or EventID=6006 or EventID=6008)]]"

    try {
        $RestartEvents = Get-WinEvent -LogName 'System' -FilterXPath $FilterXPath -ErrorAction Stop | Sort-Object -Property TimeCreated
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return [object[]]@()
        }
        Write-Warning "Failed to query System event log for restart correlation. $_"
        return [object[]]@()
    }

    return [object[]]@(
        foreach ($RestartEvent in $RestartEvents) {
            $Classification = switch ($RestartEvent.Id) {
                1074 { 'RestartInitiated' }
                1076 { 'UnexpectedShutdownReasonCaptured' }
                6005 { 'EventLogStarted' }
                6006 { 'CleanShutdown' }
                6008 { 'UnexpectedShutdown' }
                default { 'Other' }
            }

            [PSCustomObject]@{
                Timestamp      = $RestartEvent.TimeCreated
                EventId        = $RestartEvent.Id
                ProviderName   = $RestartEvent.ProviderName
                Classification = $Classification
                Message        = $RestartEvent.FormatDescription()
            }
        }
    )
}

function Get-LocalUpdateClientEvents {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,
        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    $t1 = $StartTime.ToUniversalTime().ToString('s')
    $t2 = $EndTime.ToUniversalTime().ToString('s')
    $FilterXPath = "*[System[TimeCreated[@SystemTime>'$t1' and @SystemTime<'$t2'] and Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=20 or EventID=43 or EventID=44)]]"

    try {
        $ClientEvents = Get-WinEvent -LogName 'System' -FilterXPath $FilterXPath -ErrorAction Stop | Sort-Object -Property TimeCreated
    } catch {
        return [object[]]@()
    }

    return [object[]]@(
        foreach ($ClientEvent in $ClientEvents) {
            $Message = $ClientEvent.FormatDescription()
            $KbMatches = [System.Text.RegularExpressions.Regex]::Matches($Message, 'KB\d{6,8}')
            $KbArticles = @($KbMatches | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
            $TitleMatch = [System.Text.RegularExpressions.Regex]::Match($Message, 'following update:\s*(.+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $UpdateTitleFromMessage = if ($TitleMatch.Success) { $TitleMatch.Groups[1].Value.Trim() } else { $null }

            $Outcome = switch ($ClientEvent.Id) {
                19 { 'Success' }
                20 { 'Failure' }
                43 { 'Success' }
                44 { 'Failure' }
                default { 'Unknown' }
            }

            [PSCustomObject]@{
                Timestamp   = $ClientEvent.TimeCreated
                EventId     = $ClientEvent.Id
                Outcome     = $Outcome
                KbArticles  = $KbArticles
                UpdateTitle = $UpdateTitleFromMessage
                Message     = $Message
            }
        }
    )
}

function Get-NormalizedUpdateEvidenceTitle {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Title
    )

    if ([string]::IsNullOrWhiteSpace($Title)) {
        return $null
    }

    $Normalized = $Title.ToLowerInvariant()
    $Normalized = $Normalized -replace 'corporation', ''
    $Normalized = $Normalized -replace '[^a-z0-9\. ]', ' '
    $Normalized = $Normalized -replace '\s+', ' '
    return $Normalized.Trim()
}

function Get-LocalLockStateEvents {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,
        [Parameter(Mandatory = $true)]
        [datetime]$EndTime
    )

    $t1 = $StartTime.ToUniversalTime().ToString('s')
    $t2 = $EndTime.ToUniversalTime().ToString('s')
    $FilterXPath = "*[System[TimeCreated[@SystemTime>'$t1' and @SystemTime<'$t2'] and (EventID=4800 or EventID=4801)]]"

    try {
        $LockEvents = Get-WinEvent -LogName 'Security' -FilterXPath $FilterXPath -ErrorAction Stop | Sort-Object -Property TimeCreated
    } catch {
        if ($_.Exception.Message -match 'No events were found') {
            return [object[]]@()
        }
        return [object[]]@()
    }

    return [object[]]@(
        foreach ($LockEvent in $LockEvents) {
            [PSCustomObject]@{
                Timestamp = $LockEvent.TimeCreated
                EventId   = $LockEvent.Id
                State     = if ($LockEvent.Id -eq 4800) { 'Locked' } else { 'Unlocked' }
            }
        }
    )
}

function Get-LockStateAtTimestamp {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$LockEvents
    )

    if ($null -eq $Timestamp -or -not $LockEvents -or $LockEvents.Count -eq 0) {
        return 'Unknown'
    }

    $LastLockStateEvent = @(
        $LockEvents |
            Where-Object { $_.Timestamp -le $Timestamp } |
            Sort-Object -Property Timestamp -Descending
    ) | Select-Object -First 1

    if ($null -eq $LastLockStateEvent) {
        return 'Unknown'
    }

    return $LastLockStateEvent.State
}

function Get-SignedInSessionsAtTimestamp {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$Sessions,
        [Parameter(Mandatory = $false)]
        [object[]]$LockEvents
    )

    if ($null -eq $Timestamp -or -not $Sessions -or $Sessions.Count -eq 0) {
        return [object[]]@()
    }

    $LockStateAtTimestamp = Get-LockStateAtTimestamp -Timestamp $Timestamp -LockEvents $LockEvents
    if ($LockStateAtTimestamp -eq 'Locked') {
        return [object[]]@()
    }

    $ActiveSessions = @(
        $Sessions |
            Where-Object {
                $_.SessionStart -le $Timestamp -and
                ($null -eq $_.SessionEnd -or $_.SessionEnd -gt $Timestamp)
            } |
            Sort-Object -Property SessionStart -Descending
    )

    if ($ActiveSessions.Count -eq 0) {
        return [object[]]@()
    }

    $SeenUsers = @{}
    $DistinctSessions = [System.Collections.Generic.List[object]]::new()

    foreach ($Session in $ActiveSessions) {
        $UserKey = if (-not [string]::IsNullOrWhiteSpace($Session.Sid)) {
            "sid:$($Session.Sid)"
        } elseif (-not [string]::IsNullOrWhiteSpace($Session.UserPrincipal)) {
            "principal:$($Session.UserPrincipal.ToLowerInvariant())"
        } else {
            "name:$($Session.Domain)\\$($Session.UserName)"
        }

        if (-not $SeenUsers.ContainsKey($UserKey)) {
            $SeenUsers[$UserKey] = $true
            $DistinctSessions.Add($Session)
        }
    }

    return [object[]]@($DistinctSessions)
}

function Get-NotificationConfidence {
    param(
        [Parameter(Mandatory = $false)]
        [string]$NotificationDisplayed,
        [Parameter(Mandatory = $false)]
        [string]$NotificationNotShownSignal,
        [Parameter(Mandatory = $false)]
        [string]$NotificationProcessedReason,
        [Parameter(Mandatory = $false)]
        [string]$NotificationNotProcessedReason,
        [Parameter(Mandatory = $false)]
        [string]$SessionLockStateAtNotification,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$UserClickedAt
    )

    if ($UserClickedAt) {
        return 'High'
    }

    if ($NotificationNotShownSignal -eq 'Notification Not Processed') {
        if ($NotificationNotProcessedReason -match 'Initialization Not Complete|Initalization Not Complete') {
            return 'Low'
        }

        return 'Low'
    }

    if ($NotificationDisplayed -eq 'Maybe') {
        if ($NotificationProcessedReason -match 'Update Approval Changed Callback|Update Progress Callback|USO Attention Required Callback') {
            return 'Medium'
        }

        return 'Medium'
    }

    if ($NotificationDisplayed -eq 'Yes') {
        if ($SessionLockStateAtNotification -eq 'Unlocked') {
            return 'High'
        }

        if ($SessionLockStateAtNotification -eq 'Locked') {
            return 'Medium'
        }

        return 'Medium'
    }

    return 'Low'
}

function Get-NotificationType {
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$UpdateStatusValues,
        [Parameter(Mandatory = $false)]
        [string[]]$AttentionReasons,
        [Parameter(Mandatory = $false)]
        [string]$ClickSignal,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DisplayEvent,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$NotProcessedEvent
    )

    $Statuses = @($UpdateStatusValues | Where-Object { $_ } | Select-Object -Unique)
    $Reasons = @($AttentionReasons | Where-Object { $_ } | Select-Object -Unique)

    $IsRestartPrompt = @($Statuses | Where-Object { $_ -match 'RebootRequired|Restart' }).Count -gt 0 -or
        @($Reasons | Where-Object { $_ -eq 'UpdateAttentionRequiredReason_ReadyToReboot' }).Count -gt 0
    if ($IsRestartPrompt) {
        return 'RestartPrompt'
    }

    $IsInstallApprovalPrompt = @($Reasons | Where-Object { $_ -eq 'UpdateAttentionRequiredReason_NeedUserAgreementForPolicy' }).Count -gt 0 -or
        $ClickSignal -in @('UpdateApproved', 'PerUpdateActionTaken', 'SeekerUpdateApprovedForInstall')
    if ($IsInstallApprovalPrompt) {
        return 'InstallApprovalPrompt'
    }

    if ($DisplayEvent) {
        return 'PassiveNotification'
    }

    if ($NotProcessedEvent) {
        return 'NotShown'
    }

    return 'Unknown'
}

function Get-NotificationDisplayedState {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DisplayEvent,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$NotProcessedEvent,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$UserClickedAt,
        [Parameter(Mandatory = $false)]
        [string]$NotificationType,
        [Parameter(Mandatory = $false)]
        [string]$NotificationNotProcessedReason
    )

    if ($UserClickedAt) {
        return 'Yes'
    }

    if ($NotificationType -eq 'RestartPrompt') {
        return 'Yes'
    }

    if ($DisplayEvent -and $NotProcessedEvent) {
        if ($NotificationNotProcessedReason -match 'Initialization Not Complete|Initalization Not Complete') {
            return 'Maybe'
        }

        return 'Maybe'
    }

    if ($DisplayEvent) {
        return 'Yes'
    }

    if ($NotProcessedEvent) {
        return 'No'
    }

    return 'Unknown'
}

function Get-ExclusivityInterpretation {
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$AttentionReasons
    )

    if (-not $AttentionReasons -or $AttentionReasons.Count -eq 0) {
        return 'NotExclusive'
    }

    if (@($AttentionReasons | Where-Object { $_ -eq 'UpdateAttentionRequiredReason_Exclusivity' }).Count -gt 0) {
        return 'DeferredByExclusiveInstall'
    }

    return 'NotExclusive'
}

function Get-KbArticlesFromTitle {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Title
    )

    if ([string]::IsNullOrWhiteSpace($Title)) {
        return @()
    }

    $KbMatches = [System.Text.RegularExpressions.Regex]::Matches($Title, 'KB\d{6,8}')
    return @($KbMatches | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
}

function Get-BestInstallResultMatch {
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$KbArticles,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$FirstSeen,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$LastSeen,
        [Parameter(Mandatory = $false)]
        [object[]]$UpdateClientEvents,
        [int]$CorrelationWindowMinutes = 720
    )

    if (-not $UpdateClientEvents -or $UpdateClientEvents.Count -eq 0) {
        return $null
    }

    if (-not $KbArticles -or $KbArticles.Count -eq 0) {
        return $null
    }

    $WindowStart = if ($FirstSeen) { $FirstSeen.AddMinutes(-30) } else { $LastSeen.AddMinutes(-$CorrelationWindowMinutes) }
    $WindowEnd = if ($LastSeen) { $LastSeen.AddMinutes($CorrelationWindowMinutes) } else { $FirstSeen.AddMinutes($CorrelationWindowMinutes) }

    return @(
        $UpdateClientEvents |
            Where-Object {
                $_.Timestamp -ge $WindowStart -and
                $_.Timestamp -le $WindowEnd -and
                (@($_.KbArticles | Where-Object { $KbArticles -contains $_ }).Count -gt 0)
            } |
            Sort-Object -Property Timestamp -Descending
    ) | Select-Object -First 1
}

function Get-GlobalInstallEvidenceFromUpdateClient {
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$KbArticles,
        [Parameter(Mandatory = $false)]
        [string]$UpdateTitle,
        [Parameter(Mandatory = $false)]
        [object[]]$UpdateClientEvents
    )

    if (-not $UpdateClientEvents -or $UpdateClientEvents.Count -eq 0) {
        return [PSCustomObject]@{
            Status    = 'NoEvidence'
            Timestamp = $null
            EventId   = $null
        }
    }

    $Matches = @()

    if ($KbArticles -and $KbArticles.Count -gt 0) {
        $Matches = @(
            $UpdateClientEvents |
                Where-Object {
                    @($_.KbArticles | Where-Object { $KbArticles -contains $_ }).Count -gt 0
                } |
                Sort-Object -Property Timestamp -Descending
        )
    }

    if ($Matches.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($UpdateTitle)) {
        $NormalizedTargetTitle = Get-NormalizedUpdateEvidenceTitle -Title $UpdateTitle
        if (-not [string]::IsNullOrWhiteSpace($NormalizedTargetTitle)) {
            $Matches = @(
                $UpdateClientEvents |
                    Where-Object {
                        $NormalizedEventTitle = Get-NormalizedUpdateEvidenceTitle -Title $_.UpdateTitle
                        if ([string]::IsNullOrWhiteSpace($NormalizedEventTitle)) {
                            return $false
                        }

                        return $NormalizedEventTitle -eq $NormalizedTargetTitle -or
                            $NormalizedEventTitle.Contains($NormalizedTargetTitle) -or
                            $NormalizedTargetTitle.Contains($NormalizedEventTitle)
                    } |
                    Sort-Object -Property Timestamp -Descending
            )
        }
    }

    if ($Matches.Count -eq 0) {
        return [PSCustomObject]@{
            Status    = 'NoKbMatch'
            Timestamp = $null
            EventId   = $null
        }
    }

    $LatestSuccess = $Matches | Where-Object { $_.Outcome -eq 'Success' } | Select-Object -First 1
    if ($LatestSuccess) {
        return [PSCustomObject]@{
            Status    = 'Installed'
            Timestamp = $LatestSuccess.Timestamp
            EventId   = $LatestSuccess.EventId
        }
    }

    $LatestFailure = $Matches | Where-Object { $_.Outcome -eq 'Failure' } | Select-Object -First 1
    if ($LatestFailure) {
        return [PSCustomObject]@{
            Status    = 'Failed'
            Timestamp = $LatestFailure.Timestamp
            EventId   = $LatestFailure.EventId
        }
    }

    return [PSCustomObject]@{
        Status    = 'Seen'
        Timestamp = $Matches[0].Timestamp
        EventId   = $Matches[0].EventId
    }
}

function Get-BestSessionMatch {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$Sessions,
        [Parameter(Mandatory = $true)]
        [int]$CorrelationWindowMinutes
    )

    if (-not $Sessions -or $Sessions.Count -eq 0) {
        return $null
    }

    $ActiveSessions = @(
        $Sessions | Where-Object {
            $_.SessionStart -le $Timestamp -and (
                $null -eq $_.SessionEnd -or $_.SessionEnd -ge $Timestamp
            )
        }
    )

    if ($ActiveSessions.Count -gt 0) {
        return ($ActiveSessions | Sort-Object -Property SessionStart -Descending | Select-Object -First 1)
    }

    $NearestPriorSession = @(
        $Sessions | Where-Object {
            $_.SessionStart -le $Timestamp -and
            ($Timestamp - $_.SessionStart).TotalMinutes -le $CorrelationWindowMinutes
        } | Sort-Object -Property SessionStart -Descending
    ) | Select-Object -First 1

    return $NearestPriorSession
}

function Get-BestRestartMatch {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$RestartEvents,
        [Parameter(Mandatory = $true)]
        [int]$CorrelationWindowMinutes
    )

    if ($null -eq $Timestamp) {
        return $null
    }

    if (-not $RestartEvents -or $RestartEvents.Count -eq 0) {
        return $null
    }

    return @(
        $RestartEvents | Where-Object {
            $_.Timestamp -ge $Timestamp -and ($_.Timestamp - $Timestamp).TotalMinutes -le $CorrelationWindowMinutes
        } | Sort-Object -Property Timestamp
    ) | Select-Object -First 1
}

function Get-BestDisplayMatch {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$Events,
        [int]$CorrelationWindowSeconds = 120
    )

    if ($null -eq $Timestamp) {
        return $null
    }

    if (-not $Events -or $Events.Count -eq 0) {
        return $null
    }

    $PreferredTasks = @(
        'Notification Processed',
        'CreatingNotificationThread'
    )

    $Candidates = foreach ($DisplayCandidate in ($Events | Where-Object { $_.Role -eq 'DisplaySignal' -and $_.Task -in $PreferredTasks })) {
        $TimeDeltaSeconds = [math]::Abs(($DisplayCandidate.Timestamp - $Timestamp).TotalSeconds)
        if ($TimeDeltaSeconds -le $CorrelationWindowSeconds) {
            [PSCustomObject]@{
                Event            = $DisplayCandidate
                TimeDeltaSeconds = $TimeDeltaSeconds
                TaskPriority     = $PreferredTasks.IndexOf($DisplayCandidate.Task)
            }
        }
    }

    return ($Candidates | Sort-Object -Property TimeDeltaSeconds, TaskPriority | Select-Object -First 1).Event
}

function Get-BestNotProcessedMatch {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $false)]
        [object[]]$Events,
        [int]$CorrelationWindowSeconds = 120
    )

    if ($null -eq $Timestamp) {
        return $null
    }

    if (-not $Events -or $Events.Count -eq 0) {
        return $null
    }

    return @(
        $Events |
            Where-Object {
                $_.Task -eq 'Notification Not Processed' -and
                [math]::Abs(($_.Timestamp - $Timestamp).TotalSeconds) -le $CorrelationWindowSeconds
            } |
            Sort-Object -Property Timestamp
    ) | Select-Object -First 1
}

function Resolve-OutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    if (Test-Path -LiteralPath $Path) {
        $Item = Get-Item -LiteralPath $Path
        if ($Item.PSIsContainer) {
            return (Join-Path -Path $Item.FullName -ChildPath 'UpdateNotification.clixml')
        }
    }

    return $Path
}

function Get-UpdateEventGroups {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,
        [int]$SplitGapMinutes = 15
    )

    $Groups = [System.Collections.Generic.List[object]]::new()

    foreach ($GroupedById in ($Events | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UpdateId) } | Group-Object -Property UpdateId)) {
        $Ordered = @($GroupedById.Group | Sort-Object -Property Timestamp, Sequence)
        $CurrentAttempt = [System.Collections.Generic.List[object]]::new()
        $AttemptNumber = 1
        $LastTerminalTimestamp = $null

        foreach ($GroupedEvent in $Ordered) {
            $ShouldSplit = $false

            if ($CurrentAttempt.Count -gt 0) {
                $LastAttemptEvent = $CurrentAttempt[$CurrentAttempt.Count - 1]
                if ($LastAttemptEvent.Timestamp -and $GroupedEvent.Timestamp) {
                    $GapMinutes = ($GroupedEvent.Timestamp - $LastAttemptEvent.Timestamp).TotalMinutes
                    if ($GapMinutes -ge $SplitGapMinutes) {
                        $ShouldSplit = $true
                    }
                }

                if ($LastTerminalTimestamp -and $GroupedEvent.Timestamp -and ($GroupedEvent.Timestamp - $LastTerminalTimestamp).TotalMinutes -ge 2) {
                    $ShouldSplit = $true
                }
            }

            if ($ShouldSplit -and $CurrentAttempt.Count -gt 0) {
                $Groups.Add([PSCustomObject]@{
                    GroupName     = $GroupedById.Name
                    AttemptNumber = $AttemptNumber
                    Events        = @($CurrentAttempt)
                })
                $CurrentAttempt = [System.Collections.Generic.List[object]]::new()
                $AttemptNumber++
                $LastTerminalTimestamp = $null
            }

            $CurrentAttempt.Add($GroupedEvent)

            if ($GroupedEvent.UpdateStatus -match 'DownloadFailed|InstallFailed|Failed|RebootRequired|Installed|Succeeded|InstallComplete') {
                $LastTerminalTimestamp = $GroupedEvent.Timestamp
            }
        }

        if ($CurrentAttempt.Count -gt 0) {
            $Groups.Add([PSCustomObject]@{
                GroupName     = $GroupedById.Name
                AttemptNumber = $AttemptNumber
                Events        = @($CurrentAttempt)
            })
        }
    }

    $TitlesWithUpdateId = @(
        $Events |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.UpdateId) -and -not [string]::IsNullOrWhiteSpace($_.UpdateTitle) } |
            Select-Object -ExpandProperty UpdateTitle -Unique
    )

    foreach ($GroupedByTitle in (
        $Events | Where-Object {
            [string]::IsNullOrWhiteSpace($_.UpdateId) -and
            -not [string]::IsNullOrWhiteSpace($_.UpdateTitle) -and
            ($TitlesWithUpdateId -notcontains $_.UpdateTitle)
        } | Group-Object -Property UpdateTitle
    )) {
        $Groups.Add([PSCustomObject]@{
            GroupName     = $GroupedByTitle.Name
            AttemptNumber = 1
            Events        = @($GroupedByTitle.Group)
        })
    }

    return @($Groups)
}

function New-NotificationEventRecord {
    param(
        [Parameter(Mandatory = $true)]
        $EventRecordXml,
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [int]$Sequence
    )

    $Data = Get-EventDataMap -EventRecordXml $EventRecordXml
    $Task = Get-XmlNodeText -Node $EventRecordXml.RenderingInfo.Task
    $ProviderName = Get-XmlNodeText -Node $EventRecordXml.System.Provider.Name
    $EventId = Get-XmlNodeText -Node $EventRecordXml.System.EventID
    $Level = Get-XmlNodeText -Node $EventRecordXml.System.Level
    $RecordId = Get-XmlNodeText -Node $EventRecordXml.System.EventRecordID
    $Channel = Get-XmlNodeText -Node $EventRecordXml.System.Channel
    $Computer = Get-XmlNodeText -Node $EventRecordXml.System.Computer
    $Timestamp = Get-EventTimestamp -EventRecordXml $EventRecordXml

    $UpdateId = $Data['UpdateId']
    $UpdateTitle = $Data['UpdateTitle']
    $UpdateStatus = $Data['UpdateStatus']
    $AttentionRequiredReason = $Data['AttentionRequiredReason']
    $Progress = $Data['Progress']

    $Role = 'Other'
    $RestartRequired = $false

    if ($Task -match 'Display|Displayed|Toast|Notification') {
        $Role = 'DisplaySignal'
    } elseif ($Task -match 'Approved|Clicked|Accepted|Action') {
        $Role = 'UserInteraction'
    } elseif ($Task -match 'Progress') {
        $Role = 'Progress'
    } elseif ($Task -match 'Count|Status') {
        $Role = 'StateSignal'
    }

    if ($AttentionRequiredReason -match 'Reboot|Restart' -or $UpdateStatus -match 'Reboot|Restart') {
        $RestartRequired = $true
        if ($Role -eq 'Other') {
            $Role = 'RestartSignal'
        }
    }

    [PSCustomObject]@{
        Sequence                = $Sequence
        SourcePath              = $SourcePath
        Timestamp               = $Timestamp
        ProviderName            = $ProviderName
        EventId                 = $EventId
        Level                   = $Level
        RecordId                = $RecordId
        Channel                 = $Channel
        Computer                = $Computer
        Task                    = $Task
        Role                    = $Role
        UpdateId                = $UpdateId
        UpdateTitle             = $UpdateTitle
        UpdateStatus            = $UpdateStatus
        AttentionRequiredReason = $AttentionRequiredReason
        Progress                = $Progress
        Data                    = $Data
        RestartRequired         = $RestartRequired
        RawEvent                = if ($IncludeRawEvents) { $EventRecordXml } else { $null }
    }
}

function Get-UpdateRestartClassification {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,
        [Parameter(Mandatory = $false)]
        $RestartEvent
    )

    $RestartEvents = @($Events | Where-Object { $_.RestartRequired -or $_.Role -eq 'RestartSignal' })
    if ($RestartEvents.Count -gt 0) {
        if ($null -ne $RestartEvent -and $RestartEvent.EventId -eq 1074) {
            if ($RestartEvent.Message -match 'user|Benutzer|account') {
                return 'UserInitiated'
            }

            return 'SystemInitiated'
        }

        return 'RestartRelated'
    }

    if ($Events | Where-Object { $_.UpdateStatus -match 'Reboot|Restart' -or $_.AttentionRequiredReason -match 'Reboot|Restart' }) {
        if ($null -ne $RestartEvent) {
            return 'RestartObserved'
        }

        return 'RestartRequiredNoObservedRestart'
    }

    return 'Unknown'
}

function Get-UpdateSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,
        [string]$GroupKey,
        [int]$AttemptNumber = 1,
        [Parameter(Mandatory = $false)]
        [object[]]$AllEvents,
        [Parameter(Mandatory = $false)]
        [object[]]$Sessions,
        [Parameter(Mandatory = $false)]
        [object[]]$RestartEvents,
        [Parameter(Mandatory = $false)]
        [object[]]$UpdateClientEvents,
        [Parameter(Mandatory = $false)]
        [object[]]$LocalIdentityFallback,
        [Parameter(Mandatory = $false)]
        [object[]]$LockEvents,
        [Parameter(Mandatory = $true)]
        [int]$SessionWindowMinutes,
        [Parameter(Mandatory = $true)]
        [int]$RestartWindowMinutes,
        [int]$InstallResultWindowMinutes = 720
    )

    $OrderedEvents = @($Events | Sort-Object -Property Timestamp, Sequence)
    $PrimaryEvent = $OrderedEvents | Where-Object { $_.UpdateId } | Select-Object -First 1
    $UpdateId = $PrimaryEvent.UpdateId
    $UpdateTitle = ($OrderedEvents | Where-Object { $_.UpdateTitle } | Select-Object -First 1).UpdateTitle
    $FirstSeen = ($OrderedEvents | Select-Object -First 1).Timestamp
    $LastSeen = ($OrderedEvents | Select-Object -Last 1).Timestamp

    $DisplayEvent = $OrderedEvents | Where-Object { $_.Role -eq 'DisplaySignal' } | Select-Object -First 1
    $InteractionEvent = $OrderedEvents | Where-Object { $_.Role -eq 'UserInteraction' } | Select-Object -First 1
    $ProgressEvents = @($OrderedEvents | Where-Object { $_.Role -eq 'Progress' -and $_.Progress })
    $CorrelationTimestamp = if ($DisplayEvent.Timestamp) { $DisplayEvent.Timestamp } elseif ($InteractionEvent.Timestamp) { $InteractionEvent.Timestamp } else { $FirstSeen }
    if ($null -eq $DisplayEvent) {
        $DisplayEvent = Get-BestDisplayMatch -Timestamp $CorrelationTimestamp -Events $AllEvents
    }
    $NotProcessedEvent = Get-BestNotProcessedMatch -Timestamp $CorrelationTimestamp -Events $AllEvents

    $DisplayDistanceSeconds = if ($DisplayEvent -and $DisplayEvent.Timestamp) { [math]::Abs(($DisplayEvent.Timestamp - $CorrelationTimestamp).TotalSeconds) } else { [double]::PositiveInfinity }
    $NotProcessedDistanceSeconds = if ($NotProcessedEvent -and $NotProcessedEvent.Timestamp) { [math]::Abs(($NotProcessedEvent.Timestamp - $CorrelationTimestamp).TotalSeconds) } else { [double]::PositiveInfinity }

    if ($NotProcessedEvent -and $NotProcessedDistanceSeconds -le $DisplayDistanceSeconds) {
        $DisplayEvent = $null
    }

    $NotificationTimestamp = $DisplayEvent.Timestamp
    $SignedInSessions = Get-SignedInSessionsAtTimestamp -Timestamp $NotificationTimestamp -Sessions $Sessions -LockEvents $LockEvents
    $SignedInUserCount = @($SignedInSessions).Count
    $MatchedSession = if ($SignedInUserCount -eq 1) { $SignedInSessions[0] } else { $null }
    $MatchedRestartEvent = Get-BestRestartMatch -Timestamp $LastSeen -RestartEvents $RestartEvents -CorrelationWindowMinutes $RestartWindowMinutes
    $RestartClassification = Get-UpdateRestartClassification -Events $OrderedEvents -RestartEvent $MatchedRestartEvent
    $LockStateAtNotification = Get-LockStateAtTimestamp -Timestamp $NotificationTimestamp -LockEvents $LockEvents

    $OrderedUpdateStatusValues = @($OrderedEvents.UpdateStatus | Where-Object { $_ } | Select-Object -Unique)
    $OrderedAttentionReasons = @($OrderedEvents.AttentionRequiredReason | Where-Object { $_ } | Select-Object -Unique)

    $NotificationProcessedReason = if ($DisplayEvent -and $DisplayEvent.Data) { $DisplayEvent.Data['Notification Reason'] } else { $null }
    $NotificationNotProcessedReason = if ($NotProcessedEvent -and $NotProcessedEvent.Data) { $NotProcessedEvent.Data['Not Processed Reason'] } else { $null }
    $NotificationType = Get-NotificationType -UpdateStatusValues $OrderedUpdateStatusValues -AttentionReasons $OrderedAttentionReasons -ClickSignal $InteractionEvent.Task -DisplayEvent $DisplayEvent -NotProcessedEvent $NotProcessedEvent
    $NotificationDisplayedState = Get-NotificationDisplayedState -DisplayEvent $DisplayEvent -NotProcessedEvent $NotProcessedEvent -UserClickedAt $InteractionEvent.Timestamp -NotificationType $NotificationType -NotificationNotProcessedReason $NotificationNotProcessedReason

    $KbArticles = Get-KbArticlesFromTitle -Title $UpdateTitle
    $InstallResultEvent = Get-BestInstallResultMatch -KbArticles $KbArticles -FirstSeen $FirstSeen -LastSeen $LastSeen -UpdateClientEvents $UpdateClientEvents -CorrelationWindowMinutes $InstallResultWindowMinutes
    $GlobalInstallEvidence = Get-GlobalInstallEvidenceFromUpdateClient -KbArticles $KbArticles -UpdateTitle $UpdateTitle -UpdateClientEvents $UpdateClientEvents
    $HasSuccessStatus = @($OrderedEvents.UpdateStatus | Where-Object { $_ -match 'Installed|Succeeded|InstallComplete' }).Count -gt 0
    $HasFailureSignal = @($OrderedEvents.UpdateStatus | Where-Object { $_ -match 'Failed|DownloadFailed|InstallFailed' }).Count -gt 0 -or @($OrderedEvents.AttentionRequiredReason | Where-Object { $_ -match 'BlockedByFailure' }).Count -gt 0

    $AttemptSuccessWindowMinutes = 20
    $InstallResultIsNearAttempt = $InstallResultEvent -and $LastSeen -and (($InstallResultEvent.Timestamp - $LastSeen).TotalMinutes -ge 0) -and (($InstallResultEvent.Timestamp - $LastSeen).TotalMinutes -le $AttemptSuccessWindowMinutes)

    $UpdateSuccessful = if ($HasSuccessStatus) {
        'Yes'
    } elseif ($HasFailureSignal) {
        if ($InstallResultEvent -and $InstallResultEvent.Outcome -eq 'Success' -and $InstallResultIsNearAttempt) {
            'Yes'
        } else {
            'No'
        }
    } elseif ($InstallResultEvent -and $InstallResultEvent.Outcome -eq 'Success' -and $InstallResultIsNearAttempt) {
        'Yes'
    } elseif ($InstallResultEvent -and $InstallResultEvent.Outcome -eq 'Failure') {
        'No'
    } else {
        'Unknown'
    }

    $NotificationConfidence = Get-NotificationConfidence -NotificationDisplayed $NotificationDisplayedState -NotificationNotShownSignal $NotProcessedEvent.Task -NotificationProcessedReason $NotificationProcessedReason -NotificationNotProcessedReason $NotificationNotProcessedReason -SessionLockStateAtNotification $LockStateAtNotification -UserClickedAt $InteractionEvent.Timestamp
    $ExclusivityInterpretation = Get-ExclusivityInterpretation -AttentionReasons $OrderedAttentionReasons
    $ResolvedUserName = if ($SignedInUserCount -gt 1) {
        'Multiple'
    } elseif ($MatchedSession) {
        $MatchedSession.UserName
    } else {
        $null
    }
    $ResolvedUserDomain = if ($SignedInUserCount -gt 1) {
        'Multiple'
    } elseif ($MatchedSession) {
        $MatchedSession.Domain
    } else {
        $null
    }
    $ResolvedUserPrincipal = if ($SignedInUserCount -gt 1) {
        'Multiple'
    } elseif ($MatchedSession) {
        $MatchedSession.UserPrincipal
    } else {
        $null
    }
    $ResolvedUserSid = if ($SignedInUserCount -gt 1) {
        'Multiple'
    } elseif ($MatchedSession) {
        $MatchedSession.Sid
    } else {
        $null
    }
    $ResolvedSamAccountName = if ($SignedInUserCount -gt 1) {
        'Multiple'
    } elseif ($MatchedSession) {
        $MatchedSession.UserName
    } else {
        $null
    }
    $RelatedRestart = if ($MatchedRestartEvent) { '✅' } else { '❌' }

    [PSCustomObject]@{
        GroupKey               = $GroupKey
        AttemptNumber          = $AttemptNumber
        UpdateId                = $UpdateId
        Title                   = $UpdateTitle
        KbArticles              = $KbArticles
        FirstSeen               = $FirstSeen
        LastSeen                = $LastSeen
        NotificationType        = $NotificationType
        NotificationDisplayedState = $NotificationDisplayedState
        NotificationDisplayedAt = $DisplayEvent.Timestamp
        NotificationSignal      = $DisplayEvent.Task
        NotificationProcessedReason = $NotificationProcessedReason
        NotificationNotShownAt  = $NotProcessedEvent.Timestamp
        NotificationNotShownSignal = $NotProcessedEvent.Task
        NotificationNotProcessedReason = $NotificationNotProcessedReason
        SessionLockStateAtNotification = $LockStateAtNotification
        NotificationConfidence  = $NotificationConfidence
        ExclusivityInterpretation = $ExclusivityInterpretation
        UpdateSuccessful        = $UpdateSuccessful
        UpdateSuccessSignalAt   = $InstallResultEvent.Timestamp
        UpdateSuccessSignalType = $InstallResultEvent.Outcome
        InstallEvidenceFromWUClient = $GlobalInstallEvidence.Status
        InstallEvidenceAt      = $GlobalInstallEvidence.Timestamp
        InstallEvidenceEventId = $GlobalInstallEvidence.EventId
        UserClickedAt           = $InteractionEvent.Timestamp
        ClickSignal             = $InteractionEvent.Task
        SessionCorrelationTime  = $NotificationTimestamp
        UserName                = $ResolvedUserName
        UserDomain              = $ResolvedUserDomain
        UserPrincipal           = $ResolvedUserPrincipal
        UserSid                 = $ResolvedUserSid
        SamAccountName          = $ResolvedSamAccountName
        LogonId                 = if ($SignedInUserCount -eq 1) { $MatchedSession.LogonId } else { $null }
        LogonType               = if ($SignedInUserCount -eq 1) { $MatchedSession.LogonType } else { $null }
        LogonTypeLabel          = if ($SignedInUserCount -eq 1) { $MatchedSession.LogonTypeLabel } else { $null }
        SessionStart            = if ($SignedInUserCount -eq 1) { $MatchedSession.SessionStart } else { $null }
        SessionEnd              = if ($SignedInUserCount -eq 1) { $MatchedSession.SessionEnd } else { $null }
        RelatedRestart          = $RelatedRestart
        RestartClassificationRaw = $RestartClassification
        RestartEventAt          = $MatchedRestartEvent.Timestamp
        RestartEventId          = $MatchedRestartEvent.EventId
        RestartEventType        = $MatchedRestartEvent.Classification
        UpdateStatusValues      = $OrderedUpdateStatusValues
        AttentionReasons        = $OrderedAttentionReasons
        ProgressSamples         = @($ProgressEvents.Progress | Where-Object { $_ } | Select-Object -Unique)
        EventCount              = $OrderedEvents.Count
        Events                  = if ($IncludeRawEvents) { $OrderedEvents } else { $null }
    }
}

$SourceFiles = Get-NotificationSourceFiles -Paths $InputPath
if (-not $SourceFiles -or $SourceFiles.Count -eq 0) {
    throw 'No UpdateUx, MoNotifications, or XML files were found in the provided input path.'
}

$EventRecords = [System.Collections.Generic.List[object]]::new()
$Sequence = 0

foreach ($SourceFile in $SourceFiles) {
    $ImportedXml = Import-NotificationXml -Path $SourceFile.FullName
    $ImportedEvents = @($ImportedXml.Events.Event)

    foreach ($EventRecordXml in $ImportedEvents) {
        $Sequence++
        $EventRecords.Add((New-NotificationEventRecord -EventRecordXml $EventRecordXml -SourcePath $SourceFile.FullName -Sequence $Sequence))
    }
}

$OrderedRecords = @($EventRecords | Sort-Object -Property Timestamp, Sequence)
$TimelineStart = ($OrderedRecords | Where-Object { $_.Timestamp } | Select-Object -First 1).Timestamp
$TimelineEnd = ($OrderedRecords | Where-Object { $_.Timestamp } | Select-Object -Last 1).Timestamp

if ($null -eq $TimelineStart) {
    $TimelineStart = (Get-Date).AddDays(-$SessionLookbackDays)
}

if ($null -eq $TimelineEnd) {
    $TimelineEnd = Get-Date
}

$SessionQueryStart = $TimelineStart.AddDays(-1)
$SessionQueryEnd = $TimelineEnd.AddDays(1)
$LocalSessions = @(Get-LocalUserSessions -StartTime $SessionQueryStart -EndTime $SessionQueryEnd)
$LocalRestartEvents = @(Get-LocalRestartEvents -StartTime $SessionQueryStart -EndTime $SessionQueryEnd)
$LocalUpdateClientEvents = @(Get-LocalUpdateClientEvents -StartTime $SessionQueryStart -EndTime $SessionQueryEnd)
$LocalLockEvents = @(Get-LocalLockStateEvents -StartTime $SessionQueryStart -EndTime $SessionQueryEnd)
$LocalRegistryIdentities = @(Get-LocalRegistryUserIdentities)

$Updates = foreach ($UpdateGroup in (Get-UpdateEventGroups -Events $OrderedRecords -SplitGapMinutes $AttemptSplitGapMinutes)) {
    Get-UpdateSummary -Events $UpdateGroup.Events -GroupKey $UpdateGroup.GroupName -AttemptNumber $UpdateGroup.AttemptNumber -AllEvents $OrderedRecords -Sessions $LocalSessions -RestartEvents $LocalRestartEvents -UpdateClientEvents $LocalUpdateClientEvents -LocalIdentityFallback $LocalRegistryIdentities -LockEvents $LocalLockEvents -SessionWindowMinutes $SessionCorrelationWindowMinutes -RestartWindowMinutes $RestartCorrelationWindowMinutes -InstallResultWindowMinutes $InstallResultCorrelationWindowMinutes
}

if ($UpdateStatusFilter -and $UpdateStatusFilter.Count -gt 0) {
    $Updates = @(
        $Updates | Where-Object {
            Test-UpdateStatusMatch -Update $_ -StatusFilter $UpdateStatusFilter
        }
    )
}

$Output = [PSCustomObject]@{
    SourceFiles   = @($SourceFiles.FullName)
    EventTimeline = [PSCustomObject]@{
        FirstEvent = $TimelineStart
        LastEvent  = $TimelineEnd
    }
    UpdateCount   = @($Updates).Count
    EventCount    = $OrderedRecords.Count
    SessionCount  = @($LocalSessions).Count
    RestartCount  = @($LocalRestartEvents).Count
    UpdateClientEventCount = @($LocalUpdateClientEvents).Count
    LockEventCount = @($LocalLockEvents).Count
    LocalIdentityCount = @($LocalRegistryIdentities).Count
    Updates       = @($Updates | Sort-Object -Property NotificationDisplayedAt, FirstSeen -Descending)
    NonNotifiedUpdates = @(
        $Updates | Where-Object {
            $_.NotificationDisplayedState -eq 'No' -or (
                [string]::IsNullOrWhiteSpace($_.NotificationDisplayedState) -and
                -not $_.NotificationDisplayedAt -and
                $_.NotificationNotShownSignal -eq 'Notification Not Processed'
            )
        } | Sort-Object -Property FirstSeen
    )
    Sessions      = @($LocalSessions)
    RestartEvents = @($LocalRestartEvents)
    LocalIdentities = @($LocalRegistryIdentities)
    Events        = if ($IncludeRawEvents) { $OrderedRecords } else { $null }
}

$HumanReadableRows = ConvertTo-HumanReadableUpdateRows -Updates $Output.Updates -IncludeSamAccountName:$IncludeSamAccountName
$Output | Add-Member -MemberType NoteProperty -Name HumanReadableRows -Value $HumanReadableRows -Force

if ($OutputPath) {
    $ResolvedOutputPath = Resolve-OutputPath -Path $OutputPath

    if ($ResolvedOutputPath.EndsWith('.json')) {
        $Output | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ResolvedOutputPath
    } elseif ($ResolvedOutputPath.EndsWith('.csv')) {
        $Updates | Export-Csv -LiteralPath $ResolvedOutputPath -NoTypeInformation
    } else {
        $Output | Export-Clixml -LiteralPath $ResolvedOutputPath
    }
}

if (-not $HideReport) {
    Show-HumanReadableReport -Rows $HumanReadableRows
}

$Output