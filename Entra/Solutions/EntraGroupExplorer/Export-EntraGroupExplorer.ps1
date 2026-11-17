<#
.SYNOPSIS
    Exports Entra group membership counts and builds a self-contained explorer.
.DESCRIPTION
    Reads group properties and membership counts from Microsoft Graph, or loads an existing
    explorer JSON file, then writes a timestamped JSON snapshot and an interactive HTML viewer.
    Membership object identifiers are used only during collection and are not exported.
.PARAMETER OutputPath
    Directory for generated JSON and HTML files. Defaults to the solution Output directory.
.PARAMETER OutputName
    Base name for generated files.
.PARAMETER MaxNameLength
    Maximum displayed group-name length. Use 0 to disable abbreviation.
.PARAMETER AbbreviationStyle
    Abbreviation strategy: Middle or End.
.PARAMETER InitialDepth
    Number of parent and child levels initially expanded.
.PARAMETER AutoExpandLimit
    Nested branches with more related groups than this start collapsed. Use 0 to always expand up to InitialDepth.
.PARAMETER DangerousGroup
    Group ids, exact display names, or wildcard display-name patterns to flag.
.PARAMETER DangerousGroupFile
    JSON file containing dangerous-group rules.
.PARAMETER TreatRoleAssignableAsDangerous
    Marks role-assignable groups as dangerous.
.PARAMETER TenantId
    Tenant id used when connecting to Microsoft Graph.
.PARAMETER IncludeHiddenMembership
    Requests Member.Read.Hidden in addition to GroupMember.Read.All.
.PARAMETER IncludeMembershipRule
    Includes dynamic membership rule text in the exported data.
.PARAMETER DataFile
    Existing explorer JSON file to process without connecting to Microsoft Graph.
.PARAMETER SkipHtml
    Writes the JSON snapshot without generating HTML.
.PARAMETER OpenReport
    Opens the generated HTML file in the default browser.
.PARAMETER BatchSize
    Number of sub-requests per Graph batch, from 1 to 20.
.PARAMETER MaxRetries
    Maximum retries for throttled or transient Graph requests.
.PARAMETER MaxUnavailablePercent
    Maximum percentage of groups with unavailable counts before returning exit code 2.
.PARAMETER LogPath
    Directory in which the log file is created. The default is the current directory.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.NOTES
    Version: 0.1
    Author: Martin Himken
    Original script name: Export-EntraGroupExplorer.ps1
    Initial creation date: 2026-11-12
    Last change: 2026-11-12
    Changes: Initial version
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Output'),
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$OutputName = 'EntraGroupExplorer',
    [ValidateScript({ $_ -eq 0 -or ($_ -ge 8 -and $_ -le 200) })]
    [int]$MaxNameLength = 30,
    [ValidateSet('Middle', 'End')]
    [string]$AbbreviationStyle = 'Middle',
    [ValidateRange(1, 10)]
    [int]$InitialDepth = 2,
    [ValidateRange(0, 1000)]
    [int]$AutoExpandLimit = 10,
    [string[]]$DangerousGroup = @(),
    [string]$DangerousGroupFile = (Join-Path -Path $PSScriptRoot -ChildPath 'Config\DangerousGroups.json'),
    [switch]$TreatRoleAssignableAsDangerous,
    [string]$TenantId,
    [switch]$IncludeHiddenMembership,
    [switch]$IncludeMembershipRule,
    [string]$DataFile,
    [switch]$SkipHtml,
    [switch]$OpenReport,
    [ValidateRange(1, 20)]
    [int]$BatchSize = 20,
    [ValidateRange(0, 12)]
    [int]$MaxRetries = 6,
    [ValidateRange(0, 100)]
    [int]$MaxUnavailablePercent = 10,
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null
)

$Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $Pwsh7Path) {
    Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
    exit 1
}

function Write-Log {
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')]
        [int]$Type
    )
    if ($Script:LogFile) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($Script:ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
        } elseif ($Script:ToConsole) {
            switch ($Type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}

function Initialize-Script {
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Export-EntraGroupExplorer'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    if (-not $LogFile) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:ToConsole = $false
    $Script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'
    $Script:UnavailableGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
}

function Test-Prerequisite {
    if (-not $SkipHtml) {
        $TemplatePaths = @(
            (Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.template.html'),
            (Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.css'),
            (Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.logic.js'),
            (Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.ui.js')
        )
        foreach ($TemplatePath in $TemplatePaths) {
            if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) {
                throw "Required viewer file is missing: $TemplatePath"
            }
        }
    }
    if ($DataFile) { return }

    $GraphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $GraphModule) {
        throw 'Microsoft.Graph.Authentication is required. Install the module and run the generator again.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $GraphCommand = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    foreach ($RequiredParameter in @('SkipHttpErrorCheck', 'StatusCodeVariable', 'ResponseHeadersVariable', 'OutputType')) {
        if (-not $GraphCommand.Parameters.ContainsKey($RequiredParameter)) {
            throw "Microsoft.Graph.Authentication must support -$RequiredParameter. Update the module and run the generator again."
        }
    }
}

function Connect-GraphSession {
    $CurrentContext = Get-MgContext
    if ($CurrentContext) {
        $CurrentScopes = @($CurrentContext.Scopes)
        $MembershipScopes = @('GroupMember.Read.All', 'Group.Read.All', 'Group.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All')
        if (-not ($CurrentScopes | Where-Object { $_ -in $MembershipScopes })) {
            throw 'The current Graph context lacks GroupMember.Read.All (or Group.Read.All/Directory.Read.All/Directory.AccessAsUser.All). Connect with the required scope and retry.'
        }
        if ($IncludeHiddenMembership -and 'Member.Read.Hidden' -notin $CurrentScopes) {
            throw 'The current Graph context lacks Member.Read.Hidden. Reconnect with -IncludeHiddenMembership and the required scope.'
        }
        return $CurrentContext
    }

    $RequestedScopes = [System.Collections.Generic.List[string]]::new()
    $RequestedScopes.Add('GroupMember.Read.All')
    if ($IncludeHiddenMembership) { $RequestedScopes.Add('Member.Read.Hidden') }
    $ConnectParameters = @{ Scopes = @($RequestedScopes); NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $ConnectParameters.TenantId = $TenantId }
    Connect-MgGraph @ConnectParameters | Out-Null
    $CurrentContext = Get-MgContext
    if (-not $CurrentContext) { throw 'Microsoft Graph did not return an authenticated context.' }
    return $CurrentContext
}

function Get-GraphField {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($Key in $InputObject.Keys) {
            if ([string]::Equals([string]$Key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $InputObject[$Key]
            }
        }
        return $null
    }
    $Property = $InputObject.PSObject.Properties |
        Where-Object { [string]::Equals($_.Name, $Name, [System.StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1
    if ($Property) { return $Property.Value }
    return $null
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )
    $Attempt = 0
    do {
        $RequestParameters = @{
            Method                  = $Method
            Uri                     = $Uri
            SkipHttpErrorCheck      = $true
            StatusCodeVariable      = 'GraphStatusCode'
            ResponseHeadersVariable = 'GraphResponseHeaders'
            OutputType              = 'PSObject'
            ErrorAction             = 'Stop'
        }
        if ($Headers) { $RequestParameters.Headers = $Headers }
        if ($PSBoundParameters.ContainsKey('Body')) {
            $RequestParameters.Body = $Body
            $RequestParameters.ContentType = 'application/json'
        }
        $GraphStatusCode = 0
        $GraphResponseHeaders = @{}
        $ResponseBody = Invoke-MgGraphRequest @RequestParameters
        $Response = [pscustomobject]@{
            StatusCode = [int]$GraphStatusCode
            Body       = $ResponseBody
            Headers    = $GraphResponseHeaders
        }
        if ($Response.StatusCode -notin @(429, 503, 504) -or $Attempt -ge $MaxRetries) {
            return $Response
        }
        $RetryAfter = Get-GraphField -InputObject $Response.Headers -Name 'Retry-After'
        $Delay = [Math]::Min(30, [Math]::Pow(2, $Attempt + 1))
        $RetrySeconds = 0
        if ($RetryAfter -and [int]::TryParse([string]$RetryAfter, [ref]$RetrySeconds)) {
            $Delay = [Math]::Min(60, [Math]::Max(1, $RetrySeconds))
        }
        $Delay += (Get-Random -Minimum 0 -Maximum 1000) / 1000
        Write-Log -Message "Graph returned HTTP $($Response.StatusCode). Retrying after $([Math]::Round($Delay, 1)) seconds." -Component 'GraphRetry' -Type 2
        Start-Sleep -Seconds $Delay
        $Attempt++
    } while ($true)
}

function Invoke-GraphBatch {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Requests
    )
    $PendingRequests = [System.Collections.Generic.List[object]]::new()
    foreach ($Request in $Requests) { $PendingRequests.Add($Request) }
    $CompletedResponses = [System.Collections.Generic.List[object]]::new()
    $AttemptById = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)

    while ($PendingRequests.Count -gt 0) {
        $CurrentRequests = @($PendingRequests | Select-Object -First $BatchSize)
        $PendingRequests.RemoveRange(0, $CurrentRequests.Count)
        $BatchBody = @{ requests = $CurrentRequests } | ConvertTo-Json -Depth 8 -Compress
        $BatchResponse = Invoke-GraphRequestWithRetry -Method POST -Uri "$($Script:GraphBaseUri)/`$batch" -Body $BatchBody
        if ($BatchResponse.StatusCode -lt 200 -or $BatchResponse.StatusCode -ge 300) {
            foreach ($Request in $CurrentRequests) {
                $CompletedResponses.Add([pscustomobject]@{ id = $Request.id; status = $BatchResponse.StatusCode; body = $BatchResponse.Body; headers = $BatchResponse.Headers })
            }
            continue
        }

        $SubResponses = Get-GraphField -InputObject $BatchResponse.Body -Name 'responses'
        foreach ($Request in $CurrentRequests) {
            $SubResponse = @($SubResponses | Where-Object { [string](Get-GraphField -InputObject $_ -Name 'id') -eq [string]$Request.id } | Select-Object -First 1)
            if (-not $SubResponse) {
                $CompletedResponses.Add([pscustomobject]@{ id = $Request.id; status = 0; body = $null; headers = @{} })
                continue
            }
            $SubResponse = $SubResponse[0]
            $SubStatus = [int](Get-GraphField -InputObject $SubResponse -Name 'status')
            if ($SubStatus -in @(429, 503, 504)) {
                $PreviousAttempt = 0
                if ($AttemptById.ContainsKey([string]$Request.id)) { $PreviousAttempt = $AttemptById[[string]$Request.id] }
                if ($PreviousAttempt -lt $MaxRetries) {
                    $AttemptById[[string]$Request.id] = $PreviousAttempt + 1
                    $SubHeaders = Get-GraphField -InputObject $SubResponse -Name 'headers'
                    $RetryAfter = Get-GraphField -InputObject $SubHeaders -Name 'Retry-After'
                    $Delay = [Math]::Min(30, [Math]::Pow(2, $PreviousAttempt + 1))
                    $RetrySeconds = 0
                    if ($RetryAfter -and [int]::TryParse([string]$RetryAfter, [ref]$RetrySeconds)) {
                        $Delay = [Math]::Min(60, [Math]::Max(1, $RetrySeconds))
                    }
                    $Delay += (Get-Random -Minimum 0 -Maximum 1000) / 1000
                    Write-Log -Message "Graph sub-request returned HTTP $SubStatus. Retrying after $([Math]::Round($Delay, 1)) seconds." -Component 'GraphBatch' -Type 2
                    Start-Sleep -Seconds $Delay
                    $PendingRequests.Add($Request)
                    continue
                }
            }
            $CompletedResponses.Add($SubResponse)
        }
    }
    return @($CompletedResponses)
}

function Get-AllGroup {
    $SelectedProperties = 'id,displayName,description,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled,createdDateTime,visibility'
    if ($IncludeMembershipRule) { $SelectedProperties += ',membershipRule,membershipRuleProcessingState' }
    $NextUri = "$($Script:GraphBaseUri)/groups?`$select=$SelectedProperties&`$top=999"
    $GroupList = [System.Collections.Generic.List[object]]::new()
    while ($NextUri) {
        $PageResponse = Invoke-GraphRequestWithRetry -Method GET -Uri $NextUri
        if ($PageResponse.StatusCode -lt 200 -or $PageResponse.StatusCode -ge 300) {
            throw "Graph group enumeration returned HTTP $($PageResponse.StatusCode)."
        }
        $PageGroups = Get-GraphField -InputObject $PageResponse.Body -Name 'value'
        foreach ($Group in @($PageGroups)) { $GroupList.Add($Group) }
        $NextUri = [string](Get-GraphField -InputObject $PageResponse.Body -Name '@odata.nextLink')
    }
    return @($GroupList)
}

function Get-GroupType {
    param([Parameter(Mandatory = $true)][object]$Group)
    $GroupTypes = @(Get-GraphField -InputObject $Group -Name 'groupTypes')
    $MailEnabled = [bool](Get-GraphField -InputObject $Group -Name 'mailEnabled')
    $SecurityEnabled = [bool](Get-GraphField -InputObject $Group -Name 'securityEnabled')
    $Type = if ('Unified' -in $GroupTypes) {
        'm365'
    } elseif ($MailEnabled -and $SecurityEnabled) {
        'mailSecurity'
    } elseif ($MailEnabled) {
        'distribution'
    } elseif ($SecurityEnabled) {
        'security'
    } else {
        'unknown'
    }
    $Membership = if ('DynamicMembership' -in $GroupTypes) { 'dynamic' } else { 'assigned' }
    return [pscustomobject]@{ Type = $Type; Membership = $Membership }
}

function Get-GroupCallPlan {
    param([Parameter(Mandatory = $true)][object]$Group)
    $TypeInfo = Get-GroupType -Group $Group
    $Plan = [System.Collections.Generic.List[string]]::new()
    $Plan.Add('users')
    if ($TypeInfo.Type -in @('security', 'mailSecurity', 'unknown')) { $Plan.Add('devices') }
    if ($TypeInfo.Membership -eq 'assigned' -and $TypeInfo.Type -in @('security', 'mailSecurity', 'distribution', 'unknown')) {
        $Plan.Add('groups')
    }
    return @($Plan)
}

function New-CountRequest {
    param(
        [Parameter(Mandatory = $true)][string]$RequestId,
        [Parameter(Mandatory = $true)][string]$GroupId,
        [Parameter(Mandatory = $true)][string]$Kind,
        [switch]$Transitive
    )
    $CollectionName = if ($Transitive) { 'transitiveMembers' } else { 'members' }
    $CastType = switch ($Kind) {
        'users' { 'user' }
        'devices' { 'device' }
        'groups' { 'group' }
        default { throw "Unsupported membership count type: $Kind" }
    }
    return [ordered]@{
        id      = $RequestId
        method  = 'GET'
        url     = "/groups/$GroupId/$CollectionName/microsoft.graph.${CastType}?`$count=true&`$top=$(if ($Kind -eq 'groups') { 999 } else { 1 })&`$select=id"
        headers = @{ ConsistencyLevel = 'eventual' }
    }
}

function Get-ResponseById {
    param([object[]]$Responses, [string]$RequestId)
    foreach ($Response in $Responses) {
        if ([string](Get-GraphField -InputObject $Response -Name 'id') -eq $RequestId) { return $Response }
    }
    return $null
}

function Add-GroupFlag {
    param([object]$Group, [string]$Flag)
    $Group.flags = @($Group.flags | Where-Object { $_ -ne $Flag } | Sort-Object -Unique) + $Flag
}

function Set-GroupChildrenFromResponse {
    param(
        [Parameter(Mandatory = $true)][object]$Group,
        [Parameter(Mandatory = $true)][object]$Response
    )
    $ChildIds = [System.Collections.Generic.List[string]]::new()
    $ResponseBody = Get-GraphField -InputObject $Response -Name 'body'
    foreach ($Child in @(Get-GraphField -InputObject $ResponseBody -Name 'value')) {
        $ChildId = [string](Get-GraphField -InputObject $Child -Name 'id')
        if ($ChildId) { $ChildIds.Add($ChildId) }
    }
    $NextUri = [string](Get-GraphField -InputObject $ResponseBody -Name '@odata.nextLink')
    while ($NextUri) {
        $PageResponse = Invoke-GraphRequestWithRetry -Method GET -Uri $NextUri -Headers @{ ConsistencyLevel = 'eventual' }
        if ($PageResponse.StatusCode -ne 200) {
            $Group.counts.direct.groups = $null
            if ($PageResponse.StatusCode -eq 404) {
                Add-GroupFlag -Group $Group -Flag 'notFound'
                $null = $Script:UnavailableGroups.Add([string]$Group.id)
            } elseif ($PageResponse.StatusCode -eq 403) {
                Add-GroupFlag -Group $Group -Flag 'membersForbidden'
            } elseif ($PageResponse.StatusCode -eq 401) {
                throw 'Microsoft Graph returned HTTP 401 while paging child groups. Reconnect and run the export again.'
            } else {
                Add-GroupFlag -Group $Group -Flag 'countsUnavailable'
                $null = $Script:UnavailableGroups.Add([string]$Group.id)
            }
            return
        }
        foreach ($Child in @(Get-GraphField -InputObject $PageResponse.Body -Name 'value')) {
            $ChildId = [string](Get-GraphField -InputObject $Child -Name 'id')
            if ($ChildId) { $ChildIds.Add($ChildId) }
        }
        $NextUri = [string](Get-GraphField -InputObject $PageResponse.Body -Name '@odata.nextLink')
    }
    $Group.children = @($ChildIds)
    $Group.counts.direct.groups = $ChildIds.Count
}

function Set-CountResult {
    param(
        [object]$Group,
        [string]$Kind,
        [object]$Response,
        [switch]$Transitive
    )
    $StatusCode = [int](Get-GraphField -InputObject $Response -Name 'status')
    $Body = Get-GraphField -InputObject $Response -Name 'body'
    $CountValue = Get-GraphField -InputObject $Body -Name '@odata.count'
    $Target = if ($Transitive) { $Group.counts.nested } else { $Group.counts.direct }
    $Target[$Kind] = if ($null -ne $CountValue -and $StatusCode -eq 200) { [long]$CountValue } else { $null }
    if ($StatusCode -eq 401) {
        throw 'Microsoft Graph returned HTTP 401. Reconnect and run the export again.'
    } elseif ($StatusCode -eq 400) {
        $Target[$Kind] = 0
        Write-Log -Message "Graph rejected the $Kind cast for group type $($Group.type). The count was set to zero." -Component 'Membership' -Type 2
    } elseif ($StatusCode -eq 403) {
        Add-GroupFlag -Group $Group -Flag 'membersForbidden'
        $Visibility = [string](Get-GraphField -InputObject $Group -Name 'visibility')
        if ($Visibility -eq 'HiddenMembership') { Add-GroupFlag -Group $Group -Flag 'hiddenMembership' }
        $null = $Script:UnavailableGroups.Add([string]$Group.id)
    } elseif ($StatusCode -eq 404) {
        Add-GroupFlag -Group $Group -Flag 'notFound'
        $null = $Script:UnavailableGroups.Add([string]$Group.id)
    } elseif ($StatusCode -in @(429, 503, 504) -or $null -eq $CountValue) {
        Add-GroupFlag -Group $Group -Flag 'countsUnavailable'
        $null = $Script:UnavailableGroups.Add([string]$Group.id)
    }
}

function Get-MembershipCount {
    param([Parameter(Mandatory = $true)][object[]]$Groups)
    $GroupIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Group in $Groups) {
        $TypeInfo = Get-GroupType -Group $Group
        $Group.type = $TypeInfo.Type
        $Group.membership = $TypeInfo.Membership
        $Group.counts = @{ direct = @{ users = 0; devices = 0; groups = 0 }; nested = @{ users = 0; devices = 0; groups = 0 } }
        foreach ($CountKind in (Get-GroupCallPlan -Group $Group)) {
            $Group.counts.direct[$CountKind] = $null
            $Group.counts.nested[$CountKind] = $null
        }
        $Group.children = @()
        $Group.parents = @()
        $Group.flags = @()
        $GroupIndex[[string]$Group.id] = $Group
    }

    $MembershipRequests = [System.Collections.Generic.List[object]]::new()
    $RequestMap = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $RequestNumber = 0
    foreach ($Group in $Groups) {
        foreach ($Kind in (Get-GroupCallPlan -Group $Group)) {
            $RequestId = "m$RequestNumber"
            $MembershipRequests.Add((New-CountRequest -RequestId $RequestId -GroupId ([string]$Group.id) -Kind $Kind))
            $RequestMap[$RequestId] = [pscustomobject]@{ Group = $Group; Kind = $Kind; Transitive = $false }
            $RequestNumber++
        }
    }
    $BatchNumber = 0
    $TotalBatches = [Math]::Ceiling($MembershipRequests.Count / $BatchSize)
    Write-Log -Message "Loaded $($Groups.Count) groups; $($MembershipRequests.Count) membership requests in $TotalBatches batches." -Component 'Progress' -Type 1
    for ($RequestStart = 0; $RequestStart -lt $MembershipRequests.Count; $RequestStart += $BatchSize) {
        $RequestEnd = [Math]::Min($RequestStart + $BatchSize - 1, $MembershipRequests.Count - 1)
        $Responses = Invoke-GraphBatch -Requests @($MembershipRequests[$RequestStart..$RequestEnd])
        foreach ($Response in $Responses) {
            $ResponseId = [string](Get-GraphField -InputObject $Response -Name 'id')
            if ($RequestMap.ContainsKey($ResponseId)) {
                $Metadata = $RequestMap[$ResponseId]
                Set-CountResult -Group $Metadata.Group -Kind $Metadata.Kind -Response $Response
                if ($Metadata.Kind -eq 'groups' -and [int](Get-GraphField -InputObject $Response -Name 'status') -eq 200) {
                    Set-GroupChildrenFromResponse -Group $Metadata.Group -Response $Response
                }
            }
        }
        $BatchNumber++
        if ($BatchNumber % 25 -eq 0) {
            Write-Progress -Activity 'Reading group memberships' -Status "$BatchNumber of $TotalBatches batches completed" -PercentComplete ([Math]::Min(100, [int](100 * $BatchNumber / $TotalBatches)))
            Write-Log -Message "$BatchNumber of $TotalBatches membership batches completed." -Component 'Progress' -Type 1
        }
    }

    $TransitiveRequests = [System.Collections.Generic.List[object]]::new()
    $TransitiveMap = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($Group in $Groups) {
        if ($Group.counts.direct.groups -eq 0) {
            foreach ($CountKind in @('users', 'devices')) { $Group.counts.nested[$CountKind] = $Group.counts.direct[$CountKind] }
            $Group.counts.nested.groups = 0
        } elseif ($null -eq $Group.counts.direct.groups) {
            foreach ($CountKind in @('users', 'devices', 'groups')) { $Group.counts.nested[$CountKind] = $null }
        }
    }
    foreach ($Group in $Groups) {
        if ($Group.counts.direct.groups -gt 0) {
            foreach ($Kind in (Get-GroupCallPlan -Group $Group | Where-Object { $_ -in @('users', 'devices') })) {
                $RequestId = "t$RequestNumber"
                $TransitiveRequests.Add((New-CountRequest -RequestId $RequestId -GroupId ([string]$Group.id) -Kind $Kind -Transitive))
                $TransitiveMap[$RequestId] = [pscustomobject]@{ Group = $Group; Kind = $Kind }
                $RequestNumber++
            }
        }
    }
    $TransitiveBatchNumber = 0
    $TransitiveTotalBatches = [Math]::Ceiling($TransitiveRequests.Count / $BatchSize)
    Write-Log -Message "$($TransitiveRequests.Count) transitive count requests in $TransitiveTotalBatches batches." -Component 'Progress' -Type 1
    for ($RequestStart = 0; $RequestStart -lt $TransitiveRequests.Count; $RequestStart += $BatchSize) {
        $RequestEnd = [Math]::Min($RequestStart + $BatchSize - 1, $TransitiveRequests.Count - 1)
        $TransitiveResponses = Invoke-GraphBatch -Requests @($TransitiveRequests[$RequestStart..$RequestEnd])
        foreach ($Response in $TransitiveResponses) {
            $ResponseId = [string](Get-GraphField -InputObject $Response -Name 'id')
            if ($TransitiveMap.ContainsKey($ResponseId)) {
                $Metadata = $TransitiveMap[$ResponseId]
                Set-CountResult -Group $Metadata.Group -Kind $Metadata.Kind -Response $Response -Transitive
            }
        }
        $TransitiveBatchNumber++
        if ($TransitiveBatchNumber % 25 -eq 0) {
            Write-Progress -Activity 'Reading nested membership counts' -Status "$TransitiveBatchNumber of $TransitiveTotalBatches batches completed" -PercentComplete ([Math]::Min(100, [int](100 * $TransitiveBatchNumber / $TransitiveTotalBatches)))
            Write-Log -Message "$TransitiveBatchNumber of $TransitiveTotalBatches transitive batches completed." -Component 'Progress' -Type 1
        }
    }
    Write-Progress -Activity 'Reading nested membership counts' -Completed

    return $GroupIndex
}

function Resolve-GroupRelationship {
    param(
        [Parameter(Mandatory = $true)][object[]]$Groups,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string, object]]$GroupIndex
    )
    foreach ($Group in $Groups) {
        $Group.children = @($Group.children | Where-Object { $GroupIndex.ContainsKey([string]$_) } | Sort-Object -Unique)
        $Group.parents = @($Group.parents | Where-Object { $GroupIndex.ContainsKey([string]$_) } | Sort-Object -Unique)
        foreach ($ChildId in @($Group.children)) {
            if ($GroupIndex.ContainsKey([string]$ChildId)) {
                $Child = $GroupIndex[[string]$ChildId]
                $Child.parents = @($Child.parents) + [string]$Group.id
            }
        }
    }
    foreach ($Group in $Groups) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $null = $Visited.Add([string]$Group.id)
        $Queue = [System.Collections.Generic.Queue[string]]::new()
        foreach ($ChildId in @($Group.children)) { $Queue.Enqueue([string]$ChildId) }
        while ($Queue.Count -gt 0) {
            $CurrentId = $Queue.Dequeue()
            if (-not $GroupIndex.ContainsKey($CurrentId) -or -not $Visited.Add($CurrentId)) { continue }
            $CurrentGroup = $GroupIndex[$CurrentId]
            foreach ($DescendantId in @($CurrentGroup.children)) { $Queue.Enqueue([string]$DescendantId) }
        }
        $Group.counts.nested.groups = $Visited.Count - 1
        $Group.parents = @($Group.parents | Sort-Object -Unique)
        $Group.children = @($Group.children | Sort-Object -Unique)
    }
}

function Import-DangerousGroupDefinition {
    $Rules = [System.Collections.Generic.List[object]]::new()
    foreach ($DangerousValue in $DangerousGroup) {
        if ($DangerousValue -match '^[0-9a-fA-F-]{36}$') {
            $Rules.Add([pscustomobject]@{ id = $DangerousValue; reason = 'Configured as dangerous' })
        } elseif ($DangerousValue.Contains('*') -or $DangerousValue.Contains('?')) {
            $Rules.Add([pscustomobject]@{ namePattern = $DangerousValue; reason = 'Configured as dangerous' })
        } else {
            $Rules.Add([pscustomobject]@{ name = $DangerousValue; reason = 'Configured as dangerous' })
        }
    }
    if (Test-Path -LiteralPath $DangerousGroupFile -PathType Leaf) {
        $FileContent = Get-Content -LiteralPath $DangerousGroupFile -Raw | ConvertFrom-Json -AsHashtable
        if ($FileContent.schemaVersion -ne 1 -or -not $FileContent.ContainsKey('rules')) {
            throw "Dangerous-group file must contain schemaVersion 1 and a rules array: $DangerousGroupFile"
        }
        foreach ($Rule in $FileContent.rules) {
            $SupportedKeys = @('id', 'name', 'namePattern', 'reason')
            $UnknownKeys = @($Rule.Keys | Where-Object { $_ -notin $SupportedKeys })
            $Matchers = @('id', 'name', 'namePattern' | Where-Object { $Rule.ContainsKey($_) })
            if ($UnknownKeys.Count -gt 0 -or $Matchers.Count -ne 1) {
                throw 'Each dangerous-group rule must contain exactly one of id, name, or namePattern and no unknown fields.'
            }
            $Rules.Add([pscustomobject]$Rule)
        }
    }
    return @($Rules)
}

function ConvertTo-DangerRuleSchema {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rules)
    $SchemaRules = [System.Collections.Generic.List[object]]::new()
    foreach ($Rule in $Rules) {
        foreach ($PropertyName in @('id', 'name', 'namePattern')) {
            if ($Rule.$PropertyName) {
                $SchemaRules.Add([ordered]@{
                    match  = $PropertyName
                    value  = [string]$Rule.$PropertyName
                    reason = [string]$Rule.reason
                })
                break
            }
        }
    }
    return @($SchemaRules)
}

function Set-DangerousGroupFlag {
    param(
        [Parameter(Mandatory = $true)][object[]]$Groups,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rules,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string, object]]$GroupIndex
    )
    $DangerousIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $MatchedRuleIndexes = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($Group in $Groups) {
        $Reasons = [System.Collections.Generic.List[string]]::new()
        for ($RuleIndex = 0; $RuleIndex -lt $Rules.Count; $RuleIndex++) {
            $Rule = $Rules[$RuleIndex]
            $MatchesRule = $false
            $RuleId = Get-GraphField -InputObject $Rule -Name 'id'
            $RuleName = Get-GraphField -InputObject $Rule -Name 'name'
            $RulePattern = Get-GraphField -InputObject $Rule -Name 'namePattern'
            if ($RuleId -and [string]$RuleId -eq [string]$Group.id) { $MatchesRule = $true }
            if ($RuleName -and [string]$RuleName -eq [string]$Group.name) { $MatchesRule = $true }
            if ($RulePattern -and [string]$Group.name -like [string]$RulePattern) { $MatchesRule = $true }
            if ($MatchesRule) {
                $null = $MatchedRuleIndexes.Add($RuleIndex)
                $ReasonText = [string](Get-GraphField -InputObject $Rule -Name 'reason')
                if ([string]::IsNullOrWhiteSpace($ReasonText)) { $ReasonText = 'Configured as dangerous' }
                if ($ReasonText -notin $Reasons) { $Reasons.Add($ReasonText) }
            }
        }
        if ($TreatRoleAssignableAsDangerous -and $Group.roleAssignable) {
            $Reasons.Add('Role-assignable group')
        }
        $DangerData = [ordered]@{
            self          = $Reasons.Count -gt 0
            reason        = @($Reasons)
            nestedCount   = 0
            ancestorCount = 0
        }
        if ($Group -is [System.Collections.IDictionary]) {
            $Group['danger'] = $DangerData
        } else {
            $Group | Add-Member -MemberType NoteProperty -Name 'danger' -Value $DangerData -Force
        }
        if ($Reasons.Count -gt 0) { $null = $DangerousIds.Add([string]$Group.id) }
    }
    for ($RuleIndex = 0; $RuleIndex -lt $Rules.Count; $RuleIndex++) {
        if (-not $MatchedRuleIndexes.Contains($RuleIndex)) {
            $RuleValue = $Rules[$RuleIndex] | ConvertTo-Json -Compress
            Write-Warning "Dangerous-group rule did not match a group: $RuleValue"
        }
    }
    foreach ($DangerousId in $DangerousIds) {
        foreach ($Direction in @('children', 'parents')) {
            $Visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $null = $Visited.Add($DangerousId)
            $Queue = [System.Collections.Generic.Queue[string]]::new()
            foreach ($RelatedId in @($GroupIndex[$DangerousId].$Direction)) { $Queue.Enqueue([string]$RelatedId) }
            while ($Queue.Count -gt 0) {
                $RelatedId = $Queue.Dequeue()
                if (-not $GroupIndex.ContainsKey($RelatedId) -or -not $Visited.Add($RelatedId)) { continue }
                $RelatedGroup = $GroupIndex[$RelatedId]
                if ($Direction -eq 'children') { $RelatedGroup.danger.ancestorCount++ } else { $RelatedGroup.danger.nestedCount++ }
                foreach ($NextId in @($RelatedGroup.$Direction)) { $Queue.Enqueue([string]$NextId) }
            }
        }
    }
}

function ConvertTo-HtmlSafeJson {
    param([Parameter(Mandatory = $true)][object]$Data)
    $JsonText = $Data | ConvertTo-Json -Depth 15 -Compress
    return $JsonText.Replace('<', '\u003c').Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
}

function New-ExplorerHtml {
    param(
        [Parameter(Mandatory = $true)][object]$Data,
        [Parameter(Mandatory = $true)][string]$OutputFile
    )
    $TemplatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.template.html'
    $CssPath = Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.css'
    $LogicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.logic.js'
    $UiPath = Join-Path -Path $PSScriptRoot -ChildPath 'Templates\viewer.ui.js'
    # Browsers normalize CRLF/CR to LF before hashing inline code, so CSP hashes must use LF text.
    $NormalizeNewline = { param([string]$Text) $Text.Replace("`r`n", "`n").Replace("`r", "`n") }
    $CssText = & $NormalizeNewline (Get-Content -LiteralPath $CssPath -Raw)
    $ScriptText = & $NormalizeNewline ((Get-Content -LiteralPath $LogicPath -Raw) + "`n" + (Get-Content -LiteralPath $UiPath -Raw))
    $Utf8 = [System.Text.UTF8Encoding]::new($false)
    $CssHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($CssText)))
    $ScriptHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($ScriptText)))
    $CspValue = "default-src 'none'; script-src 'sha256-$ScriptHash'; style-src 'sha256-$CssHash'; base-uri 'none'; form-action 'none'"
    $HtmlText = & $NormalizeNewline (Get-Content -LiteralPath $TemplatePath -Raw)
    $HtmlText = $HtmlText.Replace('__EXPLORER_TITLE__', [System.Net.WebUtility]::HtmlEncode($OutputName))
    $HtmlText = $HtmlText.Replace('__EXPLORER_CSP__', $CspValue)
    $HtmlText = $HtmlText.Replace('__EXPLORER_CSS__', $CssText)
    $HtmlText = $HtmlText.Replace('__EXPLORER_DATA__', (ConvertTo-HtmlSafeJson -Data $Data))
    $HtmlText = $HtmlText.Replace('__EXPLORER_JS__', $ScriptText)
    if ($HtmlText -match '__EXPLORER_[A-Z_]+__') { throw 'HTML template contains an unresolved placeholder.' }
    Set-Content -LiteralPath $OutputFile -Value $HtmlText -Encoding utf8NoBOM -NoNewline
    $WrittenHtml = & $NormalizeNewline ([System.IO.File]::ReadAllText($OutputFile, $Utf8))
    $WrittenCsp = [regex]::Match($WrittenHtml, 'http-equiv="Content-Security-Policy" content="([^"]+)"')
    $WrittenCss = [regex]::Match($WrittenHtml, '<style>([\s\S]*?)</style>')
    $WrittenScript = [regex]::Match($WrittenHtml, '<script>([\s\S]*?)</script>')
    if (-not $WrittenCsp.Success -or -not $WrittenCss.Success -or -not $WrittenScript.Success) {
        throw 'Generated HTML is missing the CSP or an inline asset.'
    }
    $WrittenCssHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($WrittenCss.Groups[1].Value)))
    $WrittenScriptHash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData($Utf8.GetBytes($WrittenScript.Groups[1].Value)))
    if (-not $WrittenCsp.Groups[1].Value.Contains("'sha256-$WrittenCssHash'") -or
        -not $WrittenCsp.Groups[1].Value.Contains("'sha256-$WrittenScriptHash'")) {
        throw 'Generated CSP hashes do not match the written inline assets.'
    }
}

function Export-ExplorerData {
    param(
        [Parameter(Mandatory = $true)][object]$Data,
        [Parameter(Mandatory = $true)][string]$OutputFile
    )
    $Data | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $OutputFile -Encoding utf8NoBOM
}

function Write-Summary {
    param([object]$Data, [string]$JsonPath, [string]$HtmlPath)
    $DangerousCount = @($Data.groups | Where-Object { $_.danger.self }).Count
    $Message = "Groups: $($Data.summary.groups); dangerous: $DangerousCount; counts unavailable: $($Data.summary.unavailableCounts); JSON: $JsonPath"
    if ($HtmlPath) { $Message += "; HTML: $HtmlPath" }
    Write-Log -Message $Message -Component 'Summary' -Type 1
    Write-Output $Message
}

function Start-ExplorerExport {
    Initialize-Script
    Write-Log -Message 'Starting Entra group export.' -Component 'Startup' -Type 1
    Test-Prerequisite
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }
    $StartedAt = [datetime]::UtcNow
    if ($DataFile) {
        if (-not (Test-Path -LiteralPath $DataFile -PathType Leaf)) {
            throw "Data file was not found: $DataFile"
        }
        $Data = Get-Content -LiteralPath $DataFile -Raw | ConvertFrom-Json -AsHashtable
        if ($Data.schemaVersion -ne 1 -or -not $Data.ContainsKey('groups')) {
            throw 'The input data file must use schemaVersion 1 and contain a groups array.'
        }
        $Groups = @($Data.groups)
        $GroupIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Script:UnavailableGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($Group in $Groups) {
            if ($Group.flags -and (@($Group.flags) | Where-Object { $_ -in @('countsUnavailable', 'membersForbidden', 'notFound') })) {
                $null = $Script:UnavailableGroups.Add([string]$Group.id)
            }
            if (-not $Group.ContainsKey('counts')) {
                $Group.counts = @{ direct = @{ users = $null; devices = $null; groups = 0 }; nested = @{ users = $null; devices = $null; groups = 0 } }
            }
            if (-not $Group.ContainsKey('children')) { $Group.children = @() }
            if (-not $Group.ContainsKey('parents')) { $Group.parents = @() }
            $GroupIndex[[string]$Group.id] = $Group
        }
        $Groups = @($Groups | Where-Object { 'notFound' -notin $_.flags })
        $GroupIndex.Clear()
        foreach ($Group in $Groups) { $GroupIndex[[string]$Group.id] = $Group }
    } else {
        $Context = Connect-GraphSession
        $Groups = [System.Collections.Generic.List[object]]::new()
        foreach ($GraphGroup in (Get-AllGroup)) {
            $TypeInfo = Get-GroupType -Group $GraphGroup
            # Invoke-MgGraphRequest converts timestamps to DateTime; [string] would use the local culture.
            $CreatedValue = Get-GraphField -InputObject $GraphGroup -Name 'createdDateTime'
            if ($CreatedValue -is [datetime]) {
                $CreatedValue = $CreatedValue.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
            }
            $BasicGroup = [ordered]@{
                id               = [string](Get-GraphField -InputObject $GraphGroup -Name 'id')
                name             = [string](Get-GraphField -InputObject $GraphGroup -Name 'displayName')
                description      = [string](Get-GraphField -InputObject $GraphGroup -Name 'description')
                groupTypes       = @(Get-GraphField -InputObject $GraphGroup -Name 'groupTypes')
                mailEnabled      = [bool](Get-GraphField -InputObject $GraphGroup -Name 'mailEnabled')
                securityEnabled  = [bool](Get-GraphField -InputObject $GraphGroup -Name 'securityEnabled')
                type             = $TypeInfo.Type
                membership       = $TypeInfo.Membership
                roleAssignable   = [bool](Get-GraphField -InputObject $GraphGroup -Name 'isAssignableToRole')
                onPremSynced     = [bool](Get-GraphField -InputObject $GraphGroup -Name 'onPremisesSyncEnabled')
                created          = [string]$CreatedValue
                visibility       = [string](Get-GraphField -InputObject $GraphGroup -Name 'visibility')
                membershipRule   = [string](Get-GraphField -InputObject $GraphGroup -Name 'membershipRule')
                counts           = $null
                children         = @()
                parents          = @()
                flags            = @()
            }
            $Groups.Add([pscustomobject]$BasicGroup)
        }
        $Groups = @($Groups)
        $GroupIndex = Get-MembershipCount -Groups $Groups
        $Groups = @($Groups | Where-Object { 'notFound' -notin $_.flags })
        $GroupIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($Group in $Groups) {
            $Group.PSObject.Properties.Remove('visibility')
            if (-not $IncludeMembershipRule) { $Group.PSObject.Properties.Remove('membershipRule') }
            $Group.PSObject.Properties.Remove('groupTypes')
            $Group.PSObject.Properties.Remove('mailEnabled')
            $Group.PSObject.Properties.Remove('securityEnabled')
            $GroupIndex[[string]$Group.id] = $Group
        }
        $Data = [ordered]@{
            schemaVersion = 1
            generatedAt   = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
            generator     = @{ script = 'Export-EntraGroupExplorer.ps1'; version = '0.1.0' }
            tenantId      = [string]$Context.TenantId
            options       = @{ maxNameLength = $MaxNameLength; abbreviationStyle = $AbbreviationStyle; initialDepth = $InitialDepth; autoExpandLimit = $AutoExpandLimit }
            dangerRules   = @()
            summary       = @{}
            groups        = $Groups
        }
    }

    Resolve-GroupRelationship -Groups $Groups -GroupIndex $GroupIndex
    $Rules = [System.Collections.Generic.List[object]]::new()
    if ($DataFile -and $Data.dangerRules) {
        foreach ($ExistingRule in $Data.dangerRules) {
            $Matcher = [string]$ExistingRule.match
            if ($Matcher -in @('id', 'name', 'namePattern') -and $ExistingRule.value) {
                $Rules.Add([pscustomobject]@{
                    $Matcher = [string]$ExistingRule.value
                    reason  = [string]$ExistingRule.reason
                })
            }
        }
    }
    $Rules.AddRange(@(Import-DangerousGroupDefinition))
    $Rules = @($Rules)
    Set-DangerousGroupFlag -Groups $Groups -Rules $Rules -GroupIndex $GroupIndex
    $Data.groups = @($Groups)
    $Data.options = @{ maxNameLength = $MaxNameLength; abbreviationStyle = $AbbreviationStyle; initialDepth = $InitialDepth; autoExpandLimit = $AutoExpandLimit }
    $Data.dangerRules = ConvertTo-DangerRuleSchema -Rules $Rules
    $Data.generatedAt = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
    $Data.summary = @{
        groups             = $Groups.Count
        groupEdges         = (@($Groups | ForEach-Object { @($_.children).Count } | Measure-Object -Sum).Sum)
        dangerousGroups    = @($Groups | Where-Object { $_.danger.self }).Count
        unavailableCounts  = $Script:UnavailableGroups.Count
        durationSeconds    = [Math]::Round(([datetime]::UtcNow - $StartedAt).TotalSeconds, 1)
    }
    $Data.tenantId = if ($DataFile) { $Data.tenantId } else { [string]$Context.TenantId }

    do {
        $FileTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
        $JsonPath = Join-Path -Path $OutputPath -ChildPath "$($OutputName)_$FileTime.json"
        $HtmlPath = if ($SkipHtml) { $null } else { Join-Path -Path $OutputPath -ChildPath "$($OutputName)_$FileTime.html" }
        $PathExists = (Test-Path -LiteralPath $JsonPath) -or ($HtmlPath -and (Test-Path -LiteralPath $HtmlPath))
        if ($PathExists) { Start-Sleep -Milliseconds 1100 }
    } while ($PathExists)
    if ($DataFile -and [System.IO.Path]::GetFullPath($DataFile) -eq [System.IO.Path]::GetFullPath($JsonPath)) {
        throw 'Generated JSON path resolves to the input data file. Choose a different OutputPath or OutputName.'
    }
    try {
        Export-ExplorerData -Data $Data -OutputFile $JsonPath
        if ($HtmlPath) { New-ExplorerHtml -Data $Data -OutputFile $HtmlPath }
    } catch {
        Write-Log -Message "Output generation failed with $($_.Exception.GetType().Name)." -Component 'Output' -Type 3
        exit 3
    }
    Write-Summary -Data $Data -JsonPath $JsonPath -HtmlPath $HtmlPath
    if ($OpenReport -and $HtmlPath) { Start-Process -FilePath $HtmlPath }
    if ($Data.summary.groups -gt 0 -and (100 * $Data.summary.unavailableCounts / $Data.summary.groups) -gt $MaxUnavailablePercent) {
        Write-Log -Message "Unavailable count share exceeds $MaxUnavailablePercent percent." -Component 'Completeness' -Type 2
        exit 2
    }
}

try {
    Start-ExplorerExport
} catch {
    Write-Error $_
    Write-Log -Message "Export failed with $($_.Exception.GetType().Name)." -Component 'Failure' -Type 3
    exit 1
}
