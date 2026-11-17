<#
.SYNOPSIS
    Checks Microsoft Graph group count and membership behavior in a tenant.
.DESCRIPTION
    Runs the EntraGroupExplorer tenant probes with read-only Microsoft Graph requests. The script
    prints status, count, and resource-unit evidence without writing group or member data to disk.
    Provide test-group identifiers for probes that require a specific membership shape.
.PARAMETER TenantId
    Optional tenant identifier used when establishing a Microsoft Graph connection.
.PARAMETER GroupId
    Group used for T1, T2, and T3. T1 requires a session authenticated with only GroupMember.Read.All.
.PARAMETER TransitiveCountGroupId
    Fixture group used for T4. It should have two child groups that share at least one user.
.PARAMETER ServicePrincipalGroupId
    Group with a known service principal membership, used for T5.
.PARAMETER DistributionGroupId
    Assigned distribution group used for T7.
.PARAMETER HiddenMembershipGroupId
    Hidden-membership group used for T7. The signed-in identity must have access to its membership.
.PARAMETER LogPath
    Directory in which the log file is created. The default is the current directory.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.NOTES
    Version: 0.1
    Author: Martin Himken
    Original script name: Test-GraphProbe.ps1
    Initial creation date: 2026-11-12
    Last change: 2026-11-12
    Changes: Initial version
#>

[CmdletBinding()]
param(
    [string]$TenantId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$TransitiveCountGroupId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ServicePrincipalGroupId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$DistributionGroupId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$HiddenMembershipGroupId,
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
    $DefinedScriptName = 'Test-GraphProbe'
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
    $Script:ProbeResults = [System.Collections.Generic.List[object]]::new()
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

function Test-GraphFieldPresent {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($Key in $InputObject.Keys) {
            if ([string]::Equals([string]$Key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
        return $false
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )
    $RequestParameters = @{
        Method               = $Method
        Uri                  = $Uri
        SkipHttpErrorCheck   = $true
        StatusCodeVariable   = 'GraphStatusCode'
        ResponseHeadersVariable = 'GraphResponseHeaders'
        OutputType           = 'PSObject'
        ErrorAction          = 'Stop'
    }
    if ($Headers) { $RequestParameters.Headers = $Headers }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $RequestParameters.Body = $Body
        $RequestParameters.ContentType = 'application/json'
    }

    $GraphStatusCode = 0
    $GraphResponseHeaders = @{}
    $ResponseBody = Invoke-MgGraphRequest @RequestParameters
    return [pscustomobject]@{
        StatusCode = [int]$GraphStatusCode
        Body       = $ResponseBody
        Headers    = $GraphResponseHeaders
    }
}

function Get-CountFromBody {
    param([object]$Body)
    $CountValue = Get-GraphField -InputObject $Body -Name '@odata.count'
    if ($null -eq $CountValue) { return $null }
    try { return [long]$CountValue } catch { return $null }
}

function Get-ResourceUnit {
    param([object]$Headers)
    $ResourceUnit = Get-GraphField -InputObject $Headers -Name 'x-ms-resource-unit'
    if ($null -eq $ResourceUnit) { return $null }
    return [string]$ResourceUnit
}

function Add-ProbeResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Probe,
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [string]$Finding
    )
    $Script:ProbeResults.Add([pscustomobject]@{
        Probe   = $Probe
        Status  = $Status
        Finding = $Finding
    })
}

function New-CountRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    return [ordered]@{
        id      = $Id
        method  = 'GET'
        url     = $Path
        headers = @{ ConsistencyLevel = 'eventual' }
    }
}

function Invoke-GraphBatch {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Requests
    )
    $BatchBody = @{ requests = @($Requests) } | ConvertTo-Json -Depth 8 -Compress
    $BatchResult = Invoke-GraphRequest -Method POST -Uri "$($Script:GraphBaseUri)/`$batch" -Body $BatchBody
    $Responses = Get-GraphField -InputObject $BatchResult.Body -Name 'responses'
    return [pscustomobject]@{
        StatusCode = $BatchResult.StatusCode
        Responses  = @($Responses)
    }
}

function Get-ResponseById {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Responses,
        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    foreach ($Response in $Responses) {
        if ([string](Get-GraphField -InputObject $Response -Name 'id') -eq $Id) {
            return $Response
        }
    }
    return $null
}

function Get-ResponseStatus {
    param([object]$Response)
    $ResponseStatus = Get-GraphField -InputObject $Response -Name 'status'
    if ($null -eq $ResponseStatus) { return 0 }
    return [int]$ResponseStatus
}

function Get-ResponseCount {
    param([object]$Response)
    return Get-CountFromBody -Body (Get-GraphField -InputObject $Response -Name 'body')
}

function Get-GroupPage {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $PageResult = Invoke-GraphRequest -Method GET -Uri $Uri -Headers @{ ConsistencyLevel = 'eventual' }
    if ($PageResult.StatusCode -lt 200 -or $PageResult.StatusCode -ge 300) {
        throw "Graph group-page request returned HTTP $($PageResult.StatusCode)."
    }
    return $PageResult.Body
}

function Get-AllGroupIds {
    $NextUri = "$($Script:GraphBaseUri)/groups?`$select=id&`$top=999"
    $TotalGroups = 0L
    while ($NextUri) {
        $PageBody = Get-GroupPage -Uri $NextUri
        $PageValues = Get-GraphField -InputObject $PageBody -Name 'value'
        $TotalGroups += @($PageValues).Count
        $NextUri = [string](Get-GraphField -InputObject $PageBody -Name '@odata.nextLink')
    }
    return $TotalGroups
}

function Get-GroupChildren {
    param([Parameter(Mandatory = $true)][string]$Id)
    $ChildIds = [System.Collections.Generic.List[string]]::new()
    $NextUri = "$($Script:GraphBaseUri)/groups/$Id/members/microsoft.graph.group?`$select=id&`$top=999"
    while ($NextUri) {
        $PageResult = Invoke-GraphRequest -Method GET -Uri $NextUri -Headers @{ ConsistencyLevel = 'eventual' }
        if ($PageResult.StatusCode -lt 200 -or $PageResult.StatusCode -ge 300) {
            throw "Graph child-group request returned HTTP $($PageResult.StatusCode)."
        }
        $PageValues = Get-GraphField -InputObject $PageResult.Body -Name 'value'
        foreach ($Child in @($PageValues)) {
            $ChildId = [string](Get-GraphField -InputObject $Child -Name 'id')
            if ($ChildId) { $ChildIds.Add($ChildId) }
        }
        $NextUri = [string](Get-GraphField -InputObject $PageResult.Body -Name '@odata.nextLink')
    }
    return @($ChildIds)
}

function Invoke-CountProbeBatch {
    param([object[]]$Requests)
    $ProbeResponses = [System.Collections.Generic.List[object]]::new()
    for ($BatchStart = 0; $BatchStart -lt $Requests.Count; $BatchStart += 20) {
        $BatchEnd = [Math]::Min($BatchStart + 19, $Requests.Count - 1)
        $BatchResult = Invoke-GraphBatch -Requests @($Requests[$BatchStart..$BatchEnd])
        if ($BatchResult.StatusCode -lt 200 -or $BatchResult.StatusCode -ge 300) {
            throw "Graph batch request returned HTTP $($BatchResult.StatusCode)."
        }
        $ProbeResponses.AddRange(@($BatchResult.Responses))
    }
    return @($ProbeResponses)
}

function Invoke-GroupProbeSet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$RequestId,
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )
    $ProbeRequests = [System.Collections.Generic.List[object]]::new()
    for ($PathIndex = 0; $PathIndex -lt $Paths.Count; $PathIndex++) {
        $ProbeRequests.Add((New-CountRequest -Id "$RequestId$PathIndex" -Path "/groups/$Id/$($Paths[$PathIndex])"))
    }
    return Invoke-CountProbeBatch -Requests @($ProbeRequests)
}

function Invoke-TenantProbes {
    $CurrentContext = Get-MgContext
    if (-not $CurrentContext) {
        $ConnectParameters = @{ Scopes = @('GroupMember.Read.All'); NoWelcome = $true; ErrorAction = 'Stop' }
        if ($TenantId) { $ConnectParameters.TenantId = $TenantId }
        Write-Log -Message 'Connecting to Microsoft Graph with GroupMember.Read.All.' -Component 'Connect' -Type 1
        Connect-MgGraph @ConnectParameters | Out-Null
        $CurrentContext = Get-MgContext
    }
    if (-not $CurrentContext) { throw 'A Microsoft Graph context is required.' }

    $ContextScopes = @($CurrentContext.Scopes | Where-Object { $_ })
    $T1ScopeIsolated = $ContextScopes.Count -eq 1 -and $ContextScopes[0] -eq 'GroupMember.Read.All'

    if ($GroupId) {
        if (-not $T1ScopeIsolated) {
            Add-ProbeResult -Probe 'T1' -Status 'Inconclusive' -Finding 'Run in a fresh session authenticated with only GroupMember.Read.All.'
        } else {
            $SelectedFields = 'id,displayName,isAssignableToRole,membershipRule,onPremisesSyncEnabled'
            $T1Result = Invoke-GraphRequest -Method GET -Uri "$($Script:GraphBaseUri)/groups/$GroupId?`$select=$SelectedFields"
            if ($T1Result.StatusCode -eq 200) {
                $FieldResults = foreach ($FieldName in @('isAssignableToRole', 'membershipRule', 'onPremisesSyncEnabled')) {
                    $HasField = Test-GraphFieldPresent -InputObject $T1Result.Body -Name $FieldName
                    "$FieldName=$HasField"
                }
                Add-ProbeResult -Probe 'T1' -Status 'Complete' -Finding ($FieldResults -join ', ')
            } else {
                Add-ProbeResult -Probe 'T1' -Status "HTTP $($T1Result.StatusCode)" -Finding 'Group property select was not successful.'
            }
        }

        $DirectUserPath = 'members/microsoft.graph.user?$count=true&$top=1&$select=id'
        $TransitiveUserPath = 'transitiveMembers/microsoft.graph.user?$count=true&$top=1&$select=id'
        $T2Response = Invoke-CountProbeBatch -Requests @(
            (New-CountRequest -Id 'T2' -Path "/groups/$GroupId/$DirectUserPath")
        )
        $T2 = Get-ResponseById -Responses $T2Response -Id 'T2'
        $T2Count = Get-ResponseCount -Response $T2
        $T2StatusCode = Get-ResponseStatus -Response $T2
        $T2Ru = Get-ResourceUnit -Headers (Get-GraphField -InputObject $T2 -Name 'headers')
        $T2Finding = "HTTP $T2StatusCode, count=$T2Count"
        if ($T2Ru) { $T2Finding += ", RU=$T2Ru" }
        Add-ProbeResult -Probe 'T2' -Status $(if ($T2StatusCode -eq 200 -and $null -ne $T2Count) { 'Complete' } else { 'Review' }) -Finding $T2Finding

        $T3Response = Invoke-CountProbeBatch -Requests @(
            (New-CountRequest -Id 'T3' -Path "/groups/$GroupId/$TransitiveUserPath")
        )
        $T3 = Get-ResponseById -Responses $T3Response -Id 'T3'
        $T3Count = Get-ResponseCount -Response $T3
        $T3StatusCode = Get-ResponseStatus -Response $T3
        $T3Ru = Get-ResourceUnit -Headers (Get-GraphField -InputObject $T3 -Name 'headers')
        $T3Finding = "HTTP $T3StatusCode, count=$T3Count"
        if ($T3Ru) { $T3Finding += ", RU=$T3Ru" }
        Add-ProbeResult -Probe 'T3' -Status $(if ($T3StatusCode -eq 200 -and $null -ne $T3Count) { 'Complete' } else { 'Review' }) -Finding $T3Finding
    } else {
        foreach ($ProbeName in @('T1', 'T2', 'T3')) {
            Add-ProbeResult -Probe $ProbeName -Status 'Skipped' -Finding 'Supply -GroupId to run this probe.'
        }
    }

    if ($TransitiveCountGroupId) {
        $ChildIds = @(Get-GroupChildren -Id $TransitiveCountGroupId)
        $T4DirectRequests = @(
            (New-CountRequest -Id 'rootDirect' -Path "/groups/$TransitiveCountGroupId/members/microsoft.graph.user?`$count=true&`$top=1&`$select=id"),
            (New-CountRequest -Id 'rootTransitive' -Path "/groups/$TransitiveCountGroupId/transitiveMembers/microsoft.graph.user?`$count=true&`$top=1&`$select=id")
        )
        $ChildRequestIndex = 0
        foreach ($ChildId in $ChildIds) {
            $T4DirectRequests += New-CountRequest -Id "child$ChildRequestIndex" -Path "/groups/$ChildId/transitiveMembers/microsoft.graph.user?`$count=true&`$top=1&`$select=id"
            $ChildRequestIndex++
        }
        $T4Responses = [System.Collections.Generic.List[object]]::new()
        for ($BatchStart = 0; $BatchStart -lt $T4DirectRequests.Count; $BatchStart += 20) {
            $BatchEnd = [Math]::Min($BatchStart + 19, $T4DirectRequests.Count - 1)
            $T4Responses.AddRange(@(Invoke-CountProbeBatch -Requests @($T4DirectRequests[$BatchStart..$BatchEnd])))
        }
        $RootDirect = Get-ResponseCount -Response (Get-ResponseById -Responses @($T4Responses) -Id 'rootDirect')
        $RootTransitive = Get-ResponseCount -Response (Get-ResponseById -Responses @($T4Responses) -Id 'rootTransitive')
        $ChildCountTotal = 0L
        $T4Complete = $null -ne $RootDirect -and $null -ne $RootTransitive -and $ChildIds.Count -gt 0
        for ($ChildIndex = 0; $ChildIndex -lt $ChildIds.Count; $ChildIndex++) {
            $ChildCount = Get-ResponseCount -Response (Get-ResponseById -Responses @($T4Responses) -Id "child$ChildIndex")
            if ($null -eq $ChildCount) { $T4Complete = $false } else { $ChildCountTotal += $ChildCount }
        }
        if ($T4Complete) {
            $AdditiveCount = $RootDirect + $ChildCountTotal
            if ($ChildIds.Count -eq 2 -and $RootDirect -eq 0 -and $ChildCountTotal -eq 2 -and $RootTransitive -eq 1) {
                $T4Status = 'Distinct'
                $T4Finding = "Root=$RootTransitive, additive=$AdditiveCount, childGroups=$($ChildIds.Count); overlap was deduplicated."
            } else {
                $T4Status = 'Inconclusive'
                $T4Finding = "Root=$RootTransitive, additive=$AdditiveCount, directUsers=$RootDirect, childGroups=$($ChildIds.Count); fixture must contain two groups and one shared user."
            }
        } else {
            $T4Status = 'Review'
            $T4Finding = "childGroups=$($ChildIds.Count); one or more count requests were unavailable."
        }
        Add-ProbeResult -Probe 'T4' -Status $T4Status -Finding $T4Finding
    } else {
        Add-ProbeResult -Probe 'T4' -Status 'Skipped' -Finding 'Supply -TransitiveCountGroupId for a group with overlapping child membership.'
    }

    if ($ServicePrincipalGroupId) {
        $T5Paths = @(
            'members?$count=true&$top=1&$select=id',
            'members/microsoft.graph.servicePrincipal?$count=true&$top=1&$select=id',
            'transitiveMembers?$count=true&$top=1&$select=id',
            'transitiveMembers/microsoft.graph.servicePrincipal?$count=true&$top=1&$select=id'
        )
        $T5Labels = @('directTotal', 'directServicePrincipals', 'transitiveTotal', 'transitiveServicePrincipals')
        $T5Responses = @(Invoke-GroupProbeSet -Id $ServicePrincipalGroupId -RequestId 'T5' -Paths $T5Paths)
        $T5Parts = [System.Collections.Generic.List[string]]::new()
        $T5HasData = $false
        for ($T5Index = 0; $T5Index -lt $T5Paths.Count; $T5Index++) {
            $T5Response = Get-ResponseById -Responses $T5Responses -Id "T5$T5Index"
            $T5StatusCode = Get-ResponseStatus -Response $T5Response
            $T5Count = Get-ResponseCount -Response $T5Response
            $T5Parts.Add("$($T5Labels[$T5Index])=HTTP $T5StatusCode,count=$T5Count")
            if ($T5StatusCode -eq 200 -and $null -ne $T5Count) { $T5HasData = $true }
        }
        Add-ProbeResult -Probe 'T5' -Status $(if ($T5HasData) { 'Complete' } else { 'Review' }) -Finding ($T5Parts -join '; ')
    } else {
        Add-ProbeResult -Probe 'T5' -Status 'Skipped' -Finding 'Supply -ServicePrincipalGroupId for a group with a known service principal member.'
    }

    $T6Units = [System.Collections.Generic.List[string]]::new()
    foreach ($ProbeId in @('T2', 'T3')) {
        $ProbeResult = $Script:ProbeResults | Where-Object { $_.Probe -eq $ProbeId } | Select-Object -Last 1
        if ($ProbeResult -and $ProbeResult.Finding -match 'RU=([^,;]+)') {
            $T6Units.Add("$ProbeId=$($Matches[1])")
        }
    }
    if ($T6Units.Count -gt 0) {
        Add-ProbeResult -Probe 'T6' -Status 'Complete' -Finding ($T6Units -join ', ')
    } else {
        Add-ProbeResult -Probe 'T6' -Status 'Review' -Finding 'Graph did not return x-ms-resource-unit in the available batch responses.'
    }

    foreach ($TypeProbe in @(
        [pscustomobject]@{ Name = 'Distribution'; Id = $DistributionGroupId },
        [pscustomobject]@{ Name = 'HiddenMembership'; Id = $HiddenMembershipGroupId }
    )) {
        if (-not $TypeProbe.Id) { continue }
        $T7Paths = @(
            'members/microsoft.graph.user?$count=true&$top=1&$select=id',
            'members/microsoft.graph.device?$count=true&$top=1&$select=id',
            'members/microsoft.graph.group?$count=true&$top=1&$select=id'
        )
        $T7Responses = @(Invoke-GroupProbeSet -Id $TypeProbe.Id -RequestId $TypeProbe.Name -Paths $T7Paths)
        $T7Parts = [System.Collections.Generic.List[string]]::new()
        for ($T7Index = 0; $T7Index -lt $T7Paths.Count; $T7Index++) {
            $T7Response = Get-ResponseById -Responses $T7Responses -Id "$($TypeProbe.Name)$T7Index"
            $T7StatusCode = Get-ResponseStatus -Response $T7Response
            $T7Count = Get-ResponseCount -Response $T7Response
            $T7Parts.Add("$(@('user', 'device', 'group')[$T7Index])=HTTP $T7StatusCode,count=$T7Count")
        }
        Add-ProbeResult -Probe "T7-$($TypeProbe.Name)" -Status 'Complete' -Finding ($T7Parts -join '; ')
    }
    if (-not $DistributionGroupId) {
        Add-ProbeResult -Probe 'T7-Distribution' -Status 'Skipped' -Finding 'Supply -DistributionGroupId to probe an assigned distribution group.'
    }
    if (-not $HiddenMembershipGroupId) {
        Add-ProbeResult -Probe 'T7-HiddenMembership' -Status 'Skipped' -Finding 'Supply -HiddenMembershipGroupId to probe a hidden-membership group.'
    }

    $CountResult = Invoke-GraphRequest -Method GET -Uri "$($Script:GraphBaseUri)/groups?`$count=true&`$top=1&`$select=id" -Headers @{ ConsistencyLevel = 'eventual' }
    if ($CountResult.StatusCode -eq 200) {
        $ReportedCount = Get-CountFromBody -Body $CountResult.Body
        $EnumeratedCount = Get-AllGroupIds
        $T8Status = if ($null -ne $ReportedCount -and $ReportedCount -eq $EnumeratedCount) { 'Match' } else { 'Review' }
        Add-ProbeResult -Probe 'T8' -Status $T8Status -Finding "reported=$ReportedCount, enumerated=$EnumeratedCount"
    } else {
        Add-ProbeResult -Probe 'T8' -Status "HTTP $($CountResult.StatusCode)" -Finding 'Group count request was not successful.'
    }
}

function Start-GraphProbe {
    Initialize-Script
    Write-Log -Message 'Starting read-only tenant probes. No group or member data is written to disk.' -Component 'Start' -Type 1
    $Module = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $Module) {
        throw 'Microsoft.Graph.Authentication is required. Install the module and run the probe again.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $GraphCommand = Get-Command Invoke-MgGraphRequest -ErrorAction Stop
    foreach ($RequiredParameter in @('SkipHttpErrorCheck', 'StatusCodeVariable', 'ResponseHeadersVariable', 'OutputType')) {
        if (-not $GraphCommand.Parameters.ContainsKey($RequiredParameter)) {
            throw "Microsoft.Graph.Authentication must support -$RequiredParameter. Update the module and run the probe again."
        }
    }
    Invoke-TenantProbes
    $Script:ProbeResults | Format-Table -Property Probe, Status, Finding -Wrap -AutoSize
    Write-Log -Message "Completed $($Script:ProbeResults.Count) probe results." -Component 'Complete' -Type 1
}

try {
    Start-GraphProbe
} catch {
    Write-Error $_
    Write-Log -Message "Probe failed with $($_.Exception.GetType().Name)." -Component 'Failure' -Type 3
    exit 1
}
