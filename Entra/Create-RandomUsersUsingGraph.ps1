<#
.SYNOPSIS
    Creates or deletes random test users in Microsoft Entra ID through Microsoft Graph JSON batches.
.DESCRIPTION
    Create mode downloads a list of random words, builds the requested number of users with unique user principal
    names and random passwords, and creates the users through Microsoft Graph JSON batches of 20 requests.
    Every created user gets an officeLocation value that starts with 'RandomOffice'.
    Delete mode reads every user whose officeLocation starts with 'RandomOffice' and deletes these users through
    Microsoft Graph JSON batches of 20 requests.
    The batches run in parallel thread jobs. Each thread job loads its own copy of the GraphRetry block from the
    handle-graph-throttling skill, so every batch honors Retry-After on 429 and 503 responses and sends only the
    throttled inner requests again. The main thread writes the log entries of all thread jobs to the log file and
    adds their retry statistics to the final Graph retry summary.
    The script writes one summary object to the pipeline. Passwords are never logged or returned.
    Required Microsoft Graph permission: User.ReadWrite.All (application or delegated).
.PARAMETER Mode
    Create creates new random users. Delete removes all users whose officeLocation starts with 'RandomOffice'.
    The default is Create.
.PARAMETER NumberOfUsers
    Number of random users to create in Create mode. The default is 1000.
.PARAMETER UserPrincipalNameSuffix
    Verified domain used as the user principal name suffix of the created users. Alias: UPN.
.PARAMETER WordListUri
    URI of a web service that returns a JSON array of words. The words are combined into first and last names.
.PARAMETER ClientId
    Application (client) ID used to connect to Microsoft Graph. Required for certificate authentication.
.PARAMETER CertificateThumbprint
    Thumbprint of the certificate used for app-only authentication. When omitted, the script connects interactively
    with the User.ReadWrite.All scope. An existing Microsoft Graph connection is always reused.
.PARAMETER TenantId
    Tenant ID used to connect to Microsoft Graph. Required for certificate authentication.
.PARAMETER GraphApiVersion
    Microsoft Graph API version for all requests. The default is beta.
.PARAMETER ThrottleLimit
    Maximum number of thread jobs that send batches at the same time. The default and maximum is 5.
.PARAMETER LogPath
    Directory in which the log file is created. The default is the current directory.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.EXAMPLE
    .\Create-RandomUsersUsingGraph.ps1 -NumberOfUsers 200 -UserPrincipalNameSuffix contoso.com
    Connects interactively and creates 200 random users.
.EXAMPLE
    .\Create-RandomUsersUsingGraph.ps1 -Mode Delete -ClientId <AppId> -TenantId <TenantId> -CertificateThumbprint <Thumbprint>
    Connects with a certificate and deletes all users created by this script.
.NOTES
    Version: 2.0
    Author: Martin Himken
    Original script name: Create-RandomUsersUsingGraph.ps1
    Initial creation date: 2025-07-29
    Last change: 2026-11-17
    Changes: Refactored with the create-powershell-script and handle-graph-throttling skills. Added the PowerShell 7.4
    check, the Mode parameter (default Create), LogPath and LogFile parameters, interactive and certificate
    authentication, unique user names, and a summary object. Every Graph request now runs through
    the GraphRetry block, and each parallel thread job loads its own copy of the block. Removed WorkingDirectory,
    LogDirectory, LogPrefix, CreateMode, and DeleteMode.
#>

[CmdletBinding()]
param(
    [ValidateSet('Create', 'Delete')]
    [string]$Mode = 'Create',
    [ValidateRange(1, 100000)]
    [int]$NumberOfUsers = 1000,
    [Alias('UPN')]
    [string]$UserPrincipalNameSuffix = 'intune.best',
    [string]$WordListUri = 'https://random-word-api.herokuapp.com/word?number=5000&length=8&lang=de',
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$TenantId,
    [ValidateSet('beta', 'v1.0')]
    [string]$GraphApiVersion = 'beta',
    [ValidateRange(1, 5)]
    [int]$ThrottleLimit = 5,
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null
)

$Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $Pwsh7Path) {
    Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    exit 1
}
if ($PSVersionTable.PSVersion -lt [version]'7.4') {
    Write-Error 'This script requires PowerShell 7.4 or later. Start the script with pwsh.exe.'
    exit 1
}

function Write-Log {
    <#
    .DESCRIPTION
    This is a (heavily) modified version of the script by Ryan Ephgrave.
    .LINK
    https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
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
    # Default log file name uses a file-system-safe ISO 8601 date-time with a 24-hour timestamp.
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Create-RandomUsersUsingGraph'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    if (-not $LogFile) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:ToConsole = $false
    $Script:GraphBaseUri = "https://graph.microsoft.com/$GraphApiVersion"
    $Script:JobNamePrefix = 'RUUG'
    $Script:OfficeLocationMarker = 'RandomOffice'
    $Script:BatchSize = 20
    # Thread jobs from an earlier run that stopped unexpectedly are removed before new jobs start.
    Get-Job -Name "$($Script:JobNamePrefix)-*" -ErrorAction SilentlyContinue | Remove-Job -Force
    $Script:GraphRetryBlockText = Get-GraphRetryBlockText
    # Each thread job defines a Write-Log that collects entries in memory. The main thread writes them to the log file,
    # so only one thread writes to the file.
    $Script:BatchJobScript = {
        param(
            [string]$GraphRetryBlockText,
            [object[]]$BatchRequests,
            [string]$BatchUri,
            [int]$BatchNumber
        )
        $JobLogEntries = [System.Collections.Generic.List[object]]::new()
        function Write-Log {
            Param (
                [Parameter(Mandatory = $false)]
                $Message,
                $Component,
                [ValidateSet('1', '2', '3')]
                [int]$Type
            )
            $JobLogEntries.Add([pscustomobject]@{
                    Message   = $Message
                    Component = $Component
                    Type      = $Type
                })
        }
        . ([scriptblock]::Create($GraphRetryBlockText))
        $BatchResults = @()
        $BatchFailureMessage = $null
        try {
            Initialize-GraphRetry -ScriptType Script -Transport MgGraphRequest
            $BatchResults = @(Invoke-GraphBatchWithRetry -Requests $BatchRequests -BatchUri $BatchUri)
        } catch {
            $BatchFailureMessage = $_.Exception.Message
        }
        [pscustomobject]@{
            BatchNumber    = $BatchNumber
            Results        = $BatchResults
            FailureMessage = $BatchFailureMessage
            LogEntries     = $JobLogEntries.ToArray()
            Statistics     = $Script:GraphRetryStatistics
        }
    }
}

#region GraphRetry 1.0.0
# Microsoft Graph throttling and retry functions from the handle-graph-throttling skill.
# Single source: .github\skills\handle-graph-throttling\references\GraphRetryFunctions.ps1 in the toolbox repository.
# Change the single source only, then run tools\Update-GraphRetryBlock.ps1 to refresh every copy.
# Requires PowerShell 7.4 or later. Call Initialize-GraphRetry once before the first Graph request.
# Sources:
#   https://learn.microsoft.com/graph/throttling
#   https://learn.microsoft.com/graph/throttling-limits
#   https://learn.microsoft.com/graph/json-batching
#   https://www.rfc-editor.org/rfc/rfc9110#field.retry-after
#   https://learn.microsoft.com/azure/architecture/best-practices/transient-faults
#   https://learn.microsoft.com/azure/automation/automation-runbook-output-and-messages

function Initialize-GraphRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Script', 'Runbook')]
        [string]$ScriptType,

        [ValidateSet('RestMethod', 'MgGraphRequest')]
        [string]$Transport = 'RestMethod',

        [ValidateRange(0, 100)]
        [int]$MaximumRetryCount = 10,

        [ValidateRange(0, 86400)]
        [int]$MaximumTotalWaitSeconds = 900,

        [ValidateRange(0.001, 600)]
        [double]$BaseDelaySeconds = 2,

        [ValidateRange(0.001, 3600)]
        [double]$MaximumBackoffSeconds = 60,

        [ValidateRange(0, 1)]
        [double]$JitterRatio = 0.25,

        [ValidateRange(0, 60000)]
        [int]$MinimumRetryDelayMilliseconds = 1000,

        [ValidateRange(0, 60000)]
        [int]$RetryAfterJitterMilliseconds = 1000
    )
    if ($ScriptType -eq 'Script' -and -not (Get-Command -Name 'Write-Log' -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'ScriptType Script requires the Write-Log function. Define Write-Log before calling Initialize-GraphRetry, or use ScriptType Runbook.'
    }
    $Script:GraphRetrySettings = [ordered]@{
        MaximumRetryCount             = $MaximumRetryCount
        MaximumTotalWaitSeconds       = $MaximumTotalWaitSeconds
        BaseDelaySeconds              = $BaseDelaySeconds
        MaximumBackoffSeconds         = $MaximumBackoffSeconds
        JitterRatio                   = $JitterRatio
        MinimumRetryDelayMilliseconds = $MinimumRetryDelayMilliseconds
        RetryAfterJitterMilliseconds  = $RetryAfterJitterMilliseconds
        Transport                     = $Transport
        ScriptType                    = $ScriptType
    }
    $Script:GraphRetryStatistics = [ordered]@{
        Requests                  = 0
        Retries                   = 0
        ThrottleRetries           = 0
        ServiceUnavailableRetries = 0
        GatewayTimeoutRetries     = 0
        RetryAfterWaits           = 0
        BackoffWaits              = 0
        TotalWaitMilliseconds     = [long]0
    }
    if ($Transport -eq 'MgGraphRequest') {
        # The Graph SDK has its own retry handler. MaxRetry 0 keeps this block as the only retry layer.
        $null = Set-MgRequestContext -MaxRetry 0
    }
}

function Confirm-GraphRetryInitialized {
    param()
    if (-not (Get-Variable -Name 'GraphRetrySettings' -Scope Script -ErrorAction SilentlyContinue)) {
        throw 'Graph retry settings are missing. Call Initialize-GraphRetry before the first Graph request.'
    }
}

function Get-GraphPropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $PropertyValue = $null
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($DictionaryKey in $InputObject.Keys) {
            if ([string]$DictionaryKey -ieq $Name) {
                $PropertyValue = $InputObject[$DictionaryKey]
                break
            }
        }
    } else {
        $MatchingProperty = $InputObject.PSObject.Properties[$Name]
        if ($MatchingProperty) { $PropertyValue = $MatchingProperty.Value }
    }
    # The unary comma returns arrays as one object, so a one-item value array stays an array.
    return , $PropertyValue
}

function Get-GraphHeaderValue {
    param(
        [AllowNull()]
        [object]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $HeaderValue = Get-GraphPropertyValue -InputObject $Headers -Name $Name
    if ($null -eq $HeaderValue) { return $null }
    $HeaderValues = @($HeaderValue)
    if ($HeaderValues.Count -eq 0 -or $null -eq $HeaderValues[0]) { return $null }
    return ([string]$HeaderValues[0]).Trim()
}

function Get-GraphRetryAfterDelay {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$RetryAfterValue
    )
    if (-not $RetryAfterValue) { return $null }
    $TrimmedValue = $RetryAfterValue.Trim()
    if ($TrimmedValue.Length -eq 0) { return $null }
    if ($TrimmedValue -match '^[0-9]{1,9}$') {
        return ([long]$TrimmedValue) * 1000
    }
    # The typed variable lets PowerShell select the TryParseExact overload with an out DateTimeOffset.
    [System.DateTimeOffset]$ParsedRetryDate = [System.DateTimeOffset]::MinValue
    $IsHttpDate = [System.DateTimeOffset]::TryParseExact(
        $TrimmedValue,
        'r',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$ParsedRetryDate
    )
    if (-not $IsHttpDate) { return $null }
    $TimeUntilRetry = New-TimeSpan -Start (Get-Date -AsUTC) -End $ParsedRetryDate.UtcDateTime
    return [long][System.Math]::Ceiling($TimeUntilRetry.TotalMilliseconds)
}

function Get-GraphBackoffDelay {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$RetryNumber
    )
    $Settings = $Script:GraphRetrySettings
    $ExponentialSeconds = $Settings.BaseDelaySeconds * [System.Math]::Pow(2, $RetryNumber - 1)
    $CappedMilliseconds = [System.Math]::Min($ExponentialSeconds, $Settings.MaximumBackoffSeconds) * 1000
    # Jitter is added after the cap, so one wait is at most MaximumBackoffSeconds * (1 + JitterRatio).
    $JitterCeiling = [long][System.Math]::Floor($CappedMilliseconds * $Settings.JitterRatio)
    $JitterMilliseconds = 0
    if ($JitterCeiling -gt 0) {
        $JitterMilliseconds = Get-Random -Minimum 0 -Maximum ($JitterCeiling + 1)
    }
    return [long][System.Math]::Ceiling($CappedMilliseconds + $JitterMilliseconds)
}

function Test-GraphRetryableResponse {
    param(
        [Parameter(Mandatory = $true)]
        [int]$StatusCode,

        [Parameter(Mandatory = $true)]
        [string]$Method
    )
    if ($StatusCode -eq 429 -or $StatusCode -eq 503) { return $true }
    # A 504 can arrive after the service processed the request, so only idempotent methods retry it.
    if ($StatusCode -eq 504 -and $Method -in @('GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE')) { return $true }
    return $false
}

function Get-GraphErrorDetail {
    param(
        [AllowNull()]
        [object]$ResponseBody,

        [AllowNull()]
        [object]$Headers
    )
    $ParsedBody = $ResponseBody
    if ($ResponseBody -is [string]) {
        $ParsedBody = $null
        if ($ResponseBody.TrimStart().StartsWith('{')) {
            try {
                $ParsedBody = ConvertFrom-Json -InputObject $ResponseBody -ErrorAction Stop
            } catch {
                Write-Verbose -Message "The Graph error body is not valid JSON: $($_.Exception.Message)"
            }
        }
    }
    $GraphError = Get-GraphPropertyValue -InputObject $ParsedBody -Name 'error'
    $InnerError = Get-GraphPropertyValue -InputObject $GraphError -Name 'innerError'
    $RequestId = Get-GraphPropertyValue -InputObject $InnerError -Name 'request-id'
    if (-not $RequestId) { $RequestId = Get-GraphHeaderValue -Headers $Headers -Name 'request-id' }
    $ClientRequestId = Get-GraphPropertyValue -InputObject $InnerError -Name 'client-request-id'
    if (-not $ClientRequestId) { $ClientRequestId = Get-GraphHeaderValue -Headers $Headers -Name 'client-request-id' }
    $ErrorDate = Get-GraphPropertyValue -InputObject $InnerError -Name 'date'
    if (-not $ErrorDate) { $ErrorDate = Get-GraphHeaderValue -Headers $Headers -Name 'Date' }
    if ($ErrorDate -is [datetime]) { $ErrorDate = Get-Date -Date $ErrorDate -Format 'o' }
    return [pscustomobject]@{
        Code            = [string](Get-GraphPropertyValue -InputObject $GraphError -Name 'code')
        Message         = [string](Get-GraphPropertyValue -InputObject $GraphError -Name 'message')
        RequestId       = [string]$RequestId
        ClientRequestId = [string]$ClientRequestId
        Date            = [string]$ErrorDate
    }
}

function Write-GraphRetryMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('Information', 'Warning', 'Verbose', 'Error')]
        [string]$Level = 'Information',

        [string]$Detail
    )
    if ($Script:GraphRetrySettings.ScriptType -eq 'Runbook') {
        # Runbook streams: Output, Warning, and Error reach the job history. Verbose needs verbose logging on the runbook.
        # The Error level writes nothing here because the throw that follows creates the error record.
        switch ($Level) {
            'Information' { Write-Output -InputObject $Message }
            'Warning' { Write-Warning -Message $Message }
            'Verbose' { Write-Verbose -Message $Message }
        }
        if ($Detail -and $Level -ne 'Error') { Write-Verbose -Message $Detail }
        return
    }
    $LogMessage = $Message
    if ($Detail) { $LogMessage = "$Message $Detail" }
    switch ($Level) {
        'Information' { Write-Log -Message $LogMessage -Component 'GraphRetry' -Type 1 }
        'Warning' { Write-Log -Message $LogMessage -Component 'GraphRetry' -Type 2 }
        'Error' { Write-Log -Message $LogMessage -Component 'GraphRetry' -Type 3 }
        'Verbose' { Write-Verbose -Message $LogMessage }
    }
}

function Wait-GraphRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$RetryNumber,

        [Parameter(Mandatory = $true)]
        [int]$StatusCode,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$RetryAfterValue,

        [Parameter(Mandatory = $true)]
        [string]$RequestDescription,

        [long]$ElapsedWaitMilliseconds = 0,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$RequestId
    )
    $Settings = $Script:GraphRetrySettings
    $Statistics = $Script:GraphRetryStatistics
    $RetryAfterMilliseconds = Get-GraphRetryAfterDelay -RetryAfterValue $RetryAfterValue
    if ($null -ne $RetryAfterMilliseconds) {
        $WaitSource = 'Retry-After'
        $RetryAfterJitter = 0
        if ($Settings.RetryAfterJitterMilliseconds -gt 0) {
            $RetryAfterJitter = Get-Random -Minimum 0 -Maximum ($Settings.RetryAfterJitterMilliseconds + 1)
        }
        # Retry-After is never shortened. A value of 0 or a date in the past waits the minimum delay.
        $WaitMilliseconds = [long]([System.Math]::Max($RetryAfterMilliseconds, $Settings.MinimumRetryDelayMilliseconds) + $RetryAfterJitter)
    } else {
        $WaitSource = 'exponential backoff'
        $WaitMilliseconds = Get-GraphBackoffDelay -RetryNumber $RetryNumber
    }
    $StatusLabel = switch ($StatusCode) {
        429 { 'throttled (429)' }
        503 { 'service unavailable (503)' }
        504 { 'gateway timeout (504)' }
        default { "status $StatusCode" }
    }
    if (-not $RequestId) { $RequestId = 'none' }
    $LimitReached = $null
    if ($RetryNumber -gt $Settings.MaximumRetryCount) {
        $LimitReached = "MaximumRetryCount $($Settings.MaximumRetryCount)"
    } elseif (($ElapsedWaitMilliseconds + $WaitMilliseconds) -gt ([long]$Settings.MaximumTotalWaitSeconds * 1000)) {
        $LimitReached = "MaximumTotalWaitSeconds $($Settings.MaximumTotalWaitSeconds)"
    }
    if ($LimitReached) {
        $ElapsedSeconds = [System.Math]::Round($ElapsedWaitMilliseconds / 1000, 1)
        $NextWaitSeconds = [System.Math]::Round($WaitMilliseconds / 1000, 1)
        $FailureMessage = "Graph request $StatusLabel. $RequestDescription stopped after $RetryNumber attempts and $ElapsedSeconds seconds of waiting, limit $LimitReached reached. The next wait would have been $NextWaitSeconds seconds, source $WaitSource. Last request-id $RequestId."
        Write-GraphRetryMessage -Level Error -Message $FailureMessage
        $LimitException = New-Object -TypeName System.InvalidOperationException -ArgumentList $FailureMessage
        $LimitException.Data['StatusCode'] = $StatusCode
        $LimitException.Data['RequestId'] = $RequestId
        $LimitException.Data['Attempts'] = $RetryNumber
        $LimitException.Data['LimitReached'] = $LimitReached
        throw $LimitException
    }
    $Statistics.Retries++
    switch ($StatusCode) {
        429 { $Statistics.ThrottleRetries++ }
        503 { $Statistics.ServiceUnavailableRetries++ }
        504 { $Statistics.GatewayTimeoutRetries++ }
    }
    if ($WaitSource -eq 'Retry-After') { $Statistics.RetryAfterWaits++ } else { $Statistics.BackoffWaits++ }
    $Statistics.TotalWaitMilliseconds += $WaitMilliseconds
    $WaitSeconds = [System.Math]::Round($WaitMilliseconds / 1000, 1)
    $HeaderText = $RetryAfterValue
    if (-not $HeaderText) { $HeaderText = 'none' }
    Write-GraphRetryMessage -Level Warning -Message "Graph request $StatusLabel. $RequestDescription, retry $RetryNumber of $($Settings.MaximumRetryCount), waiting $WaitSeconds seconds, source $WaitSource." -Detail "Retry-After header: $HeaderText. Request-id: $RequestId."
    Start-Sleep -Milliseconds $WaitMilliseconds
    return $WaitMilliseconds
}

function Invoke-GraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [uri]$Uri,

        [System.Collections.IDictionary]$Headers = @{},

        [AllowNull()]
        [object]$Body,

        [string]$ContentType = 'application/json'
    )
    Confirm-GraphRetryInitialized
    $Settings = $Script:GraphRetrySettings
    $Method = $Method.ToUpperInvariant()
    # Serialize once so every attempt sends identical content.
    $RequestBody = $null
    if ($null -ne $Body) {
        if ($Body -is [string]) {
            $RequestBody = $Body
        } else {
            $RequestBody = ConvertTo-Json -InputObject $Body -Depth 20 -Compress
        }
    }
    if ($Uri.IsAbsoluteUri) {
        $RequestPath = $Uri.AbsolutePath
    } else {
        $RequestPath = ($Uri.OriginalString -split '\?')[0]
    }
    $RequestDescription = "$Method $RequestPath"
    $RequestParameters = @{
        Method                  = $Method
        Uri                     = $Uri
        Headers                 = $Headers
        SkipHttpErrorCheck      = $true
        StatusCodeVariable      = 'GraphStatusCode'
        ResponseHeadersVariable = 'GraphResponseHeaders'
        ErrorAction             = 'Stop'
    }
    if ($null -ne $RequestBody) {
        $RequestParameters['Body'] = $RequestBody
        $RequestParameters['ContentType'] = $ContentType
    }
    if ($Settings.Transport -eq 'MgGraphRequest') {
        $RequestParameters['OutputType'] = 'PSObject'
    }
    $RetryNumber = 0
    $ElapsedWaitMilliseconds = [long]0
    while ($true) {
        $GraphStatusCode = 0
        $GraphResponseHeaders = $null
        $Script:GraphRetryStatistics.Requests++
        # Network errors and timeouts without an HTTP status are not retried here and reach the caller unchanged.
        if ($Settings.Transport -eq 'MgGraphRequest') {
            $GraphResponse = Invoke-MgGraphRequest @RequestParameters
        } else {
            $GraphResponse = Invoke-RestMethod @RequestParameters
        }
        if ($GraphStatusCode -ge 200 -and $GraphStatusCode -le 299) {
            return $GraphResponse
        }
        $ErrorDetail = Get-GraphErrorDetail -ResponseBody $GraphResponse -Headers $GraphResponseHeaders
        if (-not (Test-GraphRetryableResponse -StatusCode $GraphStatusCode -Method $Method)) {
            $FailureMessage = "Graph request failed. $RequestDescription returned status $GraphStatusCode, error code '$($ErrorDetail.Code)', message '$($ErrorDetail.Message)', request-id $($ErrorDetail.RequestId), client-request-id $($ErrorDetail.ClientRequestId), date $($ErrorDetail.Date)."
            $RequestException = New-Object -TypeName System.InvalidOperationException -ArgumentList $FailureMessage
            $RequestException.Data['StatusCode'] = $GraphStatusCode
            $RequestException.Data['ErrorCode'] = $ErrorDetail.Code
            $RequestException.Data['RequestId'] = $ErrorDetail.RequestId
            $RequestException.Data['Attempts'] = $RetryNumber + 1
            throw $RequestException
        }
        $RetryNumber++
        $RetryAfterValue = Get-GraphHeaderValue -Headers $GraphResponseHeaders -Name 'Retry-After'
        $WaitedMilliseconds = Wait-GraphRetry -RetryNumber $RetryNumber -StatusCode $GraphStatusCode -RetryAfterValue $RetryAfterValue -RequestDescription $RequestDescription -ElapsedWaitMilliseconds $ElapsedWaitMilliseconds -RequestId $ErrorDetail.RequestId
        $ElapsedWaitMilliseconds += $WaitedMilliseconds
    }
}

function Get-GraphPagedCollection {
    param(
        [Parameter(Mandatory = $true)]
        [uri]$Uri,

        [System.Collections.IDictionary]$Headers = @{},

        [string]$DeltaLinkVariable
    )
    $PageUri = [string]$Uri
    $DeltaLink = $null
    while ($PageUri) {
        # A throttled page is retried inside Invoke-GraphRequestWithRetry with the same nextLink.
        $GraphPage = Invoke-GraphRequestWithRetry -Method GET -Uri $PageUri -Headers $Headers
        $PageItems = Get-GraphPropertyValue -InputObject $GraphPage -Name 'value'
        if ($null -ne $PageItems) {
            foreach ($PageItem in $PageItems) { $PageItem }
        }
        $PageDeltaLink = Get-GraphPropertyValue -InputObject $GraphPage -Name '@odata.deltaLink'
        if ($PageDeltaLink) { $DeltaLink = [string]$PageDeltaLink }
        $PageUri = [string](Get-GraphPropertyValue -InputObject $GraphPage -Name '@odata.nextLink')
    }
    if ($DeltaLinkVariable) {
        Set-Variable -Name $DeltaLinkVariable -Value $DeltaLink -Scope 1
    }
}

function ConvertTo-GraphBatchResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [int]$Status,

        [AllowNull()]
        [object]$Body,

        [AllowNull()]
        [object]$Headers,

        [int]$Attempts,

        [string]$ErrorCode,

        [string]$ErrorMessage
    )
    if ($Status -lt 200 -or $Status -gt 299) {
        $ErrorDetail = Get-GraphErrorDetail -ResponseBody $Body -Headers $Headers
        if (-not $ErrorCode) { $ErrorCode = $ErrorDetail.Code }
        if (-not $ErrorMessage) { $ErrorMessage = $ErrorDetail.Message }
    }
    return [pscustomobject]@{
        Id           = $Id
        Status       = $Status
        Body         = $Body
        Headers      = $Headers
        ErrorCode    = $ErrorCode
        ErrorMessage = $ErrorMessage
        Attempts     = $Attempts
    }
}

function Invoke-GraphBatchWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Requests,

        [System.Collections.IDictionary]$Headers = @{},

        [uri]$BatchUri = 'https://graph.microsoft.com/v1.0/$batch'
    )
    Confirm-GraphRetryInitialized
    # JSON batching accepts at most 20 requests per batch.
    $MaximumBatchSize = 20
    $RequestsById = @{}
    $RequestIndex = @{}
    $RequestOrder = [System.Collections.Generic.List[string]]::new()
    foreach ($BatchRequest in $Requests) {
        $RequestId = [string](Get-GraphPropertyValue -InputObject $BatchRequest -Name 'id')
        $RequestMethod = [string](Get-GraphPropertyValue -InputObject $BatchRequest -Name 'method')
        $RequestUrl = [string](Get-GraphPropertyValue -InputObject $BatchRequest -Name 'url')
        if (-not $RequestId -or -not $RequestMethod -or -not $RequestUrl) {
            throw 'Every batch request needs an id, a method, and a url.'
        }
        if ($RequestsById.ContainsKey($RequestId)) {
            throw "Batch request id '$RequestId' is used more than once. Request ids must be unique."
        }
        $RequestBody = Get-GraphPropertyValue -InputObject $BatchRequest -Name 'body'
        $RequestHeaders = Get-GraphPropertyValue -InputObject $BatchRequest -Name 'headers'
        $DependsOnValue = Get-GraphPropertyValue -InputObject $BatchRequest -Name 'dependsOn'
        $DependsOnIds = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $DependsOnValue) {
            foreach ($DependencyId in @($DependsOnValue)) {
                if ($DependencyId) { $DependsOnIds.Add([string]$DependencyId) }
            }
        }
        $NormalizedRequest = [ordered]@{
            id     = $RequestId
            method = $RequestMethod.ToUpperInvariant()
            url    = $RequestUrl
        }
        # Copy the headers so the caller's request objects stay unchanged.
        $HeaderCopy = [ordered]@{}
        if ($RequestHeaders -is [System.Collections.IDictionary]) {
            foreach ($HeaderKey in $RequestHeaders.Keys) { $HeaderCopy[[string]$HeaderKey] = $RequestHeaders[$HeaderKey] }
        } elseif ($null -ne $RequestHeaders) {
            foreach ($HeaderProperty in $RequestHeaders.PSObject.Properties) { $HeaderCopy[$HeaderProperty.Name] = $HeaderProperty.Value }
        }
        if ($null -ne $RequestBody) {
            $NormalizedRequest['body'] = $RequestBody
            if (-not (Get-GraphHeaderValue -Headers $HeaderCopy -Name 'Content-Type')) {
                $HeaderCopy['Content-Type'] = 'application/json'
            }
        }
        if ($HeaderCopy.Count -gt 0) { $NormalizedRequest['headers'] = $HeaderCopy }
        $RequestsById[$RequestId] = [pscustomobject]@{
            Request   = $NormalizedRequest
            DependsOn = $DependsOnIds.ToArray()
        }
        $RequestIndex[$RequestId] = $RequestOrder.Count
        $RequestOrder.Add($RequestId)
    }

    # Requests linked through dependsOn must travel in the same batch.
    $GroupOf = @{}
    $GroupMembers = [ordered]@{}
    foreach ($RequestId in $RequestOrder) {
        $GroupOf[$RequestId] = $RequestId
        $GroupMembers[$RequestId] = [System.Collections.Generic.List[string]]::new()
        $GroupMembers[$RequestId].Add($RequestId)
    }
    foreach ($RequestId in $RequestOrder) {
        foreach ($DependencyId in $RequestsById[$RequestId].DependsOn) {
            if (-not $RequestsById.ContainsKey($DependencyId)) {
                throw "Batch request '$RequestId' depends on '$DependencyId', which is not part of the request list."
            }
            $SourceGroup = $GroupOf[$RequestId]
            $TargetGroup = $GroupOf[$DependencyId]
            if ($SourceGroup -ne $TargetGroup) {
                foreach ($MemberId in $GroupMembers[$TargetGroup]) {
                    $GroupOf[$MemberId] = $SourceGroup
                    $GroupMembers[$SourceGroup].Add($MemberId)
                }
                $GroupMembers.Remove($TargetGroup)
            }
        }
    }
    $Chunks = [System.Collections.Generic.List[object]]::new()
    $CurrentChunk = [System.Collections.Generic.List[string]]::new()
    foreach ($GroupKey in @($GroupMembers.Keys)) {
        $Members = $GroupMembers[$GroupKey]
        if ($Members.Count -gt $MaximumBatchSize) {
            throw "A dependsOn chain with $($Members.Count) requests exceeds the batch limit of $MaximumBatchSize requests. Split the chain."
        }
        if ($CurrentChunk.Count + $Members.Count -gt $MaximumBatchSize) {
            $Chunks.Add($CurrentChunk)
            $CurrentChunk = [System.Collections.Generic.List[string]]::new()
        }
        $CurrentChunk.AddRange($Members)
    }
    if ($CurrentChunk.Count -gt 0) { $Chunks.Add($CurrentChunk) }

    $Results = @{}
    $BatchPath = $BatchUri.OriginalString
    if ($BatchUri.IsAbsoluteUri) { $BatchPath = $BatchUri.AbsolutePath }
    foreach ($Chunk in $Chunks) {
        $PendingIds = @($Chunk | Sort-Object -Property { $RequestIndex[$_] })
        $Attempts = @{}
        foreach ($PendingId in $PendingIds) { $Attempts[$PendingId] = 0 }
        $LastStatus = @{}
        $RoundNumber = 0
        $ElapsedWaitMilliseconds = [long]0
        while ($PendingIds.Count -gt 0) {
            $PendingLookup = @{}
            foreach ($PendingId in $PendingIds) { $PendingLookup[$PendingId] = $true }
            $OutgoingRequests = [System.Collections.Generic.List[object]]::new()
            foreach ($PendingId in $PendingIds) {
                $SourceRequest = $RequestsById[$PendingId]
                $OutgoingRequest = [ordered]@{}
                foreach ($RequestKey in $SourceRequest.Request.Keys) { $OutgoingRequest[$RequestKey] = $SourceRequest.Request[$RequestKey] }
                # Keep dependencies on requests that are sent again and drop dependencies on requests that already succeeded.
                $ActiveDependencies = @($SourceRequest.DependsOn | Where-Object { $PendingLookup.ContainsKey($_) })
                if ($ActiveDependencies.Count -gt 0) { $OutgoingRequest['dependsOn'] = $ActiveDependencies }
                $OutgoingRequests.Add($OutgoingRequest)
                $Attempts[$PendingId]++
            }
            $BatchResponse = Invoke-GraphRequestWithRetry -Method POST -Uri $BatchUri -Headers $Headers -Body @{ requests = $OutgoingRequests.ToArray() }
            $InnerResponses = Get-GraphPropertyValue -InputObject $BatchResponse -Name 'responses'
            $ResponsesById = @{}
            if ($null -ne $InnerResponses) {
                foreach ($InnerResponse in $InnerResponses) {
                    $ResponsesById[[string](Get-GraphPropertyValue -InputObject $InnerResponse -Name 'id')] = $InnerResponse
                }
            }
            $ResendLookup = @{}
            $DeferredIds = [System.Collections.Generic.List[string]]::new()
            $LongestRetryAfterMilliseconds = $null
            $LongestRetryAfterValue = $null
            $RoundStatusCode = 0
            $RoundRequestId = $null
            foreach ($PendingId in $PendingIds) {
                $InnerResponse = $ResponsesById[$PendingId]
                if ($null -eq $InnerResponse) {
                    $Results[$PendingId] = ConvertTo-GraphBatchResult -Id $PendingId -Status 0 -Attempts $Attempts[$PendingId] -ErrorCode 'MissingBatchResponse' -ErrorMessage 'The batch response contained no response for this request.'
                    continue
                }
                $InnerStatus = [int](Get-GraphPropertyValue -InputObject $InnerResponse -Name 'status')
                $InnerBody = Get-GraphPropertyValue -InputObject $InnerResponse -Name 'body'
                $InnerHeaders = Get-GraphPropertyValue -InputObject $InnerResponse -Name 'headers'
                $LastStatus[$PendingId] = $InnerStatus
                if ($InnerStatus -ge 200 -and $InnerStatus -le 299) {
                    $Results[$PendingId] = ConvertTo-GraphBatchResult -Id $PendingId -Status $InnerStatus -Body $InnerBody -Headers $InnerHeaders -Attempts $Attempts[$PendingId]
                    continue
                }
                if (Test-GraphRetryableResponse -StatusCode $InnerStatus -Method $RequestsById[$PendingId].Request.method) {
                    $ResendLookup[$PendingId] = $true
                    if ($RoundStatusCode -eq 0) {
                        $RoundStatusCode = $InnerStatus
                        $RoundRequestId = (Get-GraphErrorDetail -ResponseBody $InnerBody -Headers $InnerHeaders).RequestId
                    }
                    $InnerRetryAfterValue = Get-GraphHeaderValue -Headers $InnerHeaders -Name 'Retry-After'
                    $InnerRetryAfterMilliseconds = Get-GraphRetryAfterDelay -RetryAfterValue $InnerRetryAfterValue
                    if ($null -ne $InnerRetryAfterMilliseconds -and ($null -eq $LongestRetryAfterMilliseconds -or $InnerRetryAfterMilliseconds -gt $LongestRetryAfterMilliseconds)) {
                        $LongestRetryAfterMilliseconds = $InnerRetryAfterMilliseconds
                        $LongestRetryAfterValue = $InnerRetryAfterValue
                        $RoundStatusCode = $InnerStatus
                        $RoundRequestId = (Get-GraphErrorDetail -ResponseBody $InnerBody -Headers $InnerHeaders).RequestId
                    }
                    continue
                }
                if ($InnerStatus -eq 424) {
                    $DeferredIds.Add($PendingId)
                    continue
                }
                $Results[$PendingId] = ConvertTo-GraphBatchResult -Id $PendingId -Status $InnerStatus -Body $InnerBody -Headers $InnerHeaders -Attempts $Attempts[$PendingId]
            }
            # A 424 whose dependency is sent again is sent again as well. Repeat until no further request joins the resend set.
            do {
                $AddedDependentRequest = $false
                foreach ($DeferredId in @($DeferredIds)) {
                    $ResentDependencies = @($RequestsById[$DeferredId].DependsOn | Where-Object { $ResendLookup.ContainsKey($_) })
                    if ($ResentDependencies.Count -gt 0) {
                        $ResendLookup[$DeferredId] = $true
                        $null = $DeferredIds.Remove($DeferredId)
                        $AddedDependentRequest = $true
                    }
                }
            } while ($AddedDependentRequest)
            foreach ($DeferredId in $DeferredIds) {
                $InnerResponse = $ResponsesById[$DeferredId]
                $Results[$DeferredId] = ConvertTo-GraphBatchResult -Id $DeferredId -Status 424 -Body (Get-GraphPropertyValue -InputObject $InnerResponse -Name 'body') -Headers (Get-GraphPropertyValue -InputObject $InnerResponse -Name 'headers') -Attempts $Attempts[$DeferredId]
            }
            if ($ResendLookup.Count -eq 0) { break }
            $ResendIds = @($PendingIds | Where-Object { $ResendLookup.ContainsKey($_) })
            $RoundNumber++
            $RoundDescription = "POST $BatchPath, $($ResendIds.Count) of $($PendingIds.Count) batch requests to send again"
            try {
                $WaitedMilliseconds = Wait-GraphRetry -RetryNumber $RoundNumber -StatusCode $RoundStatusCode -RetryAfterValue $LongestRetryAfterValue -RequestDescription $RoundDescription -ElapsedWaitMilliseconds $ElapsedWaitMilliseconds -RequestId $RoundRequestId
            } catch {
                $LimitError = $_
                if (-not $LimitError.Exception.Data.Contains('LimitReached')) { throw }
                # The limit applies to the remaining requests only. Results of completed requests stay available.
                foreach ($ResendId in $ResendIds) {
                    $Results[$ResendId] = ConvertTo-GraphBatchResult -Id $ResendId -Status $LastStatus[$ResendId] -Attempts $Attempts[$ResendId] -ErrorCode 'RetryLimitReached' -ErrorMessage $LimitError.Exception.Message
                }
                break
            }
            $ElapsedWaitMilliseconds += $WaitedMilliseconds
            $PendingIds = $ResendIds
        }
    }
    foreach ($RequestId in $RequestOrder) { $Results[$RequestId] }
}

function Write-GraphRetrySummary {
    param()
    Confirm-GraphRetryInitialized
    $Statistics = $Script:GraphRetryStatistics
    $TotalWaitSeconds = [System.Math]::Round($Statistics.TotalWaitMilliseconds / 1000, 1)
    $SummaryMessage = "Graph retry summary: $($Statistics.Requests) requests sent, $($Statistics.Retries) retries (429: $($Statistics.ThrottleRetries), 503: $($Statistics.ServiceUnavailableRetries), 504: $($Statistics.GatewayTimeoutRetries)), $($Statistics.RetryAfterWaits) waits from Retry-After, $($Statistics.BackoffWaits) waits from exponential backoff, $TotalWaitSeconds seconds total wait."
    $SummaryLevel = 'Information'
    if ($Statistics.Retries -gt 0) { $SummaryLevel = 'Warning' }
    Write-GraphRetryMessage -Level $SummaryLevel -Message $SummaryMessage
}
#endregion GraphRetry

function Get-GraphRetryBlockText {
    # Thread jobs run in separate runspaces and load the GraphRetry block from this script file.
    if (-not $PSCommandPath) {
        throw 'The script path is unknown. Run the script as a file so the thread jobs can load the GraphRetry block.'
    }
    $ScriptText = Get-Content -LiteralPath $PSCommandPath -Raw
    $BlockMatch = Select-String -InputObject $ScriptText -Pattern '(?ms)^[ \t]*#region GraphRetry\b.*?^[ \t]*#endregion GraphRetry\b[^\r\n]*' -CaseSensitive
    if (-not $BlockMatch) {
        throw "The GraphRetry block was not found in '$PSCommandPath'."
    }
    return $BlockMatch.Matches[0].Value
}

function Connect-GraphSession {
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw 'The module Microsoft.Graph.Authentication is required. Install it with Install-Module Microsoft.Graph.Authentication.'
    }
    if (Get-MgContext) {
        Write-Log -Message 'Using the existing Microsoft Graph connection.' -Component 'Connect'
        return
    }
    $ConnectParameters = @{
        NoWelcome   = $true
        ErrorAction = 'Stop'
    }
    if ($CertificateThumbprint) {
        if (-not $ClientId -or -not $TenantId) {
            throw 'Certificate authentication requires ClientId, TenantId, and CertificateThumbprint.'
        }
        $ConnectParameters['ClientId'] = $ClientId
        $ConnectParameters['TenantId'] = $TenantId
        $ConnectParameters['CertificateThumbprint'] = $CertificateThumbprint
        $AuthenticationDescription = 'certificate authentication'
    } else {
        $ConnectParameters['Scopes'] = @('User.ReadWrite.All')
        if ($ClientId) { $ConnectParameters['ClientId'] = $ClientId }
        if ($TenantId) { $ConnectParameters['TenantId'] = $TenantId }
        $AuthenticationDescription = 'interactive authentication'
    }
    Connect-MgGraph @ConnectParameters
    if (-not (Get-MgContext)) {
        throw 'The Microsoft Graph connection could not be established.'
    }
    Write-Log -Message "Connected to Microsoft Graph with $AuthenticationDescription." -Component 'Connect'
}

function Get-RandomWordList {
    Write-Log -Message "Downloading the word list from $WordListUri." -Component 'WordList'
    $DownloadedWords = Invoke-RestMethod -Method Get -Uri $WordListUri -ErrorAction Stop
    $NormalizedWords = foreach ($DownloadedWord in @($DownloadedWords)) {
        $Word = ([string]$DownloadedWord).ToLowerInvariant() -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue' -replace 'ß', 'ss' -replace '[^a-z]', ''
        if ($Word.Length -ge 2) {
            $Word.Substring(0, 1).ToUpperInvariant() + $Word.Substring(1)
        }
    }
    $UniqueWords = @($NormalizedWords | Sort-Object -Unique)
    if ($UniqueWords.Count -lt 2) {
        throw "The word list from $WordListUri contains fewer than 2 usable words."
    }
    Write-Log -Message "The word list contains $($UniqueWords.Count) usable words." -Component 'WordList'
    return $UniqueWords
}

function New-RandomPassword {
    $PasswordLength = 20
    $PasswordCharacters = (65..90) + (97..122) + (48..57) + 33 + (35..47) + (58..64) + (91..95) + (123..126)
    return -join ($PasswordCharacters | Get-Random -Count $PasswordLength | ForEach-Object { [char]$_ })
}

function New-RandomUserDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Words
    )
    $UserDefinitions = [System.Collections.Generic.List[object]]::new()
    $UsedNicknames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $MaximumAttempts = $NumberOfUsers * 10
    $Attempt = 0
    while ($UserDefinitions.Count -lt $NumberOfUsers -and $Attempt -lt $MaximumAttempts) {
        $Attempt++
        $FirstName = $Words | Get-Random
        $LastName = $Words | Get-Random
        $MailNickname = "$($FirstName.ToLowerInvariant())$($LastName.ToLowerInvariant())"
        if (-not $UsedNicknames.Add($MailNickname)) { continue }
        $UserDefinitions.Add([ordered]@{
                accountEnabled    = $true
                displayName       = "$FirstName $LastName"
                mailNickname      = $MailNickname
                userPrincipalName = "$($FirstName.ToLowerInvariant()).$($LastName.ToLowerInvariant())@$UserPrincipalNameSuffix"
                passwordProfile   = [ordered]@{
                    forceChangePasswordNextSignIn = $false
                    password                      = New-RandomPassword
                }
                officeLocation    = "$($Script:OfficeLocationMarker)$($UserDefinitions.Count)"
            })
    }
    if ($UserDefinitions.Count -lt $NumberOfUsers) {
        Write-Log -Message "The word list allows $($UserDefinitions.Count) unique names. The script creates $($UserDefinitions.Count) of $NumberOfUsers requested users." -Component 'UserList' -Type 2
    }
    return $UserDefinitions.ToArray()
}

function Invoke-GraphBatchInThreadJob {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Requests
    )
    $BatchUri = "$Script:GraphBaseUri/`$batch"
    $BatchJobs = [System.Collections.Generic.List[object]]::new()
    $BatchNumber = 0
    for ($FirstIndex = 0; $FirstIndex -lt $Requests.Count; $FirstIndex += $Script:BatchSize) {
        $LastIndex = $FirstIndex + $Script:BatchSize - 1
        if ($LastIndex -ge $Requests.Count) { $LastIndex = $Requests.Count - 1 }
        $BatchNumber++
        $JobParameters = @{
            Name          = "$($Script:JobNamePrefix)-Batch-$BatchNumber"
            ThrottleLimit = $ThrottleLimit
            ScriptBlock   = $Script:BatchJobScript
            ArgumentList  = @($Script:GraphRetryBlockText, $Requests[$FirstIndex..$LastIndex], $BatchUri, $BatchNumber)
        }
        $BatchJobs.Add((Start-ThreadJob @JobParameters))
    }
    Write-Log -Message "Started $($BatchJobs.Count) thread jobs for $($Requests.Count) requests with throttle limit $ThrottleLimit." -Component 'BatchJob'
    $null = Wait-Job -Job $BatchJobs
    $AllResults = [System.Collections.Generic.List[object]]::new()
    foreach ($BatchJob in $BatchJobs) {
        $JobErrors = $null
        $JobOutput = Receive-Job -Job $BatchJob -ErrorAction SilentlyContinue -ErrorVariable JobErrors
        foreach ($JobError in @($JobErrors)) {
            if ($JobError) { Write-Log -Message "Thread job $($BatchJob.Name) reported an error: $($JobError.Exception.Message)" -Component 'BatchJob' -Type 3 }
        }
        $BatchOutput = @($JobOutput | Where-Object { $_.PSObject.Properties.Name -contains 'BatchNumber' }) | Select-Object -Last 1
        if (-not $BatchOutput) {
            Write-Log -Message "Thread job $($BatchJob.Name) ended with state $($BatchJob.State) and returned no result." -Component 'BatchJob' -Type 3
            Remove-Job -Job $BatchJob -Force
            continue
        }
        foreach ($JobLogEntry in $BatchOutput.LogEntries) {
            $EntryType = 1
            if ($JobLogEntry.Type -in 2, 3) { $EntryType = $JobLogEntry.Type }
            Write-Log -Message "Batch $($BatchOutput.BatchNumber): $($JobLogEntry.Message)" -Component $JobLogEntry.Component -Type $EntryType
        }
        if ($BatchOutput.Statistics) {
            foreach ($StatisticName in @($BatchOutput.Statistics.Keys)) {
                if ($Script:GraphRetryStatistics.Contains($StatisticName)) {
                    $Script:GraphRetryStatistics[$StatisticName] += $BatchOutput.Statistics[$StatisticName]
                }
            }
        }
        if ($BatchOutput.FailureMessage) {
            Write-Log -Message "Batch $($BatchOutput.BatchNumber) stopped: $($BatchOutput.FailureMessage)" -Component 'BatchJob' -Type 3
        }
        foreach ($BatchResult in $BatchOutput.Results) { $AllResults.Add($BatchResult) }
        Remove-Job -Job $BatchJob -Force
    }
    return $AllResults.ToArray()
}

function New-RandomUser {
    $Words = Get-RandomWordList
    $UserDefinitions = @(New-RandomUserDefinition -Words $Words)
    $RequestCount = $UserDefinitions.Count
    $UsersByRequestId = @{}
    $BatchRequests = for ($UserIndex = 0; $UserIndex -lt $RequestCount; $UserIndex++) {
        $RequestId = [string]($UserIndex + 1)
        $UsersByRequestId[$RequestId] = $UserDefinitions[$UserIndex]
        @{
            id     = $RequestId
            method = 'POST'
            url    = '/users'
            body   = $UserDefinitions[$UserIndex]
        }
    }
    Write-Log -Message "Creating $RequestCount random users." -Component 'CreateUser'
    $SucceededCount = 0
    $FailedCount = 0
    $ReturnedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($BatchResult in Invoke-GraphBatchInThreadJob -Requests $BatchRequests) {
        $null = $ReturnedIds.Add([string]$BatchResult.Id)
        $UserPrincipalName = $UsersByRequestId[[string]$BatchResult.Id].userPrincipalName
        if ($BatchResult.Status -eq 201) {
            $SucceededCount++
            Write-Log -Message "Created $UserPrincipalName after $($BatchResult.Attempts) attempts." -Component 'CreateUser'
        } else {
            $FailedCount++
            Write-Log -Message "Creating $UserPrincipalName failed. Status $($BatchResult.Status), error code '$($BatchResult.ErrorCode)', message '$($BatchResult.ErrorMessage)', attempts $($BatchResult.Attempts)." -Component 'CreateUser' -Type 3
        }
    }
    $FailedCount += $RequestCount - $ReturnedIds.Count
    return [pscustomobject]@{ Mode = 'Create'; Requested = $RequestCount; Succeeded = $SucceededCount; Failed = $FailedCount }
}

function Remove-RandomUser {
    Write-Log -Message "Reading users whose officeLocation starts with '$($Script:OfficeLocationMarker)'." -Component 'DeleteUser'
    $UsersUri = "$Script:GraphBaseUri/users?`$count=true&`$top=999&`$select=id,userPrincipalName,officeLocation&`$filter=startswith(officeLocation,'$($Script:OfficeLocationMarker)')"
    $UsersToDelete = @(Get-GraphPagedCollection -Uri $UsersUri -Headers @{ ConsistencyLevel = 'eventual' })
    $RequestCount = $UsersToDelete.Count
    Write-Log -Message "Found $RequestCount users to delete." -Component 'DeleteUser'
    if ($RequestCount -eq 0) {
        return [pscustomobject]@{ Mode = 'Delete'; Requested = 0; Succeeded = 0; Failed = 0 }
    }
    $UserPrincipalNamesByRequestId = @{}
    $BatchRequests = for ($UserIndex = 0; $UserIndex -lt $RequestCount; $UserIndex++) {
        $RequestId = [string]($UserIndex + 1)
        $UserToDelete = $UsersToDelete[$UserIndex]
        $UserPrincipalNamesByRequestId[$RequestId] = Get-GraphPropertyValue -InputObject $UserToDelete -Name 'userPrincipalName'
        @{
            id     = $RequestId
            method = 'DELETE'
            url    = "/users/$(Get-GraphPropertyValue -InputObject $UserToDelete -Name 'id')"
        }
    }
    $SucceededCount = 0
    $FailedCount = 0
    $ReturnedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($BatchResult in Invoke-GraphBatchInThreadJob -Requests $BatchRequests) {
        $null = $ReturnedIds.Add([string]$BatchResult.Id)
        $UserPrincipalName = $UserPrincipalNamesByRequestId[[string]$BatchResult.Id]
        if ($BatchResult.Status -eq 204) {
            $SucceededCount++
            Write-Log -Message "Deleted $UserPrincipalName after $($BatchResult.Attempts) attempts." -Component 'DeleteUser'
        } else {
            $FailedCount++
            Write-Log -Message "Deleting $UserPrincipalName failed. Status $($BatchResult.Status), error code '$($BatchResult.ErrorCode)', message '$($BatchResult.ErrorMessage)', attempts $($BatchResult.Attempts)." -Component 'DeleteUser' -Type 3
        }
    }
    $FailedCount += $RequestCount - $ReturnedIds.Count
    return [pscustomobject]@{ Mode = 'Delete'; Requested = $RequestCount; Succeeded = $SucceededCount; Failed = $FailedCount }
}

# Main
Initialize-Script
Write-Log -Message "Started. Mode $Mode, Graph API version $GraphApiVersion, throttle limit $ThrottleLimit." -Component 'Main'
$IsGraphRetryReady = $false
try {
    Connect-GraphSession
    Initialize-GraphRetry -ScriptType Script -Transport MgGraphRequest
    $IsGraphRetryReady = $true
    switch ($Mode) {
        'Create' { $RunSummary = New-RandomUser }
        'Delete' { $RunSummary = Remove-RandomUser }
    }
    $RunSummary | Add-Member -MemberType NoteProperty -Name 'LogFile' -Value $Script:LogFile
    Write-Log -Message "Finished. Mode $($RunSummary.Mode), requested $($RunSummary.Requested), succeeded $($RunSummary.Succeeded), failed $($RunSummary.Failed)." -Component 'Main'
    $RunSummary
} catch {
    Write-Log -Message "Stopped: $($_.Exception.Message)" -Component 'Main' -Type 3
    throw
} finally {
    if ($IsGraphRetryReady) { Write-GraphRetrySummary }
    Get-Job -Name "$($Script:JobNamePrefix)-*" -ErrorAction SilentlyContinue | Remove-Job -Force
}
