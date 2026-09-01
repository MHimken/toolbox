<#
.SYNOPSIS
    Analyzes Content-Security-Policy response headers and creates an interactive HTML report.
.DESCRIPTION
    Sends HTTP requests to one or more HTTPS URLs, follows up to five HTTP 301, 302, 307, or 308
    redirects, and evaluates enforced and report-only Content-Security-Policy headers. The script
    uses Microsoft Edge as a fallback when the native HTTP request fails. It records request
    details, parsed directives, practical security findings, and raw response headers in a
    self-contained HTML report that can be opened without external libraries or network resources.
.PARAMETER Url
    One or more HTTPS URLs to analyze.
.PARAMETER OutputPath
    Path of the generated HTML report. When omitted, a timestamped file is created in the current
    folder.
.PARAMETER TimeoutSeconds
    Maximum number of seconds allowed for each HEAD or GET request. The default is 30 seconds.
.PARAMETER OpenReport
    Opens the generated HTML report in the default browser. The default is true.
.PARAMETER LogPath
    Directory in which the log file is created. The default is the current folder.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.NOTES
    Version: 0.6
    Author: Martin Himken
    Original script name: Analyze-CSP-Header.ps1
    Initial creation date: 2026-09-01
    Last change: 2026-09-01
    Changes: Add a self-cleaning Microsoft Edge fallback for native HTTP request failures
    Acknowledgements: Thanks to https://httpbin.org for providing public HTTP request and
    redirect endpoints used to validate this script.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Url,
    [string]$OutputPath,
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 30,
    [bool]$OpenReport = $true,
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
    $DefinedScriptName = 'Analyze-CSP-Header'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''

    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    if (-not $LogFile) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:ToConsole = $false

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $Script:OutputPath = Join-Path -Path (Get-Location).Path -ChildPath "$($SanitizedScriptName)_$($Script:DateTime).html"
    } else {
        $Script:OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    }
    $OutputDirectory = Split-Path -Path $Script:OutputPath -Parent
    if ($OutputDirectory -and -not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }
}

function ConvertTo-HeaderRecords {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpResponseMessage]$Response
    )

    $Records = [System.Collections.Generic.List[object]]::new()
    foreach ($Header in $Response.Headers) {
        $Records.Add([pscustomobject][ordered]@{
            Name   = [string]$Header.Key
            Values = @($Header.Value | ForEach-Object { [string]$_ })
        })
    }
    foreach ($Header in $Response.Content.Headers) {
        $Records.Add([pscustomobject][ordered]@{
            Name   = [string]$Header.Key
            Values = @($Header.Value | ForEach-Object { [string]$_ })
        })
    }
    return @($Records | Sort-Object Name)
}

function Get-HeaderValues {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Headers,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return @($Headers | Where-Object { $_.Name -ieq $Name } | ForEach-Object { $_.Values })
}

function Get-EdgePath {
    $Candidates = @(
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Edge\Application\msedge.exe')
    )
    foreach ($RegistryPath in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe'
    )) {
        $RegisteredPath = (Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue).'(default)'
        if ($RegisteredPath) {
            $Candidates += $RegisteredPath
        }
    }
    return $Candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

function ConvertFrom-EdgeHeaderLines {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$HeaderLines
    )

    $HeadersByName = [ordered]@{}
    foreach ($Line in @($HeaderLines | Select-Object -Skip 1)) {
        $SeparatorIndex = $Line.IndexOf(':')
        if ($SeparatorIndex -lt 1) {
            continue
        }
        $Name = $Line.Substring(0, $SeparatorIndex).Trim()
        $Value = $Line.Substring($SeparatorIndex + 1).Trim()
        $ExistingName = @($HeadersByName.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1)
        if ($ExistingName.Count -eq 0) {
            $HeadersByName[$Name] = [System.Collections.Generic.List[string]]::new()
            $ExistingName = @($Name)
        }
        $HeadersByName[$ExistingName[0]].Add($Value)
    }
    return @($HeadersByName.Keys | ForEach-Object {
        [pscustomobject][ordered]@{
            Name   = $_
            Values = @($HeadersByName[$_])
        }
    })
}

function Invoke-EdgeHeaderRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$RequestUri
    )

    $EdgePath = Get-EdgePath
    if (-not $EdgePath) {
        throw 'Microsoft Edge was not found in a standard installation location or Windows application registration.'
    }

    Write-Log -Message "WARNING: Using Microsoft Edge fallback for $RequestUri." -Component 'EdgeFallback' -Type 2
    $CapturePath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "Analyze-CSP-Header-Edge-$([guid]::NewGuid().ToString('N'))"
    try {
        $ProfilePath = Join-Path -Path $CapturePath -ChildPath 'Profile'
        $NetLogPath = Join-Path -Path $CapturePath -ChildPath 'netlog.json'
        $OutputFile = Join-Path -Path $CapturePath -ChildPath 'output.html'
        $ErrorFile = Join-Path -Path $CapturePath -ChildPath 'error.txt'
        $null = New-Item -Path $ProfilePath -ItemType Directory -Force

        $Arguments = @(
            '--headless',
            '--disable-gpu',
            '--no-first-run',
            '--disable-extensions',
            "--user-data-dir=$ProfilePath",
            "--log-net-log=$NetLogPath",
            '--net-log-capture-mode=IncludeSensitive',
            '--dump-dom',
            $RequestUri.AbsoluteUri
        )
        $Process = Start-Process -FilePath $EdgePath -ArgumentList $Arguments -RedirectStandardOutput $OutputFile -RedirectStandardError $ErrorFile -PassThru
        if (-not $Process.WaitForExit(($TimeoutSeconds + 10) * 1000)) {
            $Process.Kill($true)
            throw "Microsoft Edge fallback exceeded the $($TimeoutSeconds + 10) second capture limit."
        }
        if (-not (Test-Path -LiteralPath $NetLogPath)) {
            $EdgeError = if (Test-Path -LiteralPath $ErrorFile) { (Get-Content -LiteralPath $ErrorFile -Raw).Trim() } else { $null }
            throw "Microsoft Edge did not create a network capture. $EdgeError".Trim()
        }

        $NetLog = Get-Content -LiteralPath $NetLogPath -Raw | ConvertFrom-Json -Depth 100
        $EventTypes = @{}
        foreach ($Property in $NetLog.constants.logEventTypes.PSObject.Properties) {
            $EventTypes[[int]$Property.Value] = $Property.Name
        }
        $NormalizedRequestUri = $RequestUri.AbsoluteUri
        $RequestSourceId = @($NetLog.events | Where-Object {
            $EventTypes[[int]$_.type] -eq 'URL_REQUEST_START_JOB' -and
            $_.params.url -and
            ([System.Uri]$_.params.url).AbsoluteUri -eq $NormalizedRequestUri
        } | Select-Object -First 1 -ExpandProperty source).id
        if ($null -eq $RequestSourceId) {
            throw "Microsoft Edge network capture did not contain the requested navigation for $RequestUri."
        }

        $CurrentUri = $RequestUri
        $Redirects = [System.Collections.Generic.List[object]]::new()
        $Responses = [System.Collections.Generic.List[object]]::new()
        foreach ($Event in @($NetLog.events | Where-Object { $_.source.id -eq $RequestSourceId })) {
            $EventName = $EventTypes[[int]$Event.type]
            if ($EventName -eq 'URL_REQUEST_START_JOB' -and $Event.params.url) {
                $CurrentUri = [System.Uri]$Event.params.url
                continue
            }
            if ($EventName -ne 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' -or -not $Event.params.headers) {
                continue
            }

            $StatusMatch = [regex]::Match([string]$Event.params.headers[0], '(?i)(?:HTTP/\S+|:status:)\s*(?<status>\d{3})(?:\s+(?<reason>.*))?')
            if (-not $StatusMatch.Success) {
                continue
            }
            $StatusCode = [int]$StatusMatch.Groups['status'].Value
            $Headers = @(ConvertFrom-EdgeHeaderLines -HeaderLines @($Event.params.headers))
            $Location = @(Get-HeaderValues -Headers $Headers -Name 'Location' | Select-Object -First 1)
            $Responses.Add([pscustomobject][ordered]@{
                Url          = $CurrentUri.AbsoluteUri
                StatusCode   = $StatusCode
                ReasonPhrase = $StatusMatch.Groups['reason'].Value.Trim()
                Headers      = $Headers
            })
            if ($StatusCode -in @(301, 302, 307, 308) -and $Location.Count -gt 0) {
                if ($Redirects.Count -ge 5) {
                    throw "Redirect limit of 5 exceeded while requesting $RequestUri."
                }
                $NextUri = [System.Uri]::new($CurrentUri, [string]$Location[0])
                $Redirects.Add([pscustomobject][ordered]@{
                    StatusCode = $StatusCode
                    From       = $CurrentUri.AbsoluteUri
                    To         = $NextUri.AbsoluteUri
                })
            }
        }
        if ($Responses.Count -eq 0) {
            throw "Microsoft Edge network capture did not contain response headers for $RequestUri."
        }

        $FinalResponse = $Responses[$Responses.Count - 1]
        return [pscustomobject][ordered]@{
            FinalUrl     = $FinalResponse.Url
            StatusCode   = $FinalResponse.StatusCode
            ReasonPhrase = $FinalResponse.ReasonPhrase
            Headers      = @($FinalResponse.Headers)
            Redirects    = @($Redirects)
        }
    } finally {
        if (Test-Path -LiteralPath $CapturePath) {
            Remove-Item -LiteralPath $CapturePath -Recurse -Force -ErrorAction Stop
        }
    }
}

function ConvertTo-CspPolicies {
    param([string[]]$PolicyValues)

    $Policies = [System.Collections.Generic.List[object]]::new()
    foreach ($PolicyValue in @($PolicyValues)) {
        if ([string]::IsNullOrWhiteSpace($PolicyValue)) {
            continue
        }

        $Directives = [System.Collections.Generic.List[object]]::new()
        foreach ($DirectiveText in ($PolicyValue -split ';')) {
            $Parts = @($DirectiveText.Trim() -split '\s+' | Where-Object { $_ })
            if ($Parts.Count -eq 0) {
                continue
            }
            $Directives.Add([pscustomobject][ordered]@{
                Name    = $Parts[0].ToLowerInvariant()
                Sources = @($Parts | Select-Object -Skip 1)
            })
        }
        $Policies.Add([pscustomobject][ordered]@{
            Raw        = $PolicyValue
            Directives = @($Directives)
        })
    }
    return @($Policies)
}

function Test-CspPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Policies,
        [Parameter(Mandatory = $true)]
        [bool]$HasReportOnlyPolicy
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    if ($Policies.Count -eq 0) {
        $Message = if ($HasReportOnlyPolicy) {
            'A report-only policy is present, but no enforced Content-Security-Policy header was returned.'
        } else {
            'No enforced Content-Security-Policy header was returned.'
        }
        $Findings.Add([pscustomobject]@{ Severity = 'Missing'; Title = 'Enforced CSP missing'; Detail = $Message })
        return [pscustomobject]@{ Status = 'Missing'; Findings = @($Findings) }
    }

    $ExecutableDirectives = @('script-src', 'script-src-elem', 'script-src-attr', 'worker-src')
    $FallbackDirectives = @('script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'media-src', 'frame-src', 'worker-src', 'manifest-src')
    $DefensiveDirectives = @('object-src', 'base-uri', 'frame-ancestors', 'form-action', 'upgrade-insecure-requests')

    for ($PolicyIndex = 0; $PolicyIndex -lt $Policies.Count; $PolicyIndex++) {
        $Policy = $Policies[$PolicyIndex]
        $Label = if ($Policies.Count -gt 1) { "Policy $($PolicyIndex + 1)" } else { 'Policy' }
        $GroupedDirectives = @($Policy.Directives | Group-Object Name)
        $DirectiveMap = @{}
        foreach ($Group in $GroupedDirectives) {
            $DirectiveMap[$Group.Name] = @($Group.Group | ForEach-Object { $_.Sources })
            if ($Group.Count -gt 1) {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label has duplicate $($Group.Name) directives"; Detail = 'Browsers use the first occurrence in a policy. Review the repeated directive for unintended behavior.' })
            }
        }

        foreach ($DirectiveName in $DirectiveMap.Keys) {
            $Sources = @($DirectiveMap[$DirectiveName])
            if ($Sources -contains '*') {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label allows a wildcard in $DirectiveName"; Detail = "The $DirectiveName directive contains *, which permits a broad source set." })
            }
            $Schemes = @($Sources | Where-Object { $_ -match '^(?i)https?:$' })
            if ($Schemes.Count -gt 0) {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label allows scheme-wide sources in $DirectiveName"; Detail = "The $DirectiveName directive contains $($Schemes -join ', ')." })
            }
            if ($Sources -contains "'unsafe-inline'") {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label allows unsafe inline content in $DirectiveName"; Detail = "The $DirectiveName directive contains 'unsafe-inline'." })
            }
            if ($Sources -contains "'unsafe-eval'") {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label allows dynamic code evaluation in $DirectiveName"; Detail = "The $DirectiveName directive contains 'unsafe-eval'." })
            }
            if ($DirectiveName -in $ExecutableDirectives) {
                $RiskyExecutableSources = @($Sources | Where-Object { $_ -in @('data:', 'blob:') })
                if ($RiskyExecutableSources.Count -gt 0) {
                    $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label allows data or blob execution in $DirectiveName"; Detail = "The $DirectiveName directive contains $($RiskyExecutableSources -join ', ')." })
                }
            }
        }

        $HasDefaultSource = $DirectiveMap.ContainsKey('default-src')
        foreach ($DirectiveName in $FallbackDirectives) {
            if (-not $HasDefaultSource -and -not $DirectiveMap.ContainsKey($DirectiveName)) {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label does not cover $DirectiveName"; Detail = "Neither $DirectiveName nor default-src is present. Confirm that unrestricted fallback behavior is intended." })
            }
        }
        foreach ($DirectiveName in $DefensiveDirectives) {
            if (-not $DirectiveMap.ContainsKey($DirectiveName)) {
                $Findings.Add([pscustomobject]@{ Severity = 'Review'; Title = "$Label does not define $DirectiveName"; Detail = "Consider whether $DirectiveName is appropriate for this application. This is a hardening observation, not a universal compliance requirement." })
            }
        }

        $Strengths = [System.Collections.Generic.List[string]]::new()
        if ($HasDefaultSource) { $Strengths.Add('default-src provides fallback coverage') }
        if (@($Policy.Directives.Sources | Where-Object { $_ -match "^'nonce-|^'sha(256|384|512)-" }).Count -gt 0) { $Strengths.Add('nonce or hash sources are present') }
        if (@($Policy.Directives.Sources | Where-Object { $_ -eq "'strict-dynamic'" }).Count -gt 0) { $Strengths.Add("'strict-dynamic' is present") }
        if ($DirectiveMap.ContainsKey('report-uri') -or $DirectiveMap.ContainsKey('report-to')) { $Strengths.Add('CSP reporting is configured') }
        if ($Strengths.Count -gt 0) {
            $Findings.Add([pscustomobject]@{ Severity = 'Info'; Title = "$Label includes defensive features"; Detail = $Strengths -join '; ' })
        }
    }

    $Status = if (@($Findings | Where-Object { $_.Severity -eq 'Review' }).Count -gt 0) { 'Review' } else { 'Good' }
    if ($Findings.Count -eq 0) {
        $Findings.Add([pscustomobject]@{ Severity = 'Info'; Title = 'No practical concerns identified'; Detail = 'The automated checks found an enforced policy without the tested broad or unsafe source patterns.' })
    }
    return [pscustomobject]@{ Status = $Status; Findings = @($Findings) }
}

function Invoke-HeaderRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)]
        [System.Uri]$RequestUri,
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpMethod]$Method
    )

    $CurrentUri = $RequestUri
    $Redirects = [System.Collections.Generic.List[object]]::new()
    $EdgeUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'

    while ($true) {
        $Request = [System.Net.Http.HttpRequestMessage]::new($Method, $CurrentUri)
        $Request.Headers.TryAddWithoutValidation('User-Agent', $EdgeUserAgent) | Out-Null
        try {
            $Response = $Client.Send($Request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
        } finally {
            $Request.Dispose()
        }

        if ([int]$Response.StatusCode -notin @(301, 302, 307, 308)) {
            return [pscustomobject]@{
                Response  = $Response
                Redirects = @($Redirects)
            }
        }

        $Location = $Response.Headers.Location
        if (-not $Location) {
            return [pscustomobject]@{
                Response  = $Response
                Redirects = @($Redirects)
            }
        }
        if ($Redirects.Count -ge 5) {
            $Response.Dispose()
            throw "Redirect limit of 5 exceeded while requesting $RequestUri."
        }

        $NextUri = [System.Uri]::new($CurrentUri, $Location)
        if ($NextUri.Scheme -notin @('http', 'https')) {
            $Response.Dispose()
            throw "Redirect target uses an unsupported URI scheme: $($NextUri.Scheme)."
        }
        $Redirects.Add([pscustomobject][ordered]@{
            StatusCode = [int]$Response.StatusCode
            From       = $CurrentUri.AbsoluteUri
            To         = $NextUri.AbsoluteUri
        })
        $Response.Dispose()
        $CurrentUri = $NextUri
    }
}

function Get-SiteAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $Response = $null
    try {
        $ParsedUri = $null
        if (-not [System.Uri]::TryCreate($Target, [System.UriKind]::Absolute, [ref]$ParsedUri) -or $ParsedUri.Scheme -ne 'https') {
            throw "Target must be an absolute HTTPS URL: $Target"
        }

        Write-Log -Message "Checking $Target." -Component 'Request' -Type 1
        $Method = 'HEAD'
        $RequestResult = Invoke-HeaderRequest -Client $Client -RequestUri $ParsedUri -Method ([System.Net.Http.HttpMethod]::Head)
        $Response = $RequestResult.Response
        $HeadHasCsp = $Response.Headers.Contains('Content-Security-Policy') -or
            $Response.Headers.Contains('Content-Security-Policy-Report-Only') -or
            $Response.Content.Headers.Contains('Content-Security-Policy') -or
            $Response.Content.Headers.Contains('Content-Security-Policy-Report-Only')
        if ([int]$Response.StatusCode -in @(400, 403, 405, 501) -or -not $HeadHasCsp) {
            $Response.Dispose()
            $Response = $null
            $Method = 'GET'
            $RequestResult = Invoke-HeaderRequest -Client $Client -RequestUri $ParsedUri -Method ([System.Net.Http.HttpMethod]::Get)
            $Response = $RequestResult.Response
        }

        $Headers = @(ConvertTo-HeaderRecords -Response $Response)
        $CspValues = @(Get-HeaderValues -Headers $Headers -Name 'Content-Security-Policy')
        $ReportOnlyValues = @(Get-HeaderValues -Headers $Headers -Name 'Content-Security-Policy-Report-Only')
        $Policies = @(ConvertTo-CspPolicies -PolicyValues $CspValues)
        $ReportOnlyPolicies = @(ConvertTo-CspPolicies -PolicyValues $ReportOnlyValues)
        $Assessment = Test-CspPolicy -Policies $Policies -HasReportOnlyPolicy ($ReportOnlyPolicies.Count -gt 0)
        $Stopwatch.Stop()

        Write-Log -Message "$Target returned HTTP $([int]$Response.StatusCode) with CSP status $($Assessment.Status)." -Component 'Analysis' -Type 1
        return [pscustomobject][ordered]@{
            Target             = $Target
            Host               = $ParsedUri.Host
            FinalUrl           = $Response.RequestMessage.RequestUri.AbsoluteUri
            Redirected         = $RequestResult.Redirects.Count -gt 0
            RedirectCount      = $RequestResult.Redirects.Count
            Redirects          = @($RequestResult.Redirects)
            Method             = $Method
            HttpStatus         = [int]$Response.StatusCode
            ReasonPhrase       = [string]$Response.ReasonPhrase
            ElapsedMilliseconds = $Stopwatch.ElapsedMilliseconds
            Status             = $Assessment.Status
            Error              = $null
            Policies           = $Policies
            ReportOnlyPolicies = $ReportOnlyPolicies
            Findings           = @($Assessment.Findings)
            Headers            = $Headers
        }
    } catch {
        $NativeError = $_.Exception.Message
        if ($ParsedUri -and $NativeError -notlike 'Redirect limit of 5 exceeded*') {
            Write-Log -Message "$Target could not be analyzed with the native HTTP client. $NativeError" -Component 'Request' -Type 2
            try {
                $EdgeResult = Invoke-EdgeHeaderRequest -RequestUri $ParsedUri
                $Headers = @($EdgeResult.Headers)
                $CspValues = @(Get-HeaderValues -Headers $Headers -Name 'Content-Security-Policy')
                $ReportOnlyValues = @(Get-HeaderValues -Headers $Headers -Name 'Content-Security-Policy-Report-Only')
                $Policies = @(ConvertTo-CspPolicies -PolicyValues $CspValues)
                $ReportOnlyPolicies = @(ConvertTo-CspPolicies -PolicyValues $ReportOnlyValues)
                $Assessment = Test-CspPolicy -Policies $Policies -HasReportOnlyPolicy ($ReportOnlyPolicies.Count -gt 0)
                $Stopwatch.Stop()

                Write-Log -Message "$Target was analyzed using Microsoft Edge with CSP status $($Assessment.Status)." -Component 'EdgeFallback' -Type 2
                return [pscustomobject][ordered]@{
                    Target              = $Target
                    Host                = $ParsedUri.Host
                    FinalUrl            = $EdgeResult.FinalUrl
                    Redirected          = $EdgeResult.Redirects.Count -gt 0
                    RedirectCount       = $EdgeResult.Redirects.Count
                    Redirects           = @($EdgeResult.Redirects)
                    Method              = 'Edge GET'
                    HttpStatus          = $EdgeResult.StatusCode
                    ReasonPhrase        = $EdgeResult.ReasonPhrase
                    ElapsedMilliseconds = $Stopwatch.ElapsedMilliseconds
                    Status              = $Assessment.Status
                    Error               = $null
                    Policies            = $Policies
                    ReportOnlyPolicies  = $ReportOnlyPolicies
                    Findings            = @($Assessment.Findings)
                    Headers             = $Headers
                }
            } catch {
                $EdgeError = $_.Exception.Message
                Write-Log -Message "ERROR: Microsoft Edge fallback failed for $Target. $EdgeError Continuing with the remaining URLs." -Component 'EdgeFallback' -Type 3
                $NativeError = "$NativeError Microsoft Edge fallback failed. $EdgeError"
            }
        }

        $Stopwatch.Stop()
        Write-Log -Message "$Target could not be analyzed. $NativeError" -Component 'Request' -Type 2
        return [pscustomobject][ordered]@{
            Target             = $Target
            Host               = $Target
            FinalUrl           = $null
            Redirected         = $false
            RedirectCount      = 0
            Redirects          = @()
            Method             = $null
            HttpStatus         = $null
            ReasonPhrase       = $null
            ElapsedMilliseconds = $Stopwatch.ElapsedMilliseconds
            Status             = 'Request failed'
            Error              = $NativeError
            Policies           = @()
            ReportOnlyPolicies = @()
            Findings           = @([pscustomobject]@{ Severity = 'Missing'; Title = 'Request failed'; Detail = $NativeError })
            Headers            = @()
        }
    } finally {
        if ($Response) {
            $Response.Dispose()
        }
    }
}

function New-CspHtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ReportData
    )

    $Json = ($ReportData | ConvertTo-Json -Depth 12 -Compress).Replace('</script', '<\/script')
    $Template = @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CSP header analysis</title>
  <style>
    :root { --ink:#202626; --jet:#242c31; --muted:#737b80; --accent:#ea2c48; --deep:#9f2f45; --paper:#fff; --wash:#f3f4f4; --line:#d9dcdd; --good:#216e4e; --warn:#8a5700; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); background:linear-gradient(135deg,#f7f8f8 0,#eceeef 100%); font-family:Bahnschrift,"Trebuchet MS",sans-serif; letter-spacing:0; }
    button,input,select { font:inherit; letter-spacing:0; }
    button,select { cursor:pointer; }
    header { color:var(--paper); background:var(--jet); border-bottom:5px solid var(--accent); }
    .header-inner,main { width:min(100% - 32px,1500px); margin-inline:auto; }
    .header-inner { display:flex; justify-content:space-between; align-items:end; gap:24px; padding:26px 0 22px; }
    h1 { margin:0; font-family:Georgia,serif; font-size:clamp(1.7rem,3vw,2.7rem); font-weight:500; }
    .generated { margin:6px 0 0; color:#d9dcdd; font-size:.84rem; }
    .header-total { text-align:right; }
    .header-total strong { display:block; font-family:Georgia,serif; font-size:2rem; font-weight:500; }
    main { padding:22px 0 36px; }
    .summary { display:grid; grid-template-columns:repeat(4,minmax(130px,1fr)); border-block:1px solid var(--line); background:var(--paper); }
    .metric { padding:17px 20px; border-right:1px solid var(--line); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:.75rem; font-weight:700; text-transform:uppercase; }
    .metric strong { font-family:Georgia,serif; font-size:1.6rem; font-weight:500; }
    .toolbar { display:grid; grid-template-columns:minmax(220px,1fr) minmax(170px,auto) auto; gap:10px; align-items:end; padding:20px 0; }
    label { display:grid; gap:5px; color:var(--muted); font-size:.75rem; font-weight:700; text-transform:uppercase; }
    input,select { min-height:40px; width:100%; border:1px solid var(--line); border-radius:4px; padding:8px 10px; color:var(--ink); background:var(--paper); }
    button:focus-visible,input:focus,select:focus { outline:3px solid color-mix(in srgb,var(--accent) 45%,transparent); outline-offset:2px; }
    .reset { min-height:40px; border:1px solid var(--jet); border-radius:4px; padding:8px 14px; color:var(--paper); background:var(--jet); }
    .site-list { display:grid; gap:12px; }
    .site { border:1px solid var(--line); border-left:5px solid var(--muted); border-radius:6px; background:var(--paper); overflow:hidden; }
    .site.good { border-left-color:var(--good); } .site.review { border-left-color:var(--warn); } .site.missing,.site.request-failed { border-left-color:var(--accent); }
    .site-summary { display:grid; grid-template-columns:minmax(190px,1.3fr) minmax(110px,.5fr) minmax(110px,.5fr) minmax(120px,.5fr) auto; gap:14px; align-items:center; width:100%; border:0; padding:16px 18px; color:inherit; background:transparent; text-align:left; }
    .site-summary:hover { background:var(--wash); }
    .host { min-width:0; overflow-wrap:anywhere; } .host strong { display:block; font-size:1rem; } .host small,.cell-label { color:var(--muted); }
    .cell-label { display:block; margin-bottom:3px; font-size:.7rem; font-weight:700; text-transform:uppercase; }
    .badge { display:inline-block; border-radius:3px; padding:4px 8px; color:var(--paper); background:var(--muted); font-size:.74rem; font-weight:700; }
    .badge.good { background:var(--good); } .badge.review { background:var(--warn); } .badge.missing,.badge.request-failed { background:var(--deep); }
    .indicator { width:1.2em; color:var(--deep); font-size:1rem; text-align:center; }
    .details { display:none; padding:0 18px 20px; border-top:1px solid var(--line); }
    .site.open .details { display:block; }
    .details-grid { display:grid; grid-template-columns:1fr 1fr; gap:22px; padding-top:18px; }
    h2 { margin:0 0 10px; font-family:Georgia,serif; font-size:1.2rem; font-weight:500; }
    .finding { margin:0 0 8px; padding:10px 12px; border-left:3px solid var(--muted); background:var(--wash); }
    .finding.review,.finding.missing { border-left-color:var(--accent); } .finding strong { display:block; margin-bottom:3px; } .finding p { margin:0; color:var(--muted); font-size:.86rem; }
    .policy { margin-bottom:12px; padding:12px; border:1px solid var(--line); background:#fafafa; }
    .policy-title { margin:0 0 8px; font-weight:700; }
    .directive { display:grid; grid-template-columns:minmax(140px,.35fr) 1fr; gap:10px; padding:6px 0; border-top:1px solid var(--line); font-family:Consolas,monospace; font-size:.82rem; overflow-wrap:anywhere; }
    .raw { max-height:310px; overflow:auto; margin:0; padding:12px; color:#f3f4f4; background:var(--jet); font-family:Consolas,monospace; font-size:.78rem; white-space:pre-wrap; overflow-wrap:anywhere; }
    .error { color:var(--deep); font-weight:700; }
    .empty { padding:50px 20px; color:var(--muted); background:var(--paper); text-align:center; border:1px solid var(--line); }
    [hidden] { display:none !important; }
    @media (max-width:800px) { .summary { grid-template-columns:1fr 1fr; } .metric:nth-child(2) { border-right:0; } .metric:nth-child(-n+2) { border-bottom:1px solid var(--line); } .site-summary { grid-template-columns:1fr 1fr; } .host { grid-column:1/-1; } .indicator { position:absolute; right:20px; } .details-grid { grid-template-columns:1fr; } }
    @media (max-width:520px) { .header-inner,main { width:min(100% - 20px,1500px); } .header-total { display:none; } .toolbar { grid-template-columns:1fr; } .summary { grid-template-columns:1fr; } .metric { border-right:0; border-bottom:1px solid var(--line); } .metric:last-child { border-bottom:0; } .site-summary { grid-template-columns:1fr; } .host { grid-column:auto; } }
  </style>
</head>
<body>
  <header><div class="header-inner"><div><h1>Content Security Policy analysis</h1><p class="generated" id="generated"></p></div><div class="header-total"><strong id="visible">0</strong><span>visible sites</span></div></div></header>
  <main>
    <section class="summary" aria-label="Analysis totals"><div class="metric"><span>Sites checked</span><strong id="total">0</strong></div><div class="metric"><span>Good</span><strong id="good">0</strong></div><div class="metric"><span>Review or missing</span><strong id="attention">0</strong></div><div class="metric"><span>Request failed</span><strong id="failed">0</strong></div></section>
    <section class="toolbar" aria-label="Report filters"><label>Search sites<input id="search" type="search" placeholder="Host, URL, finding..." autocomplete="off"></label><label>Status<select id="status"><option value="">All statuses</option><option>Good</option><option>Review</option><option>Missing</option><option>Request failed</option></select></label><button class="reset" id="reset" type="button">Reset filters</button></section>
    <div class="site-list" id="sites"></div><div class="empty" id="empty" hidden>No sites match the current filters.</div>
  </main>
  <script id="reportData" type="application/json">__REPORT_DATA__</script>
  <script>
    const REPORT=JSON.parse(document.getElementById('reportData').textContent);const sites=document.getElementById('sites');const search=document.getElementById('search');const status=document.getElementById('status');const empty=document.getElementById('empty');
    const text=value=>value===null||value===undefined?'':String(value);const css=value=>text(value).toLowerCase().replaceAll(' ','-');
    function element(tag,className='',content=''){const node=document.createElement(tag);if(className)node.className=className;if(content!=='')node.textContent=content;return node}
    function policyBlock(policy,label){const box=element('div','policy');box.appendChild(element('p','policy-title',label));if(!policy.Directives.length)box.appendChild(element('div','','Empty policy'));policy.Directives.forEach(item=>{const row=element('div','directive');row.appendChild(element('strong','',item.Name));row.appendChild(element('span','',item.Sources.join(' ')||'(no source values)'));box.appendChild(row)});return box}
        function render(){const query=search.value.trim().toLowerCase();const selected=status.value;const rows=REPORT.results.filter(row=>(!selected||row.Status===selected)&&(!query||JSON.stringify(row).toLowerCase().includes(query)));sites.replaceChildren();rows.forEach(row=>{const card=element('article',`site ${css(row.Status)}`);const button=element('button','site-summary');button.type='button';button.setAttribute('aria-expanded','false');const host=element('div','host');host.appendChild(element('strong','',row.Host));host.appendChild(element('small','',row.FinalUrl||row.Target));button.appendChild(host);const statusCell=element('div');statusCell.appendChild(element('span','cell-label','Assessment'));statusCell.appendChild(element('span',`badge ${css(row.Status)}`,row.Status));button.appendChild(statusCell);const http=element('div');http.appendChild(element('span','cell-label','HTTP'));http.appendChild(element('span','',row.HttpStatus?`${row.HttpStatus} ${row.ReasonPhrase}`:'Unavailable'));button.appendChild(http);const timing=element('div');timing.appendChild(element('span','cell-label','Request'));const redirectText=row.RedirectCount?` | ${row.RedirectCount} redirect${row.RedirectCount===1?'':'s'}`:'';timing.appendChild(element('span','',row.Method?`${row.Method} | ${row.ElapsedMilliseconds} ms${redirectText}`:`${row.ElapsedMilliseconds} ms`));button.appendChild(timing);button.appendChild(element('span','indicator','+'));card.appendChild(button);
            const details=element('div','details');const grid=element('div','details-grid');const findings=element('section');findings.appendChild(element('h2','','Findings'));if(row.Error)findings.appendChild(element('p','error',row.Error));row.Findings.forEach(item=>{const finding=element('div',`finding ${css(item.Severity)}`);finding.appendChild(element('strong','',`${item.Severity}: ${item.Title}`));finding.appendChild(element('p','',item.Detail));findings.appendChild(finding)});grid.appendChild(findings);const policies=element('section');policies.appendChild(element('h2','','Policies and directives'));row.Policies.forEach((item,index)=>policies.appendChild(policyBlock(item,`Enforced policy ${index+1}`)));row.ReportOnlyPolicies.forEach((item,index)=>policies.appendChild(policyBlock(item,`Report-only policy ${index+1}`)));if(!row.Policies.length&&!row.ReportOnlyPolicies.length)policies.appendChild(element('p','','No CSP policy values were returned.'));grid.appendChild(policies);details.appendChild(grid);if(row.Redirects.length){details.appendChild(element('h2','','Redirect chain'));const redirectChain=element('pre','raw');redirectChain.textContent=row.Redirects.map(item=>`${item.StatusCode}: ${item.From}\n  -> ${item.To}`).join('\n');details.appendChild(redirectChain)}details.appendChild(element('h2','','Response headers'));const raw=element('pre','raw');raw.textContent=row.Headers.map(item=>`${item.Name}: ${item.Values.join('\n  ')}`).join('\n')||'No response headers were captured.';details.appendChild(raw);card.appendChild(details);button.addEventListener('click',()=>{const open=card.classList.toggle('open');button.setAttribute('aria-expanded',String(open));button.querySelector('.indicator').textContent=open?'-':'+'});sites.appendChild(card)});document.getElementById('visible').textContent=rows.length;empty.hidden=rows.length!==0}
    document.getElementById('generated').textContent=`Generated ${new Date(REPORT.generatedAt).toLocaleString()} | ${REPORT.timeoutSeconds} second request timeout`;document.getElementById('total').textContent=REPORT.results.length;document.getElementById('good').textContent=REPORT.results.filter(row=>row.Status==='Good').length;document.getElementById('attention').textContent=REPORT.results.filter(row=>row.Status==='Review'||row.Status==='Missing').length;document.getElementById('failed').textContent=REPORT.results.filter(row=>row.Status==='Request failed').length;search.addEventListener('input',render);status.addEventListener('change',render);document.getElementById('reset').addEventListener('click',()=>{search.value='';status.value='';render()});render();
  </script>
</body>
</html>
'@
    return $Template.Replace('__REPORT_DATA__', $Json)
}

# Main
try {
    Initialize-Script
    Write-Log -Message "Starting CSP analysis for $($Url.Count) targets." -Component 'Startup' -Type 1

    $Handler = [System.Net.Http.SocketsHttpHandler]::new()
    $Handler.AllowAutoRedirect = $false
    $Client = [System.Net.Http.HttpClient]::new($Handler)
    $Client.Timeout = [timespan]::FromSeconds($TimeoutSeconds)
    try {
        $Results = @($Url | ForEach-Object { Get-SiteAnalysis -Client $Client -Target $_ })
    } finally {
        $Client.Dispose()
        $Handler.Dispose()
    }

    $ReportData = [ordered]@{
        generatedAt    = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        timeoutSeconds = $TimeoutSeconds
        results        = $Results
    }
    $Html = New-CspHtmlReport -ReportData $ReportData
    Set-Content -LiteralPath $Script:OutputPath -Value $Html -Encoding UTF8

    $GoodCount = @($Results | Where-Object { $_.Status -eq 'Good' }).Count
    $ReviewCount = @($Results | Where-Object { $_.Status -in @('Review', 'Missing') }).Count
    $FailedCount = @($Results | Where-Object { $_.Status -eq 'Request failed' }).Count
    $Message = "Created CSP report at $($Script:OutputPath). Good: $GoodCount; review or missing: $ReviewCount; request failed: $FailedCount."
    Write-Log -Message $Message -Component 'Report' -Type 1
    Write-Output $Message

    if ($OpenReport) {
        Start-Process -FilePath $Script:OutputPath
    }
    exit 0
} catch {
    if ($Script:LogFile) {
        Write-Log -Message $_.Exception.Message -Component 'Error' -Type 3
    }
    Write-Error "CSP analysis stopped. $($_.Exception.Message)"
    exit 1
}