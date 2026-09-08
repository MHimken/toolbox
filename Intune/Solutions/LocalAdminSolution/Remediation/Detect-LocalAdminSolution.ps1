<#
.SYNOPSIS
    Detects whether the device should run the LocalAdminSolution remediation.
.DESCRIPTION
    This detection script targets domain joined, Microsoft Entra joined, and hybrid joined devices.
    Applicable devices return noncompliant when no successful run timestamp exists or the configured
    interval has elapsed. The paired remediation collects local Administrators membership and uploads
    the result to Azure Table Storage.
.PARAMETER RemediationIntervalHours
    Number of hours between successful inventory uploads. Defaults to four hours.
.NOTES
    Version: 1.1
    Author: Martin Himken
    Original script name: Detect-LocalAdminSolution.ps1
    Initial creation date: 2026-08-30
    Last change: 2026-09-08
.LINK
    ..\changelog.md
#>

param(
    [ValidateRange(1, 8760)]
    [int]$RemediationIntervalHours = 4
)

$DomainName = ''
$MaxRetries = 3
$RetryDelaySeconds = 5
$StateRegistryPath = 'HKLM:\Software\LocalAdminSolution'
$LastSuccessfulRunValueName = 'LastSuccessfulRunUtc'

$ErrorActionPreference = 'Stop'

function Get-JoinState {
    $joinInfoPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDomainJoined = $false

    if ($null -ne $computerSystem) {
        $isDomainJoined = [bool]$computerSystem.PartOfDomain
    }

    $isEntraJoined = (Get-ChildItem -LiteralPath $joinInfoPath -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
    $joinType = 0

    if ($isDomainJoined -and $isEntraJoined) {
        $joinType = 2
    } elseif ((-not $isDomainJoined) -and $isEntraJoined) {
        $joinType = 1
    } elseif ($isDomainJoined) {
        $joinType = 3
    }

    [pscustomobject]@{
        IsDomainJoined   = $isDomainJoined
        IsEntraJoined    = $isEntraJoined
        EntraOrHybrid    = $joinType
        DomainName       = if ($null -ne $computerSystem) { $computerSystem.Domain } else { '' }
        ConfigDomainName = $DomainName
        MaxRetries       = $MaxRetries
        RetryDelay       = $RetryDelaySeconds
    }
}

try {
    $joinState = Get-JoinState

    if ($joinState.EntraOrHybrid -eq 0) {
        Write-Output 'COMPLIANT: Device is neither domain joined, hybrid joined, nor Microsoft Entra joined only.'
        exit 0
    }

    $lastSuccessfulRunText = [string](Get-ItemPropertyValue -LiteralPath $StateRegistryPath -Name $LastSuccessfulRunValueName -ErrorAction SilentlyContinue)
    $lastSuccessfulRunUtc = [datetime]::MinValue
    $hasValidTimestamp = [datetime]::TryParseExact(
        $lastSuccessfulRunText,
        'o',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
        [ref]$lastSuccessfulRunUtc
    )

    if ($hasValidTimestamp) {
        $nextRunUtc = $lastSuccessfulRunUtc.AddHours($RemediationIntervalHours)
        if ([datetime]::UtcNow -lt $nextRunUtc) {
            Write-Output ('COMPLIANT: Last successful LocalAdminSolution run was {0}; next run is due at {1}.' -f $lastSuccessfulRunUtc.ToString('o'), $nextRunUtc.ToString('o'))
            exit 0
        }
    }

    Write-Output ('NONCOMPLIANT: LocalAdminSolution inventory is due; the successful-run interval is {0} hours.' -f $RemediationIntervalHours)
    exit 1
} catch {
    Write-Output "ERROR: Detection failed. $($_.Exception.Message)"
    exit 1
}