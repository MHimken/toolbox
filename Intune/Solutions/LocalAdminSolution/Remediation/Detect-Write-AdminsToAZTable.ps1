<#
.SYNOPSIS
    Detects whether the device should run the Write-AdminsToAZTable remediation.
.DESCRIPTION
    This detection script targets domain joined, Microsoft Entra joined, and hybrid joined devices.
    Applicable devices always return noncompliant so the paired remediation can collect
    local Administrators membership and upload the result to Azure Table Storage.
.NOTES
    Version: 1.0
    Author: Martin Himken
    Original script name: Detect-Write-AdminsToAZTable.ps1
    Initial creation date: 2026-08-30
    Last change: 2026-09-02
    Changes: Added the required script metadata header.
.LINK
    ..\changelog.md
#>

$DomainName = ''
$MaxRetries = 3
$RetryDelaySeconds = 5

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

    Write-Output 'NONCOMPLIANT: Device is applicable and should run Write-AdminsToAZTable remediation.'
    exit 1
} catch {
    Write-Output "ERROR: Detection failed. $($_.Exception.Message)"
    exit 1
}