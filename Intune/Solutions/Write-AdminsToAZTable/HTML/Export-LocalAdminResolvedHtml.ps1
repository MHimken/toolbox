<#
.SYNOPSIS
    Exports the resolved local administrator Azure Table data to an interactive HTML report.
.DESCRIPTION
    Reads every page from LocalAdminCollection, AdminUserNames, and AdminGroups, resolves user
    and group SIDs to names, translates device join states, and writes a self-contained HTML
    snapshot. The SAS token is used during export and is not stored in the generated report.
.PARAMETER StorageAccountName
    Azure Storage account containing the three solution tables.
.PARAMETER SasToken
    Read-enabled SAS token. When omitted, the token is read from the remediation script.
.PARAMETER OutputPath
    Path of the generated standalone HTML report.
.PARAMETER OpenReport
    Opens the generated report in the default browser.
.PARAMETER LogPath
    Directory in which the log file is created.
.PARAMETER LogFile
    Log filename. When omitted, a timestamped filename is generated.
.LINK
    ..\changelog.md
#>

[CmdletBinding()]
param(
    [string]$StorageAccountName = '<storage-account-name>',
    [string]$SasToken,
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'LocalAdminResolved.html'),
    [switch]$OpenReport,
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null
)

function Write-Log {
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
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
    $pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwsh7Path) {
        throw 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
    }

    $script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    if (-not $LogFile) {
        $script:ResolvedLogFile = "Export-LocalAdminResolvedHtml_$($script:DateTime).log"
    } else {
        $script:ResolvedLogFile = $LogFile
    }
    if (-not (Test-Path -LiteralPath $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType Directory -Force
    }
    $script:LogFile = Join-Path -Path $LogPath -ChildPath $script:ResolvedLogFile
    $script:ToConsole = $false
}

function Get-ConfiguredSasToken {
    param([string]$Token)

    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $resolvedToken = $Token.TrimStart('?')
        if ($resolvedToken -eq '<sas-token>') {
            throw 'SasToken is not configured.'
        }
        return $resolvedToken
    }

    $solutionRoot = Split-Path -Path $PSScriptRoot -Parent
    $remediationPath = Join-Path -Path $solutionRoot -ChildPath 'Remediation\Remediate-Write-AdminsToAZTable.ps1'
    $remediationContent = Get-Content -LiteralPath $remediationPath -Raw
    $tokenMatch = [regex]::Match($remediationContent, '\$sasToken\s*=\s*''([^'']+)''')
    if (-not $tokenMatch.Success) {
        throw 'The SAS token could not be read from the remediation script.'
    }
    $resolvedToken = $tokenMatch.Groups[1].Value.TrimStart('?')
    if ($resolvedToken -eq '<sas-token>') {
        throw 'SasToken is not configured. Pass it using the SasToken parameter.'
    }
    return $resolvedToken
}

function Get-AzureTableEntities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $entities = [System.Collections.Generic.List[object]]::new()
    $nextPartitionKey = $null
    $nextRowKey = $null

    do {
        $query = $Token
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $query += '&NextPartitionKey=' + [System.Uri]::EscapeDataString($nextPartitionKey)
            if (-not [string]::IsNullOrWhiteSpace($nextRowKey)) {
                $query += '&NextRowKey=' + [System.Uri]::EscapeDataString($nextRowKey)
            }
        }

        $uri = 'https://{0}.table.core.windows.net/{1}()?{2}' -f $AccountName, $TableName, $query
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{
            Accept         = 'application/json;odata=nometadata'
            'x-ms-version' = '2023-11-03'
        }
        foreach ($entity in @(($response.Content | ConvertFrom-Json).value)) {
            $entities.Add($entity)
        }
        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
    } while (-not [string]::IsNullOrWhiteSpace($nextPartitionKey))

    return $entities
}

function ConvertTo-ResolvedData {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$MainEntities,
        [Parameter(Mandatory = $true)]
        [object[]]$UserEntities,
        [Parameter(Mandatory = $true)]
        [object[]]$GroupEntities
    )

    $usersBySid = @{}
    foreach ($user in $UserEntities) {
        $usersBySid[[string]$user.PartitionKey] = $user
    }
    $groupsBySid = @{}
    foreach ($group in $GroupEntities) {
        $groupsBySid[[string]$group.PartitionKey] = $group
    }

    $resolved = foreach ($entity in $MainEntities) {
        $userSid = [string]$entity.UserID
        $groupSid = [string]$entity.GroupID
        $joinState = switch ([string]$entity.EntraOrHybrid) {
            '1' { 'Entra joined' }
            '2' { 'Hybrid joined' }
            '3' { 'Domain joined' }
            default { if ($null -eq $entity.EntraOrHybrid) { $null } else { "Unknown ($($entity.EntraOrHybrid))" } }
        }
        $userName = if ($userSid -and $usersBySid.ContainsKey($userSid)) { [string]$usersBySid[$userSid].RowKey } else { $userSid }
        $groupName = if ($groupSid -and $groupsBySid.ContainsKey($groupSid)) { [string]$groupsBySid[$groupSid].RowKey } else { $groupSid }

        [pscustomobject][ordered]@{
            ComputerName                   = [string]$entity.Computername
            SID                            = [string]$entity.PartitionKey
            RowKey                         = [int]$entity.RowKey
            EntraOrHybrid                  = $joinState
            LastReportTimeStamp            = $entity.LastReportTimeStamp
            LocalAdminGroupName            = [string]$entity.LocalAdminGroupName
            Removed                        = [int]$entity.Removed
            UserName                       = $userName
            GroupName                      = $groupName
            LocalAccountLastPasswordChange = $entity.LocalAccountLastPasswordChange
            Timestamp                      = $entity.Timestamp
            _UserSID                       = $userSid
            _GroupSID                      = $groupSid
        }
    }

    return @($resolved | Sort-Object RowKey)
}

function ConvertTo-UserDetails {
    param([object[]]$Entities)
    return @($Entities | ForEach-Object {
        [pscustomobject][ordered]@{
            UserID              = [string]$_.PartitionKey
            SamAccountName      = [string]$_.RowKey
            UserPrincipalName   = [string]$_.UserPrincipalName
            LocalOrEntraOrAD    = [string]$_.LocalOrEntraOrAD
            Timestamp           = $_.Timestamp
        }
    })
}

function ConvertTo-GroupDetails {
    param([object[]]$Entities)
    return @($Entities | ForEach-Object {
        [pscustomobject][ordered]@{
            GroupID           = [string]$_.PartitionKey
            GroupName         = [string]$_.RowKey
            LocalOrEntraOrAD  = [string]$_.LocalOrEntraOrAD
            Timestamp         = $_.Timestamp
        }
    })
}

try {
    Initialize-Script
    if ([string]::IsNullOrWhiteSpace($StorageAccountName) -or $StorageAccountName -eq '<storage-account-name>') {
        throw 'StorageAccountName is not configured.'
    }
    $resolvedSasToken = Get-ConfiguredSasToken -Token $SasToken
    Write-Log -Message 'Reading all three Azure tables.' -Component 'Read' -Type 1

    $mainEntities = @(Get-AzureTableEntities -TableName 'LocalAdminCollection' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $userEntities = @(Get-AzureTableEntities -TableName 'AdminUserNames' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $groupEntities = @(Get-AzureTableEntities -TableName 'AdminGroups' -AccountName $StorageAccountName -Token $resolvedSasToken)
    $reportData = [ordered]@{
        generatedAt = [datetime]::UtcNow.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        summary     = ConvertTo-ResolvedData -MainEntities $mainEntities -UserEntities $userEntities -GroupEntities $groupEntities
        users       = ConvertTo-UserDetails -Entities $userEntities
        groups      = ConvertTo-GroupDetails -Entities $groupEntities
    }

    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'LocalAdminResolvedLive.html'
    if (-not (Test-Path -LiteralPath $templatePath)) {
        throw "The HTML template was not found at $templatePath."
    }
    $json = ($reportData | ConvertTo-Json -Depth 8 -Compress).Replace('</script', '<\/script')
    $html = (Get-Content -LiteralPath $templatePath -Raw).Replace('__REPORT_DATA__', $json)
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force
    }
    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8

    $message = "SUCCESS: Exported $($mainEntities.Count) resolved rows, $($userEntities.Count) users, and $($groupEntities.Count) groups to $OutputPath."
    Write-Log -Message $message -Component 'Export' -Type 1
    Write-Output $message
    if ($OpenReport) {
        Start-Process -FilePath $OutputPath
    }
    exit 0
} catch {
    if ($script:LogFile) {
        Write-Log -Message $_.Exception.Message -Component 'Error' -Type 3
    }
    Write-Error "HTML report export failed. $($_.Exception.Message)"
    exit 1
}