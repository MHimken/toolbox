<#
.SYNOPSIS
Collects NTLM audit events (ID 8004) from multiple domain controllers and exports the results to CSV.

.DESCRIPTION
This script queries the Microsoft-Windows-NTLM/Operational event log on DC13 through DC15 for event ID 8004.
It gathers results in parallel, normalizes relevant fields, and exports the combined dataset to CSV.

.PARAMETER LogPath
Specifies the directory where the log file is written.

.PARAMETER LogFile
Specifies the log file name. If not specified, a name is generated automatically.

.PARAMETER CsvOutputPath
Specifies the output directory for the CSV export. The default value is C:\Work\.

.PARAMETER CsvFileName
Specifies the CSV file name. If not specified, a name is generated automatically.

.PARAMETER DomainControllers
Specifies the domain controllers to query.

.PARAMETER EventLogName
Specifies the event log name to query.

.PARAMETER EventId
Specifies the event ID to query.

.PARAMETER ThrottleLimit
Specifies how many parallel runspaces are used when querying domain controllers.

.NOTES
Version: 0.1
Author: MHimken
Original script name: NTLMAuditAnalyse.ps1
Initial creation date: 2026-07-29
Last change: 2026-07-29
Changes: Initial version
#>

[CmdletBinding()]
param(
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null,
    [string]$CsvOutputPath = 'C:\Work\',
    [string]$CsvFileName = $null,
    [string[]]$DomainControllers = @('DC13', 'DC14', 'DC15'),
    [string]$EventLogName = 'Microsoft-Windows-NTLM/Operational',
    [int]$EventId = 8004,
    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 3
)

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
        [ValidateSet('1', '2', '3')][int]$Type
    )
    if (-not($NoOutput)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
        } elseif ($ToConsole) {
            switch ($type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}

function Initialize-Script {
    $Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $Pwsh7Path) {
        Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
        exit 1
    }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Error 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
        exit 1
    }

    # Set default script state for logging and output file names.
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'NTLMAuditAnalyse'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''

    if (-not($LogFile)) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }

    if (-not(Test-Path -LiteralPath $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }

    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Global:LogFile = $Script:LogFile
    $Global:NoOutput = $false
    $Global:ToConsole = $false

    if (-not($CsvFileName)) {
        $CsvFileName = "$($SanitizedScriptName)_$($Script:DateTime).csv"
    }

    if (-not(Test-Path -LiteralPath $CsvOutputPath)) {
        New-Item -Path $CsvOutputPath -ItemType Directory -Force | Out-Null
    }

    $Script:CsvExportPath = Join-Path -Path $CsvOutputPath -ChildPath $CsvFileName
}

function Get-NtlmAuditEventData {
    param(
        [string[]]$ComputerName,
        [string]$LogName,
        [int]$TargetEventId,
        [int]$ParallelThrottle
    )

    $events = $ComputerName | ForEach-Object -Parallel {
        $currentDc = $_

        try {
            $records = Get-WinEvent -ComputerName $currentDc -LogName $using:LogName -FilterXPath "*[System[EventID=$using:TargetEventId]]" -ErrorAction Stop

            foreach ($record in $records) {
                [pscustomobject]@{
                    TimeCreated      = $record.TimeCreated
                    SecureChannelName = if ($record.Properties.Count -gt 0) { $record.Properties[0].Value } else { $null }
                    User             = if ($record.Properties.Count -gt 1) { $record.Properties[1].Value } else { $null }
                    ClientPC         = if ($record.Properties.Count -gt 2) { $record.Properties[2].Value } else { $null }
                    ServerName       = if ($record.Properties.Count -gt 3) { $record.Properties[3].Value } else { $null }
                    NTLMVersion      = if ($record.Properties.Count -gt 4) { $record.Properties[4].Value } else { $null }
                    DomainController = $currentDc
                }
            }
        }
        catch {
            [pscustomobject]@{
                TimeCreated      = $null
                SecureChannelName = $null
                User             = $null
                ClientPC         = $null
                ServerName       = $null
                NTLMVersion      = $null
                DomainController = $currentDc
                Error            = $_.Exception.Message
            }
        }
    } -ThrottleLimit $ParallelThrottle

    return $events
}

function Export-NtlmAuditData {
    param(
        [array]$InputObject,
        [string]$Path
    )

    $InputObject |
        Sort-Object -Property TimeCreated |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

# Main
Initialize-Script

Write-Log -Message "Starting NTLM audit collection from: $($DomainControllers -join ', ')" -Component 'Main' -Type 1
Write-Log -Message "Querying event log '$EventLogName' for event ID $EventId" -Component 'Main' -Type 1

$ntlmAuditData = Get-NtlmAuditEventData -ComputerName $DomainControllers -LogName $EventLogName -TargetEventId $EventId -ParallelThrottle $ThrottleLimit

if (-not $ntlmAuditData) {
    Write-Log -Message 'No data returned from domain controllers.' -Component 'Main' -Type 2
    Write-Warning 'No data returned from domain controllers.'
    exit 0
}

$errorCount = ($ntlmAuditData | Where-Object { $_.PSObject.Properties.Name -contains 'Error' }).Count
$eventCount = ($ntlmAuditData | Where-Object { $_.PSObject.Properties.Name -notcontains 'Error' }).Count

Write-Log -Message "Collected $eventCount event rows. Domain controller query errors: $errorCount" -Component 'Main' -Type 1

try {
    Export-NtlmAuditData -InputObject $ntlmAuditData -Path $Script:CsvExportPath
    Write-Log -Message "Export complete: $Script:CsvExportPath" -Component 'Main' -Type 1
    Write-Host "CSV exported to: $Script:CsvExportPath"
}
catch {
    Write-Log -Message "CSV export failed: $($_.Exception.Message)" -Component 'Main' -Type 3
    throw
}