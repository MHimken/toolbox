<#
.SYNOPSIS
Analyzes LDAP signing related Directory Service events and shows unsigned or failing LDAP requests.

.DESCRIPTION
Collects LDAP signing and LDAP channel binding events using Get-WinEvent with an XPath filter and presents
findings in Out-GridView. The script includes event id, event name, source, and account information when available.

.PARAMETER LogPath
Specifies the log directory path. The default value is the script folder.

.PARAMETER LogFile
Specifies the log file name. If omitted, a file name is generated automatically using the script name
and an ISO 8601 24-hour timestamp.

.PARAMETER ComputerName
Specifies the server whose Directory Service log should be queried. The default is the local computer.
When a remote server is specified, local registry and audit policy checks are skipped and assumed to be configured correctly.

.NOTES
Version: 0.1
Author: Martin Himken
Original script name: LDAPSigningAnalyzer.ps1
Initial creation date: 2026-07-22
Last change: 2026-08-13
Changes: Add LDAP channel binding events 3039-3041 and 3074-3075 and query all supported LDAP security events
#>

[CmdletBinding()]
param(
	[string]$LogPath = $PSScriptRoot,
	[string]$LogFile = $null,
	[string]$ComputerName = $env:COMPUTERNAME
)

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

function Test-PowerShell7Requirement {
	$Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
	if (-not $Pwsh7Path) {
		Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
		exit 1
	}
	if ($PSVersionTable.PSVersion.Major -lt 7) {
		Write-Error 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
		exit 1
	}
}

function Initialize-Script {
	$Script:ToConsole = $false
	$Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
	$DefinedScriptName = 'LDAPSigningAnalyzer'
	$SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
	$Script:IsRemoteTarget = $ComputerName -notin @('.', 'localhost', $env:COMPUTERNAME)

	if (-not $LogPath) {
		$LogPath = $PSScriptRoot
	}

	if (-not (Test-Path -Path $LogPath)) {
		New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
	}

	if (-not($LogFile)) {
		$LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
	}

	$Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
	Write-Log -Message "Script initialized. Log file path: $($Script:LogFile)" -Component 'Initialize-Script' -Type 1
}

function Get-LdapSigningEventName {
	param(
		[int]$EventId
	)

	switch ($EventId) {
		2886 { 'LDAP signing not required' }
		2887 { 'Unsigned LDAP binds detected' }
		2888 { 'Unsigned LDAP binds rejected' }
		2889 { 'Unsigned LDAP bind details' }
		3039 { 'LDAP channel binding validation failed' }
		3040 { 'Unprotected LDAP binds detected' }
		3041 { 'LDAP channel binding not required' }
		3074 { 'LDAP channel binding would fail: invalid token' }
		3075 { 'LDAP channel binding would fail: missing information' }
		default { 'Unknown LDAP signing event' }
	}
}

function Test-LdapSigningAuditConfiguration {
	$result = [PSCustomObject]@{
		IsDomainController          = $false
		DirectoryServiceAuditPolicy = 'NotChecked'
		LdapInterfaceEventsLevel    = 'NotChecked'
	}

	if ($Script:IsRemoteTarget) {
		$result.DirectoryServiceAuditPolicy = 'AssumedConfiguredForRemoteTarget'
		$result.LdapInterfaceEventsLevel = 'AssumedConfiguredForRemoteTarget'
		Write-Log -Message "Remote target '$ComputerName' specified. Registry and audit policy checks are skipped and assumed to be configured correctly." -Component 'AuditCheck' -Type 2
		return $result
	}

	try {
		$domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
		$result.IsDomainController = ($domainRole -ge 4)
	} catch {
		Write-Log -Message "Failed to determine domain role. $($_.Exception.Message)" -Component 'AuditCheck' -Type 2
		return $result
	}

	if (-not $result.IsDomainController) {
		Write-Log -Message 'Device is not a domain controller. LDAP signing audit prerequisites are skipped.' -Component 'AuditCheck' -Type 2
		return $result
	}

	$diagnosticsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
	$diagnosticsName = '16 LDAP Interface Events'
	try {
		$currentLevel = (Get-ItemProperty -Path $diagnosticsPath -Name $diagnosticsName -ErrorAction SilentlyContinue).$diagnosticsName
		if ($null -eq $currentLevel -or [int]$currentLevel -lt 2) {
			Set-ItemProperty -Path $diagnosticsPath -Name $diagnosticsName -Value 2 -Type DWord -ErrorAction Stop
			$result.LdapInterfaceEventsLevel = 'SetTo2'
			Write-Log -Message 'Configured LDAP Interface Events level to 2.' -Component 'AuditCheck' -Type 1
		} else {
			$result.LdapInterfaceEventsLevel = "AlreadySetTo$currentLevel"
			Write-Log -Message "LDAP Interface Events level already set to $currentLevel." -Component 'AuditCheck' -Type 1
		}
	} catch {
		$result.LdapInterfaceEventsLevel = 'FailedToSet'
		Write-Log -Message "Failed to configure LDAP Interface Events level. $($_.Exception.Message)" -Component 'AuditCheck' -Type 2
	}

	try {
		$auditPolPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\auditpol.exe'
		if (Test-Path -Path $auditPolPath) {
			$null = & $auditPolPath /set /subcategory:"Directory Service Access" /success:enable /failure:enable 2>&1
			if ($LASTEXITCODE -eq 0) {
				$result.DirectoryServiceAuditPolicy = 'EnabledSuccessAndFailure'
				Write-Log -Message 'Enabled Directory Service Access audit policy (success and failure).' -Component 'AuditCheck' -Type 1
			} else {
				$result.DirectoryServiceAuditPolicy = 'FailedToSet'
				Write-Log -Message 'Could not set Directory Service Access audit policy. Check administrative rights.' -Component 'AuditCheck' -Type 2
			}
		} else {
			$result.DirectoryServiceAuditPolicy = 'AuditPolNotFound'
			Write-Log -Message 'auditpol.exe was not found. Audit policy was not changed.' -Component 'AuditCheck' -Type 2
		}
	} catch {
		$result.DirectoryServiceAuditPolicy = 'FailedToSet'
		Write-Log -Message "Failed while setting audit policy. $($_.Exception.Message)" -Component 'AuditCheck' -Type 2
	}

	return $result
}

function Get-LdapSigningEvents {
	$xPath = "*[System[Provider[@Name='Microsoft-Windows-ActiveDirectory_DomainService'] and (EventID=2886 or EventID=2887 or EventID=2888 or EventID=2889 or EventID=3039 or EventID=3040 or EventID=3041 or EventID=3074 or EventID=3075)]]"

	try {
		Write-Log -Message "Reading Directory Service log with XPath: $xPath" -Component 'Get-LdapSigningEvents' -Type 1
		$eventParameters = @{ LogName = 'Directory Service'; FilterXPath = $xPath; ErrorAction = 'Stop' }
		if ($Script:IsRemoteTarget) {
			$eventParameters.ComputerName = $ComputerName
		}
		return Get-WinEvent @eventParameters
	} catch {
		$errorMessage = $_.Exception.Message
		if ($Script:IsRemoteTarget -and $errorMessage -match '(?i)RPC server is unavailable|network path was not found|target computer.*unreachable|access is denied') {
			Write-Log -Message "Remote connection to '$ComputerName' failed while reading Directory Service events. Error: $errorMessage" -Component 'Get-LdapSigningEvents' -Type 3
		} else {
			Write-Log -Message "Could not read Directory Service events. $errorMessage" -Component 'Get-LdapSigningEvents' -Type 2
		}
		return @()
	}
}

function Get-LdapEventDetailValue {
	param(
		[string]$Message,
		[string[]]$Patterns
	)

	foreach ($pattern in $Patterns) {
		$match = [regex]::Match($Message, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
		if ($match.Success) {
			return $match.Groups['value'].Value.Trim()
		}
	}

	return 'Unknown'
}

function Get-LdapPropertyValue {
	param(
		[object]$LdapRecord,
		[int]$Index
	)

	if ($null -eq $LdapRecord -or $null -eq $LdapRecord.Properties) {
		return 'Unknown'
	}

	if ($Index -lt 0 -or $Index -ge $LdapRecord.Properties.Count) {
		return 'Unknown'
	}

	$value = $LdapRecord.Properties[$Index].Value
	if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
		return 'Unknown'
	}

	return ([string]$value).Trim()
}

function ConvertTo-LdapSigningFinding {
	param(
		[object]$LdapRecord
	)

	$eventName = Get-LdapSigningEventName -EventId $LdapRecord.Id
	$message = [string]$LdapRecord.Message
	$sourceFromProperties = 'Unknown'
	$accountFromProperties = 'Unknown'
	$bindingTypeFromProperties = 'Unknown'

	if ($LdapRecord.Id -eq 2889) {
		# EventID 2889 includes structured payload values in a stable order across localized message text.
		$sourceFromProperties = Get-LdapPropertyValue -LdapRecord $LdapRecord -Index 0
		$accountFromProperties = Get-LdapPropertyValue -LdapRecord $LdapRecord -Index 1
		$bindingTypeFromProperties = Get-LdapPropertyValue -LdapRecord $LdapRecord -Index 2
	}

	$sourcePatterns = @(
		'Client IP address:\s*(?<value>[^\r\n]+)',
		'Client-IP-Adresse:\s*(?<value>[^\r\n]+)',
		'Source(?:\s+IP)?(?:\s+Address)?:\s*(?<value>[^\r\n]+)',
		'Client:\s*(?<value>[^\r\n]+)'
	)
	$accountPatterns = @(
		'Identity\s+the\s+client\s+attempted\s+to\s+authenticate\s+as:\s*(?<value>[^\r\n]+)',
		'Identit[aä]t[^:]*:\s*(?<value>[^\r\n]+)',
		'Account\s+Name:\s*(?<value>[^\r\n]+)',
		'User(?:\s+Name)?:\s*(?<value>[^\r\n]+)'
	)
	$bindingTypePatterns = @(
		'Binding\s+Type:\s*(?<value>[^\r\n]+)',
		'Bindungstyp:\s*(?<value>[^\r\n]+)'
	)

	$source = if ($sourceFromProperties -ne 'Unknown') {
		$sourceFromProperties
	} else {
		Get-LdapEventDetailValue -Message $message -Patterns $sourcePatterns
	}
	$account = if ($accountFromProperties -ne 'Unknown') {
		$accountFromProperties
	} else {
		Get-LdapEventDetailValue -Message $message -Patterns $accountPatterns
	}
	$bindingType = if ($bindingTypeFromProperties -ne 'Unknown') {
		$bindingTypeFromProperties
	} else {
		Get-LdapEventDetailValue -Message $message -Patterns $bindingTypePatterns
	}

	$isUnsignedOrFailing = $LdapRecord.Id -in @(2886, 2887, 2888, 2889, 3039, 3040, 3041, 3074, 3075)

	return [PSCustomObject]@{
		TimeCreated         = $LdapRecord.TimeCreated
		EventId             = [string]$LdapRecord.Id
		EventName           = $eventName
		Source              = if ($source -eq 'Unknown') { $LdapRecord.MachineName } else { $source }
		Account             = $account
		BindingType         = $bindingType
		IsUnsignedOrFailing = $isUnsignedOrFailing
		Message             = $message
	}
}

function Show-LdapSigningFindings {
	param(
		[array]$Findings
	)

	$gridData = $Findings | Select-Object TimeCreated, EventId, EventName, Source, Account, BindingType, Message

	if (Get-Command -Name Out-GridView -ErrorAction SilentlyContinue) {
		$gridData | Out-GridView -Title 'LDAP Signing Analyzer - Unsigned or Failing LDAP Requests'
		Write-Log -Message "Displayed $($gridData.Count) finding(s) in Out-GridView." -Component 'Show-LdapSigningFindings' -Type 1
	} else {
		Write-Log -Message 'Out-GridView is unavailable. Output is written to the console.' -Component 'Show-LdapSigningFindings' -Type 2
		$gridData | Format-Table -AutoSize
	}
}

Test-PowerShell7Requirement
Initialize-Script

try {
	Write-Log -Message 'Starting LDAP signing analysis.' -Component 'Main' -Type 1

	$auditStatus = Test-LdapSigningAuditConfiguration
	Write-Log -Message ("Audit status: IsDomainController={0}; DirectoryServiceAuditPolicy={1}; LdapInterfaceEventsLevel={2}" -f $auditStatus.IsDomainController, $auditStatus.DirectoryServiceAuditPolicy, $auditStatus.LdapInterfaceEventsLevel) -Component 'Main' -Type 1

	$events = Get-LdapSigningEvents
	if (-not $events -or $events.Count -eq 0) {
		Write-Log -Message 'No supported LDAP signing or channel binding events were returned from the Directory Service log.' -Component 'Main' -Type 2
		exit 0
	}

	$findings = $events |
		ForEach-Object { ConvertTo-LdapSigningFinding -LdapRecord $_ } |
		Where-Object { $_.IsUnsignedOrFailing }

	if (-not $findings -or $findings.Count -eq 0) {
		Write-Log -Message 'No unsigned or failing LDAP request events were found.' -Component 'Main' -Type 1
		exit 0
	}

	Show-LdapSigningFindings -Findings $findings
	Write-Log -Message 'LDAP signing analysis completed successfully.' -Component 'Main' -Type 1
} catch {
	Write-Log -Message "Unexpected error: $($_.Exception.Message)" -Component 'Main' -Type 3
	exit 1
}

exit 0
