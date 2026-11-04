<#
.SYNOPSIS
Analyzes LDAP signing related Directory Service events on one or more domain controllers and shows unsigned or failing LDAP requests.

.DESCRIPTION
Collects LDAP signing and LDAP channel binding events using Get-WinEvent with an XPath filter from each target domain controller
and presents findings in Out-GridView. When no domain controller is specified, the script autodetects all domain controllers of
the current domain through Active Directory, uses the DNS SRV record _ldap._tcp.dc._msdcs.<domain> as fallback, and queries each
detected domain controller. Domain controllers that cannot be queried are logged and the remaining domain controllers are still
processed. The script includes the reporting domain controller, event id, event name, source, and account information when available.

.PARAMETER LogPath
Specifies the log directory path. The default value is the script folder.

.PARAMETER LogFile
Specifies the log file name. If omitted, a file name is generated automatically using the script name
and an ISO 8601 24-hour timestamp.

.PARAMETER ComputerName
Specifies one or more domain controllers whose Directory Service log should be queried. Accepts an array of names or a
comma-separated list. When omitted, all domain controllers of the current domain are autodetected and queried.
For the local computer, LDAP signing audit prerequisites are checked and configured. For remote domain controllers,
registry and audit policy checks are skipped and assumed to be configured correctly.

.EXAMPLE
.\LDAPSigningAnalyzer.ps1
Autodetects all domain controllers of the current domain and queries each of them.

.EXAMPLE
.\LDAPSigningAnalyzer.ps1 -ComputerName DC01, DC02.contoso.com
Queries the Directory Service log of the domain controllers DC01 and DC02.contoso.com.

.EXAMPLE
pwsh.exe -File .\LDAPSigningAnalyzer.ps1 -ComputerName "DC01,DC02"
Queries DC01 and DC02. The comma-separated list is split into individual domain controller names.

.NOTES
Version: 0.2
Author: Martin Himken
Original script name: LDAPSigningAnalyzer.ps1
Initial creation date: 2026-07-22
Last change: 2026-11-04
Changes: ComputerName accepts multiple domain controllers. All domain controllers of the current domain are autodetected and queried when no ComputerName is provided.
#>

[CmdletBinding()]
param(
	[string]$LogPath = $PSScriptRoot,
	[string]$LogFile = $null,
	[string[]]$ComputerName
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
	$Script:LocalComputerNames = @(Get-LocalComputerName)
}

function Get-LocalComputerName {
	$localNames = @('.', 'localhost', '127.0.0.1', '::1', $env:COMPUTERNAME)

	try {
		$ipGlobalProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
		$localNames += $ipGlobalProperties.HostName
		if ($ipGlobalProperties.DomainName) {
			$localNames += "$($ipGlobalProperties.HostName).$($ipGlobalProperties.DomainName)"
		}
	} catch {
		Write-Log -Message "Could not read the local DNS host name. $($_.Exception.Message)" -Component 'Get-LocalComputerName' -Type 2
	}

	return $localNames | Where-Object { $_ } | Sort-Object -Unique
}

function Get-LdapSigningDomainController {
	$domainControllerNames = [System.Collections.Generic.List[string]]::new()

	try {
		$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		try {
			foreach ($domainController in $currentDomain.DomainControllers) {
				if ($domainController.Name) {
					$domainControllerNames.Add($domainController.Name)
				}
			}
			Write-Log -Message "Active Directory returned $($domainControllerNames.Count) domain controller(s) for domain '$($currentDomain.Name)'." -Component 'Get-LdapSigningDomainController' -Type 1
		} finally {
			$currentDomain.Dispose()
		}
	} catch {
		Write-Log -Message "Domain controller discovery through Active Directory failed. $($_.Exception.Message)" -Component 'Get-LdapSigningDomainController' -Type 2
	}

	if ($domainControllerNames.Count -eq 0) {
		$domainName = $env:USERDNSDOMAIN
		if (-not $domainName) {
			try {
				$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
				if ($computerSystem.PartOfDomain) {
					$domainName = $computerSystem.Domain
				}
			} catch {
				Write-Log -Message "Could not determine the domain of the local computer. $($_.Exception.Message)" -Component 'Get-LdapSigningDomainController' -Type 2
			}
		}

		if ($domainName) {
			$srvRecordName = "_ldap._tcp.dc._msdcs.$domainName"
			try {
				$srvRecords = @(Resolve-DnsName -Name $srvRecordName -Type SRV -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget })
				foreach ($srvRecord in $srvRecords) {
					$domainControllerNames.Add($srvRecord.NameTarget.TrimEnd('.'))
				}
				Write-Log -Message "DNS SRV record '$srvRecordName' returned $($srvRecords.Count) domain controller(s)." -Component 'Get-LdapSigningDomainController' -Type 1
			} catch {
				Write-Log -Message "Domain controller discovery through DNS SRV record '$srvRecordName' failed. $($_.Exception.Message)" -Component 'Get-LdapSigningDomainController' -Type 2
			}
		} else {
			Write-Log -Message 'The current user and the local computer are not associated with an Active Directory domain. DNS SRV discovery is skipped.' -Component 'Get-LdapSigningDomainController' -Type 2
		}
	}

	return $domainControllerNames | Sort-Object -Unique
}

function Resolve-LdapSigningTarget {
	param(
		[string[]]$RequestedComputerName
	)

	# Split entries such as "DC01,DC02", which arrive as one string when the script is started with pwsh.exe -File.
	$candidateNames = @(
		foreach ($requestedName in $RequestedComputerName) {
			$requestedName -split '[,;\s]+' | Where-Object { $_ }
		}
	)

	if ($candidateNames.Count -eq 0) {
		Write-Log -Message 'No domain controller was specified. Starting domain controller autodetection.' -Component 'Resolve-LdapSigningTarget' -Type 1
		$candidateNames = @(Get-LdapSigningDomainController)
	}

	$targetList = [System.Collections.Generic.List[object]]::new()
	$processedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
	$hasLocalTarget = $false

	foreach ($candidateName in $candidateNames) {
		if (-not $processedNames.Add($candidateName)) {
			continue
		}

		$isLocalTarget = $candidateName -in $Script:LocalComputerNames
		if ($isLocalTarget -and $hasLocalTarget) {
			Write-Log -Message "Target '$candidateName' refers to the local computer, which is already included. The entry is skipped." -Component 'Resolve-LdapSigningTarget' -Type 1
			continue
		}

		$hasLocalTarget = $hasLocalTarget -or $isLocalTarget
		$targetList.Add([PSCustomObject]@{
				ComputerName = $candidateName
				IsLocal      = $isLocalTarget
			})
	}

	return $targetList
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
	param(
		[string]$TargetComputerName,
		[bool]$IsLocalTarget
	)

	$result = [PSCustomObject]@{
		IsDomainController          = 'NotChecked'
		DirectoryServiceAuditPolicy = 'NotChecked'
		LdapInterfaceEventsLevel    = 'NotChecked'
	}

	if (-not $IsLocalTarget) {
		$result.DirectoryServiceAuditPolicy = 'AssumedConfiguredForRemoteTarget'
		$result.LdapInterfaceEventsLevel = 'AssumedConfiguredForRemoteTarget'
		Write-Log -Message "Remote target '$TargetComputerName' specified. Registry and audit policy checks are skipped and assumed to be configured correctly." -Component 'AuditCheck' -Type 2
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
	param(
		[string]$TargetComputerName,
		[bool]$IsLocalTarget
	)

	$xPath = "*[System[Provider[@Name='Microsoft-Windows-ActiveDirectory_DomainService'] and (EventID=2886 or EventID=2887 or EventID=2888 or EventID=2889 or EventID=3039 or EventID=3040 or EventID=3041 or EventID=3074 or EventID=3075)]]"
	$queryResult = [PSCustomObject]@{
		ComputerName = $TargetComputerName
		Succeeded    = $false
		Events       = @()
	}

	try {
		Write-Log -Message "Reading Directory Service log on '$TargetComputerName' with XPath: $xPath" -Component 'Get-LdapSigningEvents' -Type 1
		$eventParameters = @{ LogName = 'Directory Service'; FilterXPath = $xPath; ErrorAction = 'Stop' }
		if (-not $IsLocalTarget) {
			$eventParameters.ComputerName = $TargetComputerName
		}
		$queryResult.Events = @(Get-WinEvent @eventParameters)
		$queryResult.Succeeded = $true
		Write-Log -Message "Read $($queryResult.Events.Count) supported LDAP signing or channel binding event(s) from '$TargetComputerName'." -Component 'Get-LdapSigningEvents' -Type 1
	} catch {
		$errorMessage = $_.Exception.Message
		if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
			$queryResult.Succeeded = $true
			Write-Log -Message "No supported LDAP signing or channel binding events were found on '$TargetComputerName'." -Component 'Get-LdapSigningEvents' -Type 1
		} elseif (-not $IsLocalTarget -and $errorMessage -match '(?i)RPC server is unavailable|network path was not found|target computer.*unreachable|access is denied') {
			Write-Log -Message "Remote connection to '$TargetComputerName' failed while reading Directory Service events. Error: $errorMessage" -Component 'Get-LdapSigningEvents' -Type 3
		} else {
			Write-Log -Message "Could not read Directory Service events on '$TargetComputerName'. $errorMessage" -Component 'Get-LdapSigningEvents' -Type 2
		}
	}

	return $queryResult
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
		DomainController    = $LdapRecord.MachineName
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

	$gridData = $Findings | Select-Object TimeCreated, DomainController, EventId, EventName, Source, Account, BindingType, Message

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

	$targetComputers = @(Resolve-LdapSigningTarget -RequestedComputerName $ComputerName)
	if ($targetComputers.Count -eq 0) {
		Write-Log -Message 'No domain controllers were specified or detected. Specify one or more domain controllers with the ComputerName parameter.' -Component 'Main' -Type 3
		exit 1
	}
	Write-Log -Message "Querying $($targetComputers.Count) domain controller(s): $($targetComputers.ComputerName -join ', ')" -Component 'Main' -Type 1

	$events = [System.Collections.Generic.List[object]]::new()
	$failedTargets = [System.Collections.Generic.List[string]]::new()
	foreach ($targetComputer in $targetComputers) {
		$auditStatus = Test-LdapSigningAuditConfiguration -TargetComputerName $targetComputer.ComputerName -IsLocalTarget $targetComputer.IsLocal
		Write-Log -Message ("Audit status for '{0}': IsDomainController={1}; DirectoryServiceAuditPolicy={2}; LdapInterfaceEventsLevel={3}" -f $targetComputer.ComputerName, $auditStatus.IsDomainController, $auditStatus.DirectoryServiceAuditPolicy, $auditStatus.LdapInterfaceEventsLevel) -Component 'Main' -Type 1

		$queryResult = Get-LdapSigningEvents -TargetComputerName $targetComputer.ComputerName -IsLocalTarget $targetComputer.IsLocal
		if ($queryResult.Succeeded) {
			foreach ($ldapRecord in $queryResult.Events) {
				$events.Add($ldapRecord)
			}
		} else {
			$failedTargets.Add($targetComputer.ComputerName)
		}
	}

	Write-Log -Message "Queried $($targetComputers.Count) domain controller(s). Succeeded: $($targetComputers.Count - $failedTargets.Count). Failed: $($failedTargets.Count)." -Component 'Main' -Type 1
	if ($failedTargets.Count -gt 0) {
		Write-Log -Message "Domain controllers that could not be queried: $($failedTargets -join ', ')" -Component 'Main' -Type 2
	}
	if ($failedTargets.Count -eq $targetComputers.Count) {
		Write-Log -Message 'Directory Service events could not be read from any domain controller.' -Component 'Main' -Type 3
		exit 1
	}

	if ($events.Count -eq 0) {
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
