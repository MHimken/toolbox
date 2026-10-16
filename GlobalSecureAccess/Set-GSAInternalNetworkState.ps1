<#
.SYNOPSIS
Controls Global Secure Access services according to reverse-DNS network detection.

.DESCRIPTION
Windows PowerShell 5.1 script that evaluates whether a configured IP address
resolves to an expected PTR hostname. It stops the four Global Secure Access
services on the internal network and starts them otherwise. Install mode stages
the script and configuration under ProgramData and registers one SYSTEM task for
NetworkProfile event 4004 plus system startup. Evaluate mode also coalesces
events that arrive during service transitions. Uninstall mode removes the owned
task and configuration and attempts to start all managed services.

This script intentionally targets Windows PowerShell 5.1 because PowerShell 7
cannot be assumed on target devices. It remains compatible with PowerShell 7.
Run from 64-bit PowerShell as an administrator for manual operation. The
scheduled task runs as SYSTEM.

.PARAMETER Mode
Operation to perform: Install, Evaluate, or Uninstall. Defaults to Evaluate.

.PARAMETER TargetIPAddress
IP address whose PTR record identifies the internal network. Required for
Install; optional for Evaluate when stored configuration is available.

.PARAMETER ExpectedDnsName
Expected PTR hostname. Matching is exact and case-insensitive. Required for
Install; optional for Evaluate when stored configuration is available.

.PARAMETER DnsServer
Optional DNS server IP address. When omitted, queries are sent directly to the
DNS servers configured on connected network interfaces.

.PARAMETER TaskName
Scheduled task name. Defaults to GlobalSecureAccess-NetworkChange.

.PARAMETER LogPath
Directory for log files. Defaults to the current directory. The scheduled task
uses the protected ProgramData Logs directory.

.PARAMETER LogFile
Optional log filename, without a directory path. When omitted, a timestamped
filename is generated.

.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Set-GSAInternalNetworkState.ps1
Initial creation date: 2026-10-16
Last change: 2026-10-16
Changes: Initial implementation of event-triggered GSA service control.

Exit codes:
0  Operation completed and services converged to the requested state.
1  Invalid configuration, missing prerequisite, or operation failure.
2  Another evaluation already holds the machine-wide mutex.

Detection uses direct DNS server queries to avoid the local DNS client cache.
DNS servers may still have cached records. A DNS failure after bounded retries
is treated as unknown; the script logs the condition and starts GSA services.
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Evaluate', 'Uninstall')]
    [string]$Mode = 'Evaluate',

    [string]$TargetIPAddress,

    [string]$ExpectedDnsName,

    [string]$DnsServer,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')]
    [string]$TaskName = 'GlobalSecureAccess-NetworkChange',

    [string]$LogPath = (Get-Location).Path,

    [string]$LogFile = $null
)

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    Write-Error 'Windows PowerShell 5.1 or later is required.'
    exit 1
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Error 'Run this script in 64-bit PowerShell (System32\WindowsPowerShell\v1.0\powershell.exe).'
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
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Set-GSAInternalNetworkState'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not $LogFile) {
        $LogFile = '{0}_{1}.log' -f $SanitizedScriptName, $Script:DateTime
    }
    if ([System.IO.Path]::GetFileName($LogFile) -ne $LogFile) {
        throw 'LogFile must be a filename without a directory path.'
    }
    if (-not (Test-Path -LiteralPath $LogPath -PathType Container)) {
        New-Item -Path $LogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:ToConsole = $false
    $Script:NoOutput = $false
}

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($Identity.User.Value -eq 'S-1-5-18') {
        return $true
    }
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DeploymentPaths {
    $BasePath = Join-Path -Path $env:ProgramData -ChildPath 'GlobalSecureAccess\NetworkControl'
    return [pscustomobject]@{
        BasePath   = $BasePath
        ScriptPath = Join-Path -Path $BasePath -ChildPath 'Set-GSAInternalNetworkState.ps1'
        ConfigPath = Join-Path -Path $BasePath -ChildPath 'Configuration.json'
        LogPath    = Join-Path -Path $BasePath -ChildPath 'Logs'
    }
}

function Set-ProtectedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $DirectoryAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $DirectoryAcl.SetAccessRuleProtection($true, $false)
    $DirectoryAcl.Access | ForEach-Object { [void]$DirectoryAcl.RemoveAccessRuleAll($_) }
    $SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $Inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $Propagation = [Security.AccessControl.PropagationFlags]::None
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemSid, $FullControl, $Inheritance, $Propagation, $Allow)))
    $DirectoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdministratorsSid, $FullControl, $Inheritance, $Propagation, $Allow)))
    Set-Acl -LiteralPath $Path -AclObject $DirectoryAcl -ErrorAction Stop
}

function Set-ProtectedFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $FileAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $FileAcl.SetAccessRuleProtection($true, $false)
    $FileAcl.Access | ForEach-Object { [void]$FileAcl.RemoveAccessRuleAll($_) }
    $SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemSid, $FullControl, $Allow)))
    $FileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($AdministratorsSid, $FullControl, $Allow)))
    Set-Acl -LiteralPath $Path -AclObject $FileAcl -ErrorAction Stop
}

function Assert-Configuration {
    param(
        [Parameter(Mandatory = $true)][string]$IPAddress,
        [Parameter(Mandatory = $true)][string]$DnsName,
        [string]$Resolver
    )

    $ParsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ParsedAddress)) {
        throw "TargetIPAddress is not a valid IP address: $IPAddress"
    }
    if ([string]::IsNullOrWhiteSpace($DnsName) -or $DnsName.Length -gt 253) {
        throw 'ExpectedDnsName must be a valid DNS hostname.'
    }
    $NormalizedDnsName = $DnsName.TrimEnd('.')
    if ($NormalizedDnsName -notmatch '^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$') {
        throw "ExpectedDnsName is not a valid DNS hostname: $DnsName"
    }
    if ($Resolver) {
        $ParsedResolver = $null
        if (-not [System.Net.IPAddress]::TryParse($Resolver, [ref]$ParsedResolver)) {
            throw "DnsServer is not a valid IP address: $Resolver"
        }
    }
    return [pscustomobject]@{
        TargetIPAddress = $ParsedAddress.ToString()
        ExpectedDnsName = $NormalizedDnsName
        DnsServer       = $Resolver
    }
}

function Get-DnsServerAddresses {
    param([string]$Resolver)

    if ($Resolver) {
        return @($Resolver)
    }
    $ConnectedInterfaces = @(Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.ConnectionState -eq 'Connected' } | Select-Object -ExpandProperty InterfaceIndex -Unique)
    $ResolverList = @()
    foreach ($InterfaceIndex in $ConnectedInterfaces) {
        $AddressFamilies = @('IPv4', 'IPv6')
        foreach ($AddressFamily in $AddressFamilies) {
            $DnsSettings = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily $AddressFamily -ErrorAction SilentlyContinue
            foreach ($DnsAddress in $DnsSettings.ServerAddresses) {
                if ($DnsAddress -and $ResolverList -notcontains $DnsAddress) {
                    $ResolverList += $DnsAddress
                }
            }
        }
    }
    return $ResolverList
}

function Resolve-InternalNetwork {
    param(
        [Parameter(Mandatory = $true)][string]$IPAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [string]$Resolver
    )

    try {
        $ResolverAddresses = @(Get-DnsServerAddresses -Resolver $Resolver)
    } catch {
        return [pscustomobject]@{ State = 'Unknown'; Answers = @(); Detail = ('Failed to enumerate DNS servers: ' + $_.Exception.Message) }
    }
    if ($ResolverAddresses.Count -eq 0) {
        return [pscustomobject]@{ State = 'Unknown'; Answers = @(); Detail = 'No DNS servers are configured on connected interfaces.' }
    }

    $AnswerNames = @()
    $QueryFailures = @()
    $SuccessfulQueries = 0
    foreach ($ResolverAddress in $ResolverAddresses) {
        $ResolveParameters = @{
            Name          = $IPAddress
            Type          = 'PTR'
            Server        = $ResolverAddress
            DnsOnly       = $true
            NoHostsFile   = $true
            QuickTimeout  = $true
            ErrorAction   = 'Stop'
        }
        try {
            $PtrRecords = @(Resolve-DnsName @ResolveParameters | Where-Object { $_.Type -eq 'PTR' })
            $SuccessfulQueries++
            foreach ($PtrRecord in $PtrRecords) {
                $AnswerNames += $PtrRecord.NameHost.TrimEnd('.')
            }
        } catch {
            $ErrorText = '{0} {1}' -f $_.FullyQualifiedErrorId, $_.Exception.Message
            if ($ErrorText -match 'DNS_ERROR_RCODE_NAME_ERROR|DNS_ERROR_RCODE_NXRRSET|DNS_ERROR_RCODE_NODATA|DNS name does not exist|name does not exist|NXDOMAIN|no records') {
                $SuccessfulQueries++
            } else {
                $QueryFailures += ('{0}: {1}' -f $ResolverAddress, $_.Exception.Message)
            }
        }
    }

    $MatchingAnswers = @($AnswerNames | Where-Object { $_.Equals($ExpectedName, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -Unique)
    if ($MatchingAnswers.Count -gt 0) {
        return [pscustomobject]@{ State = 'Internal'; Answers = @($AnswerNames | Select-Object -Unique); Detail = 'Expected PTR hostname returned.' }
    }
    if ($QueryFailures.Count -gt 0 -and $SuccessfulQueries -eq 0) {
        return [pscustomobject]@{ State = 'Unknown'; Answers = @($AnswerNames | Select-Object -Unique); Detail = ($QueryFailures -join '; ') }
    }
    if ($QueryFailures.Count -gt 0) {
        return [pscustomobject]@{ State = 'Unknown'; Answers = @($AnswerNames | Select-Object -Unique); Detail = ('Some DNS servers did not respond: ' + ($QueryFailures -join '; ')) }
    }
    return [pscustomobject]@{ State = 'External'; Answers = @($AnswerNames | Select-Object -Unique); Detail = 'No DNS server returned the expected PTR hostname.' }
}

function Get-LatestNetworkChangeRecordId {
    $LatestEvent = Get-WinEvent -FilterHashtable @{
        LogName      = 'Microsoft-Windows-NetworkProfile/Operational'
        ProviderName = 'NetworkProfile'
        Id           = 4004
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($LatestEvent) {
        return [long]$LatestEvent.RecordId
    }
    return [long]0
}

function Get-OrderedManagedServices {
    param(
        [Parameter(Mandatory = $true)][string[]]$ServiceNames,
        [bool]$CheckExternalDependents = $true
    )

    $ManagedNames = @{}
    foreach ($ServiceName in $ServiceNames) { $ManagedNames[$ServiceName] = $true }
    $VisitedNames = @{}
    $OrderedNames = New-Object System.Collections.Generic.List[string]
    foreach ($ServiceName in $ServiceNames) {
        $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
        foreach ($DependentService in $ServiceInfo.DependentServices) {
            if ($CheckExternalDependents -and -not $ManagedNames.ContainsKey($DependentService.Name) -and $DependentService.Status -ne 'Stopped') {
                throw "Cannot control $ServiceName while unmanaged dependent service $($DependentService.Name) is running."
            }
        }
    }
    foreach ($ServiceName in $ServiceNames) {
        Add-ManagedDependentsToOrder -ServiceName $ServiceName -ManagedNames $ManagedNames -VisitedNames $VisitedNames -OrderedNames $OrderedNames
    }
    $FinalOrder = @($OrderedNames)
    if ($ManagedNames.ContainsKey('GlobalSecureAccessEngineService') -and $ManagedNames.ContainsKey('GlobalSecureAccessTunnelingService')) {
        $EnginePosition = [array]::IndexOf($FinalOrder, 'GlobalSecureAccessEngineService')
        $TunnelingPosition = [array]::IndexOf($FinalOrder, 'GlobalSecureAccessTunnelingService')
        if ($EnginePosition -ge $TunnelingPosition) {
            throw 'Computed stop order violates the confirmed dependency: Engine must stop before Tunneling.'
        }
    }
    return $FinalOrder
}

function Add-ManagedDependentsToOrder {
    param(
        [string]$ServiceName,
        [hashtable]$ManagedNames,
        [hashtable]$VisitedNames,
        [System.Collections.Generic.List[string]]$OrderedNames
    )

    if ($VisitedNames.ContainsKey($ServiceName)) { return }
    $VisitedNames[$ServiceName] = $true
    $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
    foreach ($DependentService in $ServiceInfo.DependentServices) {
        if ($ManagedNames.ContainsKey($DependentService.Name)) {
            Add-ManagedDependentsToOrder -ServiceName $DependentService.Name -ManagedNames $ManagedNames -VisitedNames $VisitedNames -OrderedNames $OrderedNames
        }
    }
    $OrderedNames.Add($ServiceName)
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][ValidateSet('Running', 'Stopped')][string]$DesiredState,
        [int]$TimeoutSeconds = 45
    )

    $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($ServiceInfo.Status -eq $DesiredState) { return }
    if ($DesiredState -eq 'Stopped') {
        if ($ServiceInfo.Status -eq 'StopPending') {
            $ServiceInfo.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
            return
        }
        if ($ServiceInfo.Status -eq 'StartPending') {
            $ServiceInfo.WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSeconds))
            $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
        }
        if ($ServiceInfo.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
        }
    } else {
        if ($ServiceInfo.Status -eq 'StartPending') {
            $ServiceInfo.WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSeconds))
            return
        }
        if ($ServiceInfo.Status -eq 'StopPending') {
            $ServiceInfo.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
        }
        $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($ServiceInfo.Status -ne 'Running') {
            Start-Service -Name $ServiceName -ErrorAction Stop
            (Get-Service -Name $ServiceName -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSeconds))
        }
    }
}

function Set-ManagedServicesState {
    param([Parameter(Mandatory = $true)][ValidateSet('Running', 'Stopped')][string]$DesiredState)

    $ManagedServiceNames = @(
        'GlobalSecureAccessClientManagerService'
        'GlobalSecureAccessEngineService'
        'GlobalSecureAccessForwardingProfileService'
        'GlobalSecureAccessTunnelingService'
    )
    foreach ($ManagedServiceName in $ManagedServiceNames) {
        [void](Get-Service -Name $ManagedServiceName -ErrorAction Stop)
    }
    $StopOrder = @(Get-OrderedManagedServices -ServiceNames $ManagedServiceNames -CheckExternalDependents ($DesiredState -eq 'Stopped'))
    [string[]]$OperationOrder = @($StopOrder)
    if ($DesiredState -eq 'Running') {
        [array]::Reverse($OperationOrder)
    }
    $TransitionErrors = @()
    foreach ($ManagedServiceName in $OperationOrder) {
        try {
            Write-Log -Message "Setting service $ManagedServiceName to $DesiredState." -Component 'ServiceControl' -Type 1
            Wait-ServiceState -ServiceName $ManagedServiceName -DesiredState $DesiredState
        } catch {
            $TransitionErrors += ('{0}: {1}' -f $ManagedServiceName, $_.Exception.Message)
            Write-Log -Message "Service transition failed for $ManagedServiceName. $($_.Exception.Message)" -Component 'ServiceControl' -Type 3
            if ($DesiredState -eq 'Stopped') { break }
        }
    }
    if ($TransitionErrors.Count -gt 0 -and $DesiredState -eq 'Stopped') {
        Write-Log -Message 'Attempting to restore all GSA services to Running after the failed stop sequence.' -Component 'ServiceControl' -Type 2
        [string[]]$RecoveryOrder = @($StopOrder)
        [array]::Reverse($RecoveryOrder)
        foreach ($ManagedServiceName in $RecoveryOrder) {
            try {
                Wait-ServiceState -ServiceName $ManagedServiceName -DesiredState 'Running'
            } catch {
                $TransitionErrors += ('Recovery {0}: {1}' -f $ManagedServiceName, $_.Exception.Message)
            }
        }
    }
    Start-Sleep -Seconds 3
    foreach ($ManagedServiceName in $ManagedServiceNames) {
        $ActualService = Get-Service -Name $ManagedServiceName -ErrorAction Stop
        if ($ActualService.Status -ne $DesiredState) {
            $TransitionErrors += ('{0} is {1}; expected {2}.' -f $ManagedServiceName, $ActualService.Status, $DesiredState)
        }
    }
    if ($TransitionErrors.Count -gt 0) {
        throw ('Service state convergence failed: ' + ($TransitionErrors -join ' | '))
    }
    Write-Log -Message "All managed GSA services are $DesiredState." -Component 'ServiceControl' -Type 1
}

function Assert-Prerequisites {
    $RequiredCommands = @('Resolve-DnsName', 'Get-DnsClientServerAddress', 'Get-NetIPInterface', 'Get-WinEvent', 'Get-ScheduledTask', 'Register-ScheduledTask')
    foreach ($CommandName in $RequiredCommands) {
        if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
            throw "Required command is unavailable: $CommandName"
        }
    }
    $EventLog = Get-WinEvent -ListLog 'Microsoft-Windows-NetworkProfile/Operational' -ErrorAction Stop
    if (-not $EventLog.IsEnabled) {
        throw 'The Microsoft-Windows-NetworkProfile/Operational event log is disabled.'
    }
}

function New-NetworkChangeTaskXml {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Paths,
        [Parameter(Mandatory = $true)][string]$RegisteredTaskName
    )

    $PowerShellPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $TaskArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Evaluate -TaskName {1} -LogPath "{2}"' -f $Paths.ScriptPath, $RegisteredTaskName, $Paths.LogPath
    $EscapedExecutable = [System.Security.SecurityElement]::Escape($PowerShellPath)
    $EscapedArguments = [System.Security.SecurityElement]::Escape($TaskArguments)
    $EventSubscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[Provider[@Name=''NetworkProfile''] and EventID=4004]]</Select></Query></QueryList>'
    $EscapedSubscription = [System.Security.SecurityElement]::Escape($EventSubscription)
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Global Secure Access network state controller</Author><Description>Controls GSA services after NetworkProfile event 4004.</Description></RegistrationInfo>
  <Triggers>
    <EventTrigger><Enabled>true</Enabled><Subscription>$EscapedSubscription</Subscription></EventTrigger>
    <BootTrigger><Enabled>true</Enabled><Delay>PT15S</Delay></BootTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>SYSTEM</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>$EscapedExecutable</Command><Arguments>$EscapedArguments</Arguments><WorkingDirectory>$([System.Security.SecurityElement]::Escape($Paths.BasePath))</WorkingDirectory></Exec></Actions>
</Task>
"@
}

function Test-OwnedNetworkChangeTask {
    param([Parameter(Mandatory = $true)][string]$RegisteredTaskName)

    $ExistingTask = Get-ScheduledTask -TaskName $RegisteredTaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if (-not $ExistingTask) { return $false }
    [xml]$ExistingTaskXml = Export-ScheduledTask -TaskName $RegisteredTaskName -TaskPath '\' -ErrorAction Stop
    $TaskNamespaceManager = New-Object System.Xml.XmlNamespaceManager($ExistingTaskXml.NameTable)
    $TaskNamespaceManager.AddNamespace('task', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $TaskAuthor = $ExistingTaskXml.SelectSingleNode('//task:RegistrationInfo/task:Author', $TaskNamespaceManager)
    $TaskCommand = $ExistingTaskXml.SelectSingleNode('//task:Actions/task:Exec/task:Command', $TaskNamespaceManager)
    $TaskArguments = $ExistingTaskXml.SelectSingleNode('//task:Actions/task:Exec/task:Arguments', $TaskNamespaceManager)
    $ExpectedScriptPath = (Get-DeploymentPaths).ScriptPath
    $ExpectedPowerShellPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    return ($TaskAuthor -and
        $TaskAuthor.InnerText -eq 'Global Secure Access network state controller' -and
        $TaskCommand -and
        $TaskCommand.InnerText.Equals($ExpectedPowerShellPath, [StringComparison]::OrdinalIgnoreCase) -and
        $TaskArguments -and
        $TaskArguments.InnerText.Contains($ExpectedScriptPath))
}

function Install-NetworkChangeTask {
    param([Parameter(Mandatory = $true)][pscustomobject]$Configuration)

    if (-not (Test-IsAdministrator)) {
        throw 'Install mode requires an elevated administrator session.'
    }
    Assert-Prerequisites
    if (-not (Get-Command -Name 'Export-ScheduledTask' -ErrorAction SilentlyContinue)) {
        throw 'Required command is unavailable: Export-ScheduledTask'
    }
    foreach ($ManagedServiceName in @(
        'GlobalSecureAccessClientManagerService'
        'GlobalSecureAccessEngineService'
        'GlobalSecureAccessForwardingProfileService'
        'GlobalSecureAccessTunnelingService'
    )) {
        [void](Get-Service -Name $ManagedServiceName -ErrorAction Stop)
    }
    $MutexObject = Enter-NetworkStateMutex -TimeoutSeconds 1200
    try {
    if ((Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue) -and
        -not (Test-OwnedNetworkChangeTask -RegisteredTaskName $TaskName)) {
        throw "A task named $TaskName already exists and is not owned by this script."
    }
    $DeploymentPaths = Get-DeploymentPaths
    $LogDirectory = $DeploymentPaths.LogPath
    New-Item -Path $DeploymentPaths.BasePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Set-ProtectedDirectoryAcl -Path $DeploymentPaths.BasePath
    New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Set-ProtectedDirectoryAcl -Path $LogDirectory
    Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' -File -ErrorAction Stop | ForEach-Object {
        Set-ProtectedFileAcl -Path $_.FullName
    }

    $SourcePath = [System.IO.Path]::GetFullPath($PSCommandPath)
    $InstalledPath = [System.IO.Path]::GetFullPath($DeploymentPaths.ScriptPath)
    if (-not $SourcePath.Equals($InstalledPath, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $SourcePath -Destination $InstalledPath -Force -ErrorAction Stop
    }
    $TemporaryConfigPath = '{0}.tmp' -f $DeploymentPaths.ConfigPath
    $Configuration | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $TemporaryConfigPath -Encoding UTF8 -ErrorAction Stop
    Set-ProtectedFileAcl -Path $TemporaryConfigPath
    Move-Item -LiteralPath $TemporaryConfigPath -Destination $DeploymentPaths.ConfigPath -Force -ErrorAction Stop
    Set-ProtectedFileAcl -Path $DeploymentPaths.ConfigPath
    Set-ProtectedFileAcl -Path $DeploymentPaths.ScriptPath

    $TaskXml = New-NetworkChangeTaskXml -Paths $DeploymentPaths -RegisteredTaskName $TaskName
    Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Xml $TaskXml -Force -ErrorAction Stop | Out-Null
    $RegisteredTask = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
    [xml]$RegisteredTaskXml = Export-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
    $TaskNamespaceManager = New-Object System.Xml.XmlNamespaceManager($RegisteredTaskXml.NameTable)
    $TaskNamespaceManager.AddNamespace('task', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $EventTriggerNode = $RegisteredTaskXml.SelectSingleNode('//task:Triggers/task:EventTrigger/task:Subscription', $TaskNamespaceManager)
    $StartupTriggerNode = $RegisteredTaskXml.SelectSingleNode('//task:Triggers/task:BootTrigger', $TaskNamespaceManager)
    $ActionCommandNode = $RegisteredTaskXml.SelectSingleNode('//task:Actions/task:Exec/task:Command', $TaskNamespaceManager)
    $ActionArgumentsNode = $RegisteredTaskXml.SelectSingleNode('//task:Actions/task:Exec/task:Arguments', $TaskNamespaceManager)
    $ExpectedPowerShellPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($RegisteredTask.Principal.UserId -notin @('SYSTEM', 'S-1-5-18') -or
        $RegisteredTask.Settings.MultipleInstances -ne 'IgnoreNew' -or
        -not $EventTriggerNode -or
        -not $EventTriggerNode.InnerText.Contains('Microsoft-Windows-NetworkProfile/Operational') -or
        -not $EventTriggerNode.InnerText.Contains("Provider[@Name='NetworkProfile']") -or
        -not $EventTriggerNode.InnerText.Contains('EventID=4004') -or
        -not $StartupTriggerNode -or
        -not $ActionCommandNode -or
        -not $ActionArgumentsNode -or
        -not $ActionCommandNode.InnerText.Equals($ExpectedPowerShellPath, [StringComparison]::OrdinalIgnoreCase) -or
        -not $ActionArgumentsNode.InnerText.Contains($DeploymentPaths.ScriptPath) -or
        -not $RegisteredTaskXml.SelectSingleNode('//task:Settings/task:DisallowStartIfOnBatteries', $TaskNamespaceManager).InnerText.Equals('false') -or
        -not $RegisteredTaskXml.SelectSingleNode('//task:Settings/task:StopIfGoingOnBatteries', $TaskNamespaceManager).InnerText.Equals('false')) {
        throw 'The registered task definition did not match the required trigger, principal, action, and instance settings.'
    }
    foreach ($ProtectedPath in @($DeploymentPaths.BasePath, $DeploymentPaths.LogPath, $DeploymentPaths.ConfigPath, $DeploymentPaths.ScriptPath)) {
        if (-not (Get-Acl -LiteralPath $ProtectedPath -ErrorAction Stop).AreAccessRulesProtected) {
            throw "Deployment path does not have a protected access control list: $ProtectedPath"
        }
    }
    Write-Log -Message "Registered scheduled task $TaskName for NetworkProfile event 4004 and system startup." -Component 'Install' -Type 1
    } finally {
        Exit-NetworkStateMutex -MutexObject $MutexObject
    }
}

function Remove-NetworkChangeTask {
    if (-not (Test-IsAdministrator)) {
        throw 'Uninstall mode requires an elevated administrator session.'
    }
    $MutexObject = Enter-NetworkStateMutex -TimeoutSeconds 1200
    try {
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($ExistingTask) {
        if (-not (Test-OwnedNetworkChangeTask -RegisteredTaskName $TaskName)) {
            throw "Refusing to remove task $TaskName because it is not owned by this script."
        }
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
        Write-Log -Message "Removed scheduled task $TaskName." -Component 'Uninstall' -Type 1
    } else {
        Write-Log -Message "Scheduled task $TaskName was not registered." -Component 'Uninstall' -Type 2
    }
    Set-ManagedServicesState -DesiredState 'Running'
    $DeploymentPaths = Get-DeploymentPaths
    if (Test-Path -LiteralPath $DeploymentPaths.ConfigPath) {
        Remove-Item -LiteralPath $DeploymentPaths.ConfigPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $DeploymentPaths.ScriptPath) {
        Remove-Item -LiteralPath $DeploymentPaths.ScriptPath -Force -ErrorAction Stop
    }
    Write-Log -Message "Removed deployment script and configuration. Preserved logs under $($DeploymentPaths.LogPath)." -Component 'Uninstall' -Type 1
    } finally {
        Exit-NetworkStateMutex -MutexObject $MutexObject
    }
}

function Enter-NetworkStateMutex {
    param([int]$TimeoutSeconds = 0)

    $MutexName = 'Global\GlobalSecureAccessNetworkState'
    $MutexObject = [System.Threading.Mutex]::new($false, $MutexName)
    try {
        try {
            $MutexAcquired = $MutexObject.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        } catch [System.Threading.AbandonedMutexException] {
            $MutexAcquired = $true
        }
        if (-not $MutexAcquired) {
            throw "Timed out after $TimeoutSeconds seconds waiting for the network-state mutex."
        }
        return $MutexObject
    } catch {
        $MutexObject.Dispose()
        throw
    }
}

function Exit-NetworkStateMutex {
    param([Parameter(Mandatory = $true)][System.Threading.Mutex]$MutexObject)
    try {
        [void]$MutexObject.ReleaseMutex()
    } finally {
        $MutexObject.Dispose()
    }
}

function Invoke-Evaluation {
    $MutexObject = $null
    try {
        try {
            $MutexObject = Enter-NetworkStateMutex -TimeoutSeconds 0
        } catch {
            if ($_.Exception.Message -like 'Timed out after 0 seconds*') {
                Write-Log -Message 'Another network-state evaluation is active; this invocation is coalesced.' -Component 'Evaluate' -Type 2
                return 2
            }
            throw
        }
        $ConfigurationPath = (Get-DeploymentPaths).ConfigPath
        if ((-not $TargetIPAddress -or -not $ExpectedDnsName) -and (Test-Path -LiteralPath $ConfigurationPath)) {
            $StoredConfiguration = Get-Content -LiteralPath $ConfigurationPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if (-not $TargetIPAddress) { $TargetIPAddress = $StoredConfiguration.TargetIPAddress }
            if (-not $ExpectedDnsName) { $ExpectedDnsName = $StoredConfiguration.ExpectedDnsName }
            if (-not $DnsServer) { $DnsServer = $StoredConfiguration.DnsServer }
        }
        if (-not $TargetIPAddress -or -not $ExpectedDnsName) {
            throw 'Provide TargetIPAddress and ExpectedDnsName or install the scheduled task first.'
        }
        $ValidatedConfiguration = Assert-Configuration -IPAddress $TargetIPAddress -DnsName $ExpectedDnsName -Resolver $DnsServer
        Assert-Prerequisites

        $PreviousEventRecordId = Get-LatestNetworkChangeRecordId
        $MaximumPasses = 3
        for ($PassNumber = 1; $PassNumber -le $MaximumPasses; $PassNumber++) {
            if ($PassNumber -gt 1) {
                Start-Sleep -Seconds 2
            }
            $DetectionResult = $null
            for ($AttemptNumber = 1; $AttemptNumber -le 3; $AttemptNumber++) {
                $DetectionResult = Resolve-InternalNetwork -IPAddress $ValidatedConfiguration.TargetIPAddress -ExpectedName $ValidatedConfiguration.ExpectedDnsName -Resolver $ValidatedConfiguration.DnsServer
                if ($DetectionResult.State -ne 'Unknown') { break }
                if ($AttemptNumber -lt 3) { Start-Sleep -Seconds 3 }
            }
            Write-Log -Message ("Detection state={0}; PTR answers={1}; detail={2}" -f $DetectionResult.State, ($DetectionResult.Answers -join ', '), $DetectionResult.Detail) -Component 'Detection' -Type $(if ($DetectionResult.State -eq 'Unknown') { 2 } else { 1 })
            $DesiredServiceState = 'Running'
            if ($DetectionResult.State -eq 'Internal') { $DesiredServiceState = 'Stopped' }
            $Script:EvaluationState = $DetectionResult.State
            $Script:DesiredServiceState = $DesiredServiceState
            Set-ManagedServicesState -DesiredState $DesiredServiceState

            Start-Sleep -Seconds 2
            $LatestEventRecordId = Get-LatestNetworkChangeRecordId
            if ($LatestEventRecordId -le $PreviousEventRecordId) {
                if ($DetectionResult.State -eq 'Unknown') {
                    Write-Log -Message 'Network status is unknown. GSA services are running by policy.' -Component 'Evaluate' -Type 2
                }
                return 0
            }
            Write-Log -Message "A newer event 4004 was logged during evaluation (record $LatestEventRecordId); reevaluating." -Component 'Evaluate' -Type 2
            $PreviousEventRecordId = $LatestEventRecordId
        }
        throw "Network changes continued for $MaximumPasses evaluation passes; service state may need a later event-triggered reconciliation."
    } finally {
        if ($MutexObject) {
            Exit-NetworkStateMutex -MutexObject $MutexObject
        }
    }
}

Initialize-Script

try {
    Write-Log -Message "Starting in $Mode mode." -Component 'Main' -Type 1
    switch ($Mode) {
        'Install' {
            if (-not $TargetIPAddress -or -not $ExpectedDnsName) {
                throw 'Install mode requires TargetIPAddress and ExpectedDnsName.'
            }
            $ValidatedConfiguration = Assert-Configuration -IPAddress $TargetIPAddress -DnsName $ExpectedDnsName -Resolver $DnsServer
            Install-NetworkChangeTask -Configuration $ValidatedConfiguration
            $EvaluationExitCode = Invoke-Evaluation
            if ($EvaluationExitCode -ne 0) { exit $EvaluationExitCode }
        }
        'Evaluate' {
            if (-not (Test-IsAdministrator)) {
                throw 'Manual Evaluate mode requires an elevated administrator session.'
            }
            $EvaluationExitCode = Invoke-Evaluation
            if ($EvaluationExitCode -ne 0) { exit $EvaluationExitCode }
        }
        'Uninstall' {
            Remove-NetworkChangeTask
        }
    }
    Write-Log -Message "$Mode mode completed." -Component 'Main' -Type 1
    if ($Mode -eq 'Uninstall') {
        Write-Output "Uninstall completed. Log: $Script:LogFile"
    } else {
        Write-Output ("Network state: {0}. GSA services: {1}. Log: {2}" -f $Script:EvaluationState, $Script:DesiredServiceState, $Script:LogFile)
    }
    exit 0
} catch {
    Write-Log -Message "$Mode mode failed. $($_.Exception.Message)" -Component 'Main' -Type 3
    Write-Error $_.Exception.Message
    exit 1
}
