<#
.SYNOPSIS
Remediates stuck Windows Update policy settings for Intune reporting.
.DESCRIPTION
This is to clean a computer completely of any Windows Update related keys. Very handy if you're switching to something like Autopatch.
* Will stop relevant services such as IME and Autopatch
* Will delete legacy GPO/local policy paths (SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)
* Will delete CSPs (SOFTWARE\Microsoft\PolicyManager\current\device\Update)
* Will delete GPCache folder to get rid of stuck policies (SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache)
* Will do gpupdate (if applicable) and Intune sync
* Will do ConfigMgr machine policy and software update scan actions (if applicable)
Should get rid of most of your problems when dealing with sticky policies.
#################################################
DO NOT RUN THIS ON A REGULAR BASIS. This script is a cannonball, not a bullet.
#################################################
.PARAMETER ResetLocalPolicies
Enables or disables the reset of the local .pol file for machine settings as this can have unintended consequences
.PARAMETER BackupDisabled
##NOT RECOMMENDED## Disables all backups
.PARAMETER GPUpdateTimeout
Defines how long the script should wait for the gpupdate
.PARAMETER IntuneSyncTimeout
Defines the maximum number of seconds allowed for each DeviceEnroller process
.PARAMETER WorkingDirectory
Specifies the working directory where the script will be executed. The default value is "C:\RWU\".
.PARAMETER LogDirectory
Specifies the directory where log files will be stored. The default value is "C:\RWU\".
.PARAMETER ScriptTimeoutSeconds
Specifies the base runtime in seconds before adding GPUpdateTimeout and IntuneSyncTimeout. The combined runtime is capped at 50 minutes, and new work stops five seconds early to allow cleanup.
.PARAMETER Log
Enables CMTrace-compatible file logging.
.PARAMETER TimestampRegistryPath
Specifies the registry key that stores the successful remediation timestamp. Use the same value in the detection script.
.EXAMPLE
This example will run the script with, create the registry key backup in C:\RWU and restart required services.

.\Reset-WindowsUpdateSettings.ps1
.EXAMPLE
If you have a slower group policy update you might want to use this as it will increase the wait time from 60 seconds to 120 seconds.
This will also prevent the deletion of the .pol file which hold the machines policies.

.\Reset-WindowsUpdateSettings.ps1 -ResetLocalPolicies:$False -GPUpdateTimeout 120
.NOTES
Version: 1.6
Author: Martin Himken
Original script name: Reset-WindowsUpdateSettings.ps1
Initial creation date: 10.03.25
Last change: 30.08.26
Exit codes: 0 = success, 1 = operation failed, 2 = timeout, 3 = restore failed, 4 = timestamp failed
.LINK
changelog.md
#>

param(
    [System.IO.DirectoryInfo]$WorkingDirectory = [System.IO.DirectoryInfo]"C:\ProgramData\RWU\",
    [System.IO.DirectoryInfo]$LogDirectory = [System.IO.DirectoryInfo]"C:\ProgramData\RWU\",
    [boolean]$ResetLocalPolicies = $true,
    [switch]$BackupDisabled,
    [ValidateRange(0, 3000)]
    [int]$GPUpdateTimeout = 120,
    [ValidateRange(0, 3000)]
    [int]$IntuneSyncTimeout = 120,
    [ValidateRange(10, 300)]
    [int]$ScriptTimeoutSeconds = 300,
    [boolean]$Log = $false,
    [ValidatePattern('^HKLM:\\')]
    [string]$TimestampRegistryPath = 'HKLM:\SOFTWARE\MHimken\Remediations\ResetWindowsUpdateSettings'
)
$Script:ExitCode = 0
$Script:DeadlineExpired = $false
$Script:RemediationErrors = [System.Collections.Generic.List[string]]::new()
$Script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$Script:MaximumRuntimeSeconds = [Math]::Min(3000, $ScriptTimeoutSeconds + $GPUpdateTimeout + $IntuneSyncTimeout)
$Script:WorkDeadlineSeconds = [Math]::Max(1, $Script:MaximumRuntimeSeconds - 5)
$Script:RemediationTimestampName = 'LastSuccessUtc'

function Get-RemainingWorkMilliseconds {
    $RemainingMilliseconds = ([double]$Script:WorkDeadlineSeconds * 1000) - $Script:Stopwatch.ElapsedMilliseconds
    return [Math]::Max(0, [int][Math]::Floor($RemainingMilliseconds))
}
function Assert-WorkTimeRemaining {
    param(
        [string]$Operation
    )
    if ((Get-RemainingWorkMilliseconds) -le 0) {
        $Script:DeadlineExpired = $true
        throw [System.TimeoutException]::new("Script deadline reached before $Operation")
    }
}
function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        [int]$MaximumSeconds = 0
    )
    Assert-WorkTimeRemaining -Operation $Operation
    $RemainingMilliseconds = Get-RemainingWorkMilliseconds
    if ($MaximumSeconds -gt 0) {
        $RemainingMilliseconds = [Math]::Min($RemainingMilliseconds, $MaximumSeconds * 1000)
    }
    $Process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -WindowStyle Hidden -ErrorAction Stop
    if (-not($Process.WaitForExit($RemainingMilliseconds))) {
        try { $Process.Kill() } catch { }
        $Script:DeadlineExpired = (Get-RemainingWorkMilliseconds) -le 0
        if ($Script:DeadlineExpired) {
            throw [System.TimeoutException]::new("Script deadline reached while waiting for $Operation")
        }
        throw "$Operation exceeded its allowed runtime"
    }
    return $Process.ExitCode
}
function Initialize-Script {
    <#
        .SYNOPSIS
        Will initialize most of the required variables throughout this script.
    #>
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    $Script:CurrentLocation = Get-Location
    if (-not(Test-Path -LiteralPath $WorkingDirectory.FullName)) {
        New-Item -Path $WorkingDirectory.FullName -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    if ((Get-Location).Path -ne $WorkingDirectory.FullName) {
        Set-Location -LiteralPath $WorkingDirectory.FullName -ErrorAction Stop
    }
    if (-not($Script:LogFile)) {
        $LogPrefix = 'RWU' #Reset Windows Update
        $Script:LogFile = Join-Path -Path $LogDirectory.FullName -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path -LiteralPath $LogDirectory.FullName)) {
            New-Item -Path $LogDirectory.FullName -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
    Write-Log 'Script is initialized - gathering information and initializing directories' -Component 'InitializeScript'
    if (-not($BackupDisabled)) {
        Write-Log 'Creating Backup directory' -Component 'InitializeScript'
        $Script:BackupDirectory = Join-Path -Path $WorkingDirectory.FullName -ChildPath $Script:DateTime
        try {
            New-Item -Path $Script:BackupDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "Backup directory could not be created; continuing without backups: $($_.Exception.Message)" -Component 'InitializeScript' -Type 2
        }
    }
    $Script:BackupAvailable = (-not($BackupDisabled)) -and (Test-Path -LiteralPath $Script:BackupDirectory)
    $Script:IsIntuneDevice = ($null -ne (Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue))
    if ($Script:IsIntuneDevice) {
        Write-Log 'Device is managed by Intune' -Component 'InitializeScript'
    } else {
        Write-Log 'Device is not managed by Intune' -Component 'InitializeScript'
    }
    $Script:IsActiveDirectoryDevice = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if ($Script:IsActiveDirectoryDevice) {
        Write-Log 'Device is domain joined' -Component 'InitializeScript'
    } else {
        Write-Log 'Device is not domain joined' -Component 'InitializeScript'
    }
    $Script:IsConfigMgrDevice = ($null -ne (Get-Service ccmexec -ErrorAction SilentlyContinue))
    if ($Script:IsConfigMgrDevice) {
        Write-Log 'Device is running ConfigMgr client' -Component 'InitializeScript'
        try {
            $CurrentWorkloadConfiguration = (Get-CimInstance -Namespace root/ccm/InvAgt -ClassName CCM_System -ErrorAction Stop).ComgmtWorkloads
            if (-not[boolean]($CurrentWorkloadConfiguration -band 16)) {
                $Script:UrlToRestore = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'UpdateServiceUrlAlternate' -ErrorAction SilentlyContinue
                if (-not($Script:UrlToRestore)) {
                    $Script:UrlToRestore = 'http://localhost:8005'
                }
                Write-Log "ConfigMgr UpdateServiceUrlAlternate captured as $($Script:UrlToRestore)" -Component 'InitializeScript'
            }
        } catch {
            Write-Log "Could not capture ConfigMgr Windows Update state: $($_.Exception.Message)" -Component 'InitializeScript' -Type 2
        }
    } else {
        Write-Log 'Device is not running ConfigMgr client' -Component 'InitializeScript'
    }
}
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of the script by Ryan Ephgrave.
        .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type = 1,
        [string]$ReportMessage
    )
    if ($Type -eq 3) {
        if (-not($ReportMessage)) {
            $ReportMessage = [string]$Message
        }
        $ReportMessage = ($ReportMessage -replace '\s+', ' ').Trim()
        if ($ReportMessage.Length -gt 180) {
            $ReportMessage = $ReportMessage.Substring(0, 180)
        }
        $Script:RemediationErrors.Add($ReportMessage)
    }
    if ($Log) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
        $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
    }
}
function Reset-LocalPolicies {
    $MachinePolicyFile = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
    Assert-WorkTimeRemaining -Operation 'local policy reset'
    if (-not(Test-Path -LiteralPath $MachinePolicyFile)) {
        return $false
    }
    if ($Script:BackupAvailable) {
        Write-Log "Creating backup of machine registry.pol to $($Script:BackupDirectory)" -Component 'ResetLocalPolicies'
        try {
            Copy-Item -LiteralPath $MachinePolicyFile -Destination $Script:BackupDirectory -Force -ErrorAction Stop
        } catch {
            Write-Log "Machine policy backup failed; continuing: $($_.Exception.Message)" -Component 'ResetLocalPolicies' -Type 2
        }
    }
    Write-Log 'Removing registry.pol' -Component 'ResetLocalPolicies'
    Remove-Item -LiteralPath $MachinePolicyFile -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $MachinePolicyFile) {
        throw "Machine policy file still exists after removal: $MachinePolicyFile"
    }
    return $true
}
function Start-GroupPolicyRefresh {
    if (-not($Script:IsActiveDirectoryDevice)) {
        return
    }
    try {
        Assert-WorkTimeRemaining -Operation 'group policy refresh'
        if (Test-ComputerSecureChannel -ErrorAction Stop) {
            $GPupdatePath = Join-Path -Path $Env:SystemRoot -ChildPath 'System32\gpupdate.exe'
            $GPUpdateArguments = @('/target:computer', "/wait:$GPUpdateTimeout", '/force')
            Write-Log "Starting gpupdate with a maximum wait time of $GPUpdateTimeout seconds" -Component 'StartGroupPolicyRefresh'
            $GPUpdateExitCode = Invoke-BoundedProcess -FilePath $GPupdatePath -ArgumentList $GPUpdateArguments -Operation 'gpupdate' -MaximumSeconds $GPUpdateTimeout
            if ($GPUpdateExitCode -ne 0) {
                Write-Log "gpupdate returned exit code $GPUpdateExitCode" -Component 'StartGroupPolicyRefresh' -Type 2
            }
        }
    } catch [System.TimeoutException] {
        throw
    } catch {
        Write-Log "Group policy refresh failed; continuing: $($_.Exception.Message)" -Component 'StartGroupPolicyRefresh' -Type 2
    }
}
function Start-ConfigMgrActions {
    if (-not($Script:IsConfigMgrDevice)) {
        return
    }
    Write-Log "Starting ConfigMgr client actions" -Component 'StartConfigMgrActions'
    try {
        Assert-WorkTimeRemaining -Operation 'ConfigMgr Machine Policy action'
        Invoke-CimMethod -Namespace 'root\CCM' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000021}' } -ErrorAction Stop | Out-Null
        Write-Log "ConfigMgr Machine Policy client action successful" -Component 'StartConfigMgrActions'
    } catch [System.TimeoutException] {
        throw
    } catch {
        Write-Log "ConfigMgr Machine Policy action failed; continuing: $($_.Exception.Message)" -Component 'StartConfigMgrActions' -Type 2
    }
    try {
        Assert-WorkTimeRemaining -Operation 'ConfigMgr Software Update Scan action'
        Invoke-CimMethod -Namespace 'root\CCM' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{sScheduleID = '{00000000-0000-0000-0000-000000000113}' } -ErrorAction Stop | Out-Null
        Write-Log "ConfigMgr Software Update Scan client action successful" -Component 'StartConfigMgrActions'
    } catch [System.TimeoutException] {
        throw
    } catch {
        Write-Log "ConfigMgr Software Update Scan action failed; continuing: $($_.Exception.Message)" -Component 'StartConfigMgrActions' -Type 2
    }
}
function Restore-ConfigMgrUpdateUrl {
    if (-not($Script:UrlToRestore)) {
        return
    }
    $CurrentUpdateServiceUrlAlternate = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'UpdateServiceUrlAlternate' -ErrorAction SilentlyContinue
    if (-not($CurrentUpdateServiceUrlAlternate)) {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'WindowsUpdate' -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'UpdateServiceUrlAlternate' -Value $Script:UrlToRestore -Force -ErrorAction Stop | Out-Null
        Write-Log "Restored UpdateServiceUrlAlternate to $($Script:UrlToRestore)" -Component 'RestoreConfigMgrUpdateUrl'
    }
}
function Start-IMESync {
    Assert-WorkTimeRemaining -Operation 'Intune sync'
    Write-Log 'Starting IME sync' -Component 'StartSync'
    $Shell = New-Object -ComObject Shell.Application
    $Shell.open("intunemanagementextension://syncapp") | Out-Null
    $GUIDs = (Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' -ErrorAction SilentlyContinue).PSChildName
    foreach ($GUID in $GUIDs) {
        Assert-WorkTimeRemaining -Operation 'DeviceEnroller refresh'
        $IsIntuneGUID = (Get-ItemPropertyValue -LiteralPath "HKLM:\SOFTWARE\Microsoft\Enrollments\$GUID" -Name AADResourceID -ErrorAction SilentlyContinue) -eq "https://checkin.dm.microsoft.com"
        if ($IsIntuneGUID) {
            $DeviceEnrollerPath = Join-Path -Path $Env:SystemRoot -ChildPath 'System32\DeviceEnroller.exe'
            try {
                $DeviceEnrollerExitCode = Invoke-BoundedProcess -FilePath $DeviceEnrollerPath -ArgumentList @('/o', $GUID, '/c', '/b') -Operation 'DeviceEnroller' -MaximumSeconds $IntuneSyncTimeout
                if ($DeviceEnrollerExitCode -ne 0) {
                    Write-Log "DeviceEnroller returned exit code $DeviceEnrollerExitCode" -Component 'StartSync' -Type 2
                }
            } catch [System.TimeoutException] {
                throw
            } catch {
                Write-Log "DeviceEnroller failed; continuing: $($_.Exception.Message)" -Component 'StartSync' -Type 2
            }
        }
    }
}
function Backup-RegistryToReg {
    param(
        $Path,
        [Parameter()][ValidateSet('HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER', 'HKEY_USERS')]
        $Root,
        $RegName
    )
    $BackupTarget = Join-Path -Path $Script:BackupDirectory -ChildPath $RegName
    $FullRegistryPath = Join-Path -Path $Root -ChildPath $Path
    $RegPath = Join-Path -Path $Env:SystemRoot -ChildPath 'System32\reg.exe'
    try {
        $RegArguments = @('export', "`"$FullRegistryPath`"", "`"$BackupTarget`"", '/y')
        $RegExitCode = Invoke-BoundedProcess -FilePath $RegPath -ArgumentList $RegArguments -Operation "backup of $FullRegistryPath"
        if ($RegExitCode -eq 0) {
            Write-Log "Backup of $FullRegistryPath to $BackupTarget successful" -Component 'BackupRegistry'
            return $true
        }
        Write-Log "Backup of $FullRegistryPath failed with exit code $RegExitCode; continuing" -Component 'BackupRegistry' -Type 2
    } catch [System.TimeoutException] {
        throw
    } catch {
        Write-Log "Backup of $FullRegistryPath failed; continuing: $($_.Exception.Message)" -Component 'BackupRegistry' -Type 2
    }
    return $false
}
function Reset-KnownRWURegistryPaths {
    param(
        $path
    )
    Assert-WorkTimeRemaining -Operation "removal of $path"
    $CurrentRegPathPSDrive = Join-Path -Path 'HKLM:\' -ChildPath $path
    $CurrentRegPathExists = Test-Path -LiteralPath $CurrentRegPathPSDrive
    if (-not($CurrentRegPathExists)) {
        Write-Log 'This registry path already seems to be removed - continue' -Component 'ResetKnownRegistryPaths'
        return $false
    }
    if ($Script:BackupAvailable) {
        Write-Log "Creating backup of registry path related to windows update to $($Script:BackupDirectory)" -Component 'ResetKnownRegistryPaths'
        Backup-RegistryToReg -Path $path -Root HKEY_LOCAL_MACHINE -RegName "$((Get-Item -LiteralPath $CurrentRegPathPSDrive).PSChildName).reg" | Out-Null
    }
    Write-Log "Removing $CurrentRegPathPSDrive registry paths" -Component 'ResetKnownRegistryPaths'
    Remove-Item -LiteralPath $CurrentRegPathPSDrive -Force -Recurse -ErrorAction Stop
    if (Test-Path -LiteralPath $CurrentRegPathPSDrive) {
        throw "Registry path still exists after removal: $CurrentRegPathPSDrive"
    }
    return $true
}
function Stop-UpdateServices {
    Assert-WorkTimeRemaining -Operation 'service stop'
    $WindowsUpdateService = Get-Service wuauserv -ErrorAction SilentlyContinue
    $Script:WindowsUpdateNeedsRestart = $null -ne $WindowsUpdateService -and $WindowsUpdateService.Status -ne 'Stopped'
    $ClientBrokerService = Get-Service ClientBrokerUpgrader -ErrorAction SilentlyContinue
    $Script:HasLegacyClientBroker = $null -ne $ClientBrokerService
    $Script:ClientBrokerWasRunning = $null -ne $ClientBrokerService -and $ClientBrokerService.Status -eq 'Running'
    if ($Script:ClientBrokerWasRunning) {
        Write-Log 'Stopping the legacy Autopatch ClientBrokerUpgrader service' -Component 'StopUpdateServices'
        $ClientBrokerService | Stop-Service -Force -ErrorAction Stop
    }
    if ($null -eq $WindowsUpdateService) {
        Write-Log 'Windows Update service was not found; continuing' -Component 'StopUpdateServices' -Type 2
        return
    }
    if ($Script:WindowsUpdateNeedsRestart) {
        $MaximumAttempts = 3
        for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++) {
            try {
                Assert-WorkTimeRemaining -Operation "Windows Update service stop attempt $Attempt"
                Write-Log "Stopping the Windows Update service (attempt $Attempt of $MaximumAttempts)" -Component 'StopUpdateServices'
                Stop-Service -Name wuauserv -Force -ErrorAction Stop
                if ((Get-Service wuauserv -ErrorAction Stop).Status -eq 'Stopped') {
                    return
                }
                throw 'Windows Update service still reports a non-stopped state'
            } catch [System.TimeoutException] {
                throw
            } catch {
                if ($Attempt -eq $MaximumAttempts) {
                    Write-Log "Windows Update service could not be stopped after $MaximumAttempts attempts; continuing: $($_.Exception.Message)" -Component 'StopUpdateServices' -Type 2
                } else {
                    Write-Log "Windows Update service stop attempt $Attempt failed; retrying: $($_.Exception.Message)" -Component 'StopUpdateServices' -Type 2
                    Start-Sleep -Seconds 2
                }
            }
        }
    }
}
function Start-UpdateServices {
    if ($Script:WindowsUpdateNeedsRestart) {
        Write-Log 'Starting the Windows Update service without waiting for it' -Component 'StartUpdateServices'
        Get-Service wuauserv -ErrorAction Stop | Start-Service -ErrorAction Stop
    }
    if ($Script:ClientBrokerWasRunning) {
        Write-Log 'Starting the legacy Autopatch service without waiting for it' -Component 'StartUpdateServices'
        Get-Service ClientBrokerUpgrader -ErrorAction Stop | Start-Service -ErrorAction Stop
    }
}
function Start-AutopatchTasks {
    if (-not($Script:IsIntuneDevice) -or $Script:HasLegacyClientBroker) {
        return
    }
    Assert-WorkTimeRemaining -Operation 'Autopatch task query'
    $AutopatchTasks = @(Get-ScheduledTask -TaskName 'Autopatch*' -ErrorAction SilentlyContinue)
    if ($AutopatchTasks.Count -eq 0) {
        Write-Log 'No Autopatch scheduled tasks were found' -Component 'StartAutopatchTasks'
        return
    }
    $OrderedTasks = $AutopatchTasks | Sort-Object @{ Expression = {
            if ($_.TaskName -match 'Sync') { 0 }
            elseif ($_.TaskName -match 'Poll') { 1 }
            else { 2 }
        } }, TaskName
    foreach ($Task in $OrderedTasks) {
        Assert-WorkTimeRemaining -Operation "Autopatch task $($Task.TaskName)"
        try {
            Start-ScheduledTask -TaskPath $Task.TaskPath -TaskName $Task.TaskName -ErrorAction Stop | Out-Null
            Write-Log "Triggered Autopatch task $($Task.TaskPath)$($Task.TaskName)" -Component 'StartAutopatchTasks'
        } catch {
            Write-Log "Could not trigger Autopatch task $($Task.TaskName); continuing: $($_.Exception.Message)" -Component 'StartAutopatchTasks' -Type 2
        }
    }
}
function Set-RemediationTimestamp {
    if (-not(Test-Path -LiteralPath $TimestampRegistryPath)) {
        New-Item -Path $TimestampRegistryPath -Force -ErrorAction Stop | Out-Null
    }
    $Timestamp = Get-Date -Format o
    New-ItemProperty -LiteralPath $TimestampRegistryPath -Name $Script:RemediationTimestampName -Value $Timestamp -PropertyType String -Force -ErrorAction Stop | Out-Null
}
function Start-DelayedIMERestart {
    if (-not($Script:IsIntuneDevice)) {
        return
    }
    $RestartCommand = "`"& { Start-Sleep -Seconds 30; Restart-Service -Name 'IntuneManagementExtension' -Force -ErrorAction SilentlyContinue } *> `$null`""
    $PowerShellPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    Start-Process -FilePath $PowerShellPath -ArgumentList @('-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', $RestartCommand) -WindowStyle Hidden -ErrorAction Stop | Out-Null
}

# START CODING
$Script:CurrentLocation = Get-Location
try {
    Initialize-Script
    Stop-UpdateServices
    Reset-KnownRWURegistryPaths -path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    Reset-KnownRWURegistryPaths -path "SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache" | Out-Null
    $CSPUpdatePath = Reset-KnownRWURegistryPaths -path "SOFTWARE\Microsoft\PolicyManager\current\device\Update"
    if ($ResetLocalPolicies) {
        if (-not(Reset-LocalPolicies)) {
            Write-Log 'No local .pol file' -Component 'RSUMain'
        }
    }
    Start-AutopatchTasks
    if ($Script:IsIntuneDevice -and $CSPUpdatePath) {
        Write-Log 'Since we removed the current CSP configuration we should try to trigger a resync' -Component 'RSUMain'
        try {
            Start-IMESync
        } catch [System.TimeoutException] {
            throw
        } catch {
            Write-Log "Intune refresh failed; continuing: $($_.Exception.Message)" -Component 'RSUMain' -Type 2
        }
    }
    Start-ConfigMgrActions
    Start-GroupPolicyRefresh
} catch [System.TimeoutException] {
    $Script:DeadlineExpired = $true
    $Script:ExitCode = 2
    Write-Log $_.Exception.Message -Component 'ErrorHandling' -Type 3 -ReportMessage 'Timeout'
} catch {
    $Script:ExitCode = 1
    Write-Log "Something went wrong: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 3 -ReportMessage "Failed: $($_.Exception.Message)"
} finally {
    try {
        Restore-ConfigMgrUpdateUrl
    } catch {
        Write-Log "ConfigMgr URL restoration failed: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 3 -ReportMessage "URL restore: $($_.Exception.Message)"
        if (-not($Script:DeadlineExpired)) { $Script:ExitCode = 3 }
    }
    try {
        Start-UpdateServices
    } catch {
        Write-Log "Service restoration failed: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 3 -ReportMessage "Service restore: $($_.Exception.Message)"
        if (-not($Script:DeadlineExpired)) { $Script:ExitCode = 3 }
    }
    try {
        Set-Location -LiteralPath $Script:CurrentLocation.Path -ErrorAction Stop
    } catch {
        Write-Log "Could not restore the original location: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 3 -ReportMessage "Path restore: $($_.Exception.Message)"
        if (-not($Script:DeadlineExpired)) { $Script:ExitCode = 0 }
    }
}
if ($Script:ExitCode -eq 0) {
    try {
        Set-RemediationTimestamp
        try {
            Start-DelayedIMERestart
        } catch {
            Write-Log "Delayed IME restart could not be queued: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 2
        }
        Write-Output 'Success: Reset complete'
    } catch {
        $Script:ExitCode = 4
        Write-Log "Timestamp write failed: $($_.Exception.Message)" -Component 'ErrorHandling' -Type 3 -ReportMessage "Timestamp: $($_.Exception.Message)"
    }
}
if ($Script:ExitCode -ne 0) {
    $ErrorSummary = ($Script:RemediationErrors | Select-Object -Unique) -join ' | '
    if (-not($ErrorSummary)) {
        $ErrorSummary = "Failed: Exit $($Script:ExitCode)"
    }
    Write-Error $ErrorSummary
}
Exit $Script:ExitCode