<#
.SYNOPSIS
This script will nuke all Windows Update related keys - made with Intune and Autopatch in mind.
.DESCRIPTION
This is to clean a computer completely of any Windows Update related keys. Very handy if you're switching to something like Autopatch.
* Will stop relevant services such as IME and Autopatch
* Will delete legacy GPO/local policy paths (SOFTWARE\Policies\Windows\WindowsUpdate)
* Will delete CSPs (SOFTWARE\Microsoft\PolicyManager\current\device\Update)
* Will delete GPCache folder to get rid of stuck policies (SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache)
* Will do gpupdate (if applicable) and Intune sync
Should get rid of most of your problems when dealing with sticky policies.
#################################################
DO NOT RUN THIS ON A REGULAR BASIS. This script is a canonball, not a bullet.
#################################################
.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Reset-WindowsUpdateSettings.ps1
Initial creation date: 10.03.25
Last change: 16.03.25
#>

param(
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\RWU\",
    [System.IO.DirectoryInfo]$LogDirectory = "C:\RWU\",
    [boolean]$ResetLocalPolicies=$true,
    [switch]$BackupDisabled,
    [int]$GPUpdateTimeout = 60,
    [int]$IntuneSyncTimeout = 60
)
function Get-ScriptPath {
    <#
    .SYNOPSIS
    Get the current script path.
    #>
    if ($PSScriptRoot) { 
        # Console or VS Code debug/run button/F5 temp console
        $ScriptRoot = $PSScriptRoot 
    } else {
        if ($psISE) { 
            Split-Path -Path $psISE.CurrentFile.FullPath
        } else {
            if ($profile -match 'VScode') { 
                # VS Code "Run Code Selection" button/F8 in integrated console
                $ScriptRoot = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
            } else { 
                Write-Output 'unknown directory to set path variable. exiting script.'
                exit
            } 
        } 
    }
    $Script:PathToScript = $ScriptRoot
}
function Initialize-Script {
    <#
        .SYNOPSIS
        Will initialize most of the required variables throughout this script.
    #>
    if($Script:DateTime){
        Clear-Variable DateTime
    }
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    if (-not($Script:CurrentLocation)) {
        $Script:CurrentLocation = Get-Location
    }
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null } 
    if ((Get-Location).path -ne $WorkingDirectory) {
        Set-Location $WorkingDirectory
    }
    Get-ScriptPath
    if (-not($Script:LogFile)) {
        $LogPrefix = 'RWU' #Reset Windows Update
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
    Write-Log 'Script is initialized - gathering information and initializing directories' -Component 'InitializeScript'
    #####Custom content
    if (-not($BackupDisabled)) {
        Write-Log 'Creating Backup directory' -Component 'InitializeScript'
        $Script:BackupDirectory = $(Join-Path -Path $WorkingDirectory -ChildPath "$Script:DateTime")
        New-Item -Path $Script:BackupDirectory -ItemType Directory -Force | Out-Null
    }
    $Script:IsIntuneDevice = ($null -ne (Get-Service IntuneManagementExtension -ErrorAction SilentlyContinue))
    if ($Script:IsIntuneDevice) {
        Write-Log 'Device is managed by Intune' -Component 'InitializeScript'
        $IsAutoPatchDevice = Test-Path "C:\Program Files\Windows Autopatch Client Broker\ClientBroker\ClientBroker.exe"
        if (-not($IsAutoPatchDevice)) {
            Write-Log 'Device is not managed by Autopatch' -Component 'InitializeScript'  
        }
        Write-Log 'Device is managed by Autopatch' -Component 'InitializeScript'
    } else {
        Write-Log 'Device is not managed by Intune' -Component 'InitializeScript'
    }
    $IsActiveDirectoryDevice = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if ($IsActiveDirectoryDevice) {
        Write-Log 'Device is domain joined' -Component 'InitializeScript'
    } else {
        Write-Log 'Device is not domain joined' -Component 'InitializeScript'
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
        [ValidateSet('1', '2', '3')][int]$Type
    )
    if (-not($NoLog)) {
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
function Reset-LocalPolicies {
    $MachinePolicyFile = "C:\Windows\System32\GroupPolicy\Machine\Registry.pol"
    if(-not(Test-Path -Path $MachinePolicyFile)){
        return $false
    }
    if (-not($BackupDisabled)) {
        Write-Log "Creating backup of machine registry.pol to $($Script:BackupDirectory)" -Component 'ResetLocalPolicies'
        Copy-Item $MachinePolicyFile -Destination $Script:BackupDirectory -Force
    }
    Write-Log 'Removing registry.pol' -Component 'ResetLocalPolicies'
    Remove-Item -Path $MachinePolicyFile -Force
    if ($IsActiveDirectoryDevice -and (Test-ComputerSecureChannel)) {
        Write-Log 'Computer is domain joined and domain is reachable - forcing gpupdate with target computer' -Component 'ResetLocalPolicies'
        $GPupdatePath = Join-Path -Path "$Env:SystemRoot" -ChildPath "\System32\gpupdate.exe"
        $GPUpdateArguments = "/target:computer /wait:$GPUpdateTimeout /force"
        Write-Log "Starting gpupdate with a wait time of $GPUpdateTimeout" -Component 'ResetLocalPolicies'
        $GPUpdate = Start-Process -FilePath $GPupdatePath -ArgumentList $GPUpdateArguments -PassThru -WindowStyle Hidden -Wait
        if ($GPUpdate.ExitCode -eq 0) {
            Write-Log "Sync successful" -Component 'ResetLocalPolicies'
        } else {
            Write-Log "Sync unsuccessful - maybe the wait time was not enough." -Component 'ResetLocalPolicies' -Type 2
        }
    }
}
function Restart-IMEService {
    Write-Log 'Attempting to restart the IME service' -Component 'RestartIME'
    Get-Service IntuneManagementExtension | Restart-Service -Force
}
function Start-IMESync {
    Write-Log "Starting IME sync and waiting $IntuneSyncTimeout seconds" -Component 'StartSync'
    $Shell = New-Object -ComObject Shell.Application
    $Shell.open("intunemanagementextension://syncapp")
    $GUIDs = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\ -Depth 0).PSChildName
    foreach($GUID in $GUIDs){
        $IsIntuneGUID = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\$GUID" -Name AADResourceID) -eq "https://manage.microsoft.com/"
        if($IsIntuneGUID){
            $DeviceEnrollerPath = "C:\Windows\System32\DeviceEnroller.exe"
            $DeviceEnrollerArgs = "/o $GUID /c /b"
            Write-Log 'Running devicecontroller to enforce the CSPs from Intune' -Component 'StartSync'
            $DeviceEnroller = Start-Process -FilePath $DeviceEnrollerPath -ArgumentList $DeviceEnrollerArgs -PassThru -WindowStyle Hidden -Wait
            if($DeviceEnroller.ExitCode -ne 0){
                Write-Log 'You managed to make the Deviceenroller return with a non-zero return code somehow...' -Component 'StartSync' -Type 3
            }
        }
    }
    Start-Sleep -Seconds $IntuneSyncTimeout
}
function Backup-RegistryToReg {
    param(
        $Path,
        [Parameter()][ValidateSet('HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER', 'HKEY_USERS')]
        $Root,
        $RegName
    )
    $BackupTarget = $(Join-Path -Path $Script:BackupDirectory -ChildPath $RegName)
    $FullRegistryPath = $(Join-Path -Path $Root -ChildPath $Path)
    $RegPath = Join-Path -Path "$Env:SystemRoot" -ChildPath "\System32\reg.exe"
    $RegArguments = "export $FullRegistryPath $BackupTarget /y"
    $Reg = Start-Process -FilePath $RegPath -ArgumentList $RegArguments -PassThru -WindowStyle Hidden -Wait
    if ($Reg.ExitCode -eq 0) {
        Write-Log "Backup of $FullRegistryPath to $BackupTarget successfull" -Component 'BackupRegistry'
    } else {
        Write-Log 'Backup failed!' -Component 'BackupRegistry' -Type 3
        throw
    }
}
function Reset-KnowRWURegistryPaths {
    param(
        $path
    )
    $CurrentRegPathPSDrive = $(Join-Path -Path "HKLM:\" -ChildPath $path)
    $CurrentRegPathExists = Test-Path $CurrentRegPathPSDrive
    if (-not($CurrentRegPathExists)) {
        Write-Log 'This registry path already seems to be removed - continue' -Component 'ResetKnownRegistryPaths'
        return $false
    }
    if (-not($BackupDisabled)) {
        Write-Log "Creating backup of registry path related to windows update to $($Script:BackupDirectory)" -Component 'ResetKnownRegistryPaths'
        Backup-RegistryToReg -Path $path -Root HKEY_LOCAL_MACHINE -RegName "$((Get-Item $CurrentRegPathPSDrive).PSChildName).reg" 
    }
    Write-Log "Removing $CurrentRegPathPSDrive registry paths" -Component 'ResetKnownRegistryPaths'
    Remove-Item -Path $CurrentRegPathPSDrive -Force -Recurse
    return $true
}
function Stop-UpdateServices {
    if ($IsAutoPatchDevice) {
        Write-Log 'Attempting to stop the Autopatch service' -Component 'StopUpdateServices'
        Get-Service ClientBrokerUpgrader | Stop-Service -Force
    }
    Write-Log 'Attempting to stop the Windows Update service' -Component 'StopUpdateServices'
    Get-Service wuauserv | Stop-Service -Force
}
function Start-UpdateServices {
    Write-Log 'Attempting to start the Windows Update service' -Component 'StartUpdateServices'
    Get-Service wuauserv | Start-Service -ErrorAction Continue
    Start-Sleep -Seconds 10
    if ($IsAutoPatchDevice) {
        Write-Log 'Attempting to start the Autopatch service' -Component 'StartUpdateServices'
        Get-Service ClientBrokerUpgrader | Start-Service
    }
}

#Start Coding!
Initialize-Script
try {
    Stop-UpdateServices
    Reset-KnowRWURegistryPaths -path "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    Reset-KnowRWURegistryPaths -path "SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\GPCache" | Out-Null
    $CSPUpdatePath = Reset-KnowRWURegistryPaths -path "SOFTWARE\Microsoft\PolicyManager\current\device\Update"
    if ($Script:IsIntuneDevice -and $CSPUpdatePath) {
        Write-Log 'Since we removed the current CSP configuration we should try to trigger a resync' -Component 'RSUMain'
        Restart-IMEService
        Start-IMESync
    }
    if ($ResetLocalPolicies) {
        if(-not(Reset-LocalPolicies)){
            Write-Log 'No local .pol file' -Component 'RSUMain'
        }
    }
    Start-UpdateServices
} catch {
    Write-Log 'Something went wrong! Please consult the log' -Component 'Errorhandling'
    Write-Log "$($Error[0].Exception.Message)" -Component 'Errorhandling'
    Exit 1
}
Set-Location $Script:CurrentLocation
Exit 0