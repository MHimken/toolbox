<#
THIS SCRIPT IS NOT DONE!
    .NOTES
    Version: 0.1
    Versionname: Autopatch-FindFUEnrollingDevices
    Intial creation date: 30.06.2025
    Last change date: 02.07.2025
    Latest changes: TODO: Put .MD here
    Shoutouts: 
#>
param(
    [string]$GroupID = "",
    [version]$TargetOSVersion = "10.0.22631.0", # OS Version example for Windows 11 23H2 and older
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\AP-Enrolling\",
    [Parameter(Mandatory = $false)]
    [System.IO.DirectoryInfo]$LogDirectory = "C:\AP-Enrolling\Logs\",
    [Parameter(Mandatory = $false)]
    [Switch]$NoLog,
    [Parameter(Mandatory = $false)]
    [Switch]$ToConsole
)

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
        $LogPrefix = 'AFFED' # Autopatch Find FU Enrolling Devices
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
    $Script:results = [System.Collections.ArrayList]::new()
}

function Search-EnrollingAutopatchDevices {
    <#
    .SYNOPSIS
    Searches for devices that are marked as "enrolling" in WUfB-DS via Autopatch.
    #>
    $Members = Get-MgGroupMember -GroupId $GroupID -All
    $AllTargetedAutopatchDevices = $Members | Sort-Object -Property @{Expression = "Id"; Ascending = $true }  | ForEach-Object { Invoke-MgGraphRequest -URI "https://graph.microsoft.com/beta/devices/$($_.id)" }
    $AllAutopatchDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets?" -Method Get
    foreach ($AutopatchDevice in $AllTargetedAutopatchDevices) {
        if($AutopatchDevice.deviceId -notin $AllAutopatchDevices.value.id){
            continue
        }
        $FUEnrollmentStatusAll = $AllTargetedAutopatchDevices | Sort-Object -Property @{Expression = "deviceId"; Ascending = $true } | ForEach-Object { Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/$($_.deviceId)" }
        $FUEnrollmentStatus = $FUEnrollmentStatusAll | Where-Object { $_.id -eq $AutopatchDevice.deviceId }
        if ($FUEnrollmentStatus -and $FUEnrollmentStatus.enrollment.feature.enrollmentState -eq "enrolling") {
            $Script:results.Add([PSCustomObject]@{
                    Name             = $AutopatchDevice.displayName
                    DeviceId         = $AutopatchDevice.id
                    OSVersion        = $AutopatchDevice.operatingSystemVersion
                    EnrollmentStatus = $FUEnrollmentStatus.enrollment.feature.enrollmentState
                }) | Out-Null
        }
    }
}

function Repair-EnrollingAutopatchDevices {
    <#
    .SYNOPSIS
    Repairs devices that are marked as "enrolling" in WUfB-DS via Autopatch.
    #>
    foreach ($result in $Script:results) {
        Write-Host "Repairing device: $($result.Name) with DeviceId: $($result.DeviceId)"
        $JSONBody = @{        
            updateCategory = "feature"
            assets         = @(
                @{
                    '@odata.type' = "#microsoft.graph.windowsUpdates.azureADDevice"
                    id            = $result.DeviceId
                }
            )
        } | ConvertTo-Json
        Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/admin/windows/updates/updatableAssets/unenrollAsset" -Method Post -body $JSONBody
    }
}
#Start coding!
Initialize-Script
Search-EnrollingAutopatchDevices
$Script:results | Out-GridView