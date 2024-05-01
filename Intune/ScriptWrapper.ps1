<#
.SYNOPSIS
This script can be used to launch other scripts and only allow them a specific amount of time to run.
.DESCRIPTION
This script is specifcally written to run Powershell scripts. The script will
* Use Start-Job that uses Start-Process to launch a PowerShell.exe
* Start-Process is using -WorkingDirectory W -FilePath X -NoNewWindow -Wait -RedirectStandardOutput `"scriptoutput.log`" -ArgumentList Y
* PowerShell.exe is started using -NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy bypass -File ScriptPath ArgumentsForScript
!!Attention!!
By default this will use the powershell.exe located in system32 _not_ sysWOW64! If required, change it.
Every output from the launched script will be written to "Scriptoutput.log" in the same location as this wrapper
.PARAMETER ScriptPath
The exact path to the .ps1 file - no other files are supported at this time
.PARAMETER TimeOutInSeconds
Specify the timeout for the wrapper to wait until the sub-script is stopped
.PARAMETER ArgumentsForScript
Pass the arguments exactly as you would when running the script as a string
.EXAMPLE
.\ScriptWrapper.ps1 -ScriptPath C:\temp\Runner.ps1 -TimeOutInSeconds 9 -ArgumentsForScript "-Time 10"
This example would start the .ps1 file in C:\temp\ and wait for a maximum of 9 seconds.
.NOTES
    Version: 1.0
    Intial creation date: 01.05.2024
    Last change date: 01.05.2024
    Latest changes: https://github.com/MHimken/toolbox/tree/main/Intune
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [int]$TimeOutInSeconds,
    [string]$ArgumentsForScript
)

$JobName = New-Guid
$TimeoutInMilliseconds = [timespan]::FromSeconds($TimeOutInSeconds).TotalMilliseconds
$ExecutePath = Join-Path $env:Systemroot -ChildPath "\system32\WindowsPowerShell\v1.0\"
$Executable = "powershell.exe"
$ArgumentListForPowerShell = "-NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy bypass -File $ScriptPath " + $ArgumentsForScript
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$ScriptBlockInit = [scriptblock]::Create("Start-Process -WorkingDirectory $ExecutePath -FilePath $Executable -NoNewWindow -Wait -RedirectStandardOutput `"scriptoutput.log`" -ArgumentList `"$ArgumentListForPowerShell`"")
$parametersForJob = @{
    Name        = $JobName
    ScriptBlock = $ScriptBlockInit
}
Start-Job @parametersForJob | Out-Null
while ($Stopwatch.ElapsedMilliseconds -le $TimeoutInMilliseconds -and (Get-Job -Name $JobName).State -eq 'Running') {
    Start-Sleep -Milliseconds 1000
}

if ((Get-Job -Name $JobName).State -ne 'Running') {
    Write-Information 'Script not running anymore'
    $ExitCode = 0
} else {
    Write-Warning 'Script is still running and will not be forcefully stopped'
    $ExitCode = 1
}
#Cleanup Jobs
Get-Job -Name $JobName | ForEach-Object { Stop-Job $_; Remove-Job $_ -Force }
$Stopwatch.Stop()
$ElapsedTime = [timespan]::FromMilliseconds($Stopwatch.ElapsedMilliseconds).Seconds
Write-Information "Time elapsed according to timer: $ElapsedTime"
Exit $ExitCode