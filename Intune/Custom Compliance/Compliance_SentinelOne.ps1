<#
.SYNOPSIS
    Compliance check for SentinelOne Agent installation and running processes.
.DESCRIPTION
    This script checks if the SentinelOne Agent is installed and if the required processes are running.
.NOTES
    Version: 1.0
    Versionname: Compliance_SentinelOne
    Initial creation date: 02.08.2025
    Last change date: 02.08.2025
    Latest changes: Initial Version
    Author: Martin Himken
#>
param(
    [string]$App_DisplayName = "Sentinel Agent", # DisplayName from Appwiz.cpl
    [array]$requiredProcesses = @("SentinelAgent", "SentinelStaticEngine", "SentinelStaticEngineScanner", "SecurityHealthService", "SentinelHelperService", "SentinelMemoryScanner")
)

[boolean]$condition_ScriptProcessing = $true
[boolean]$condition_AppInstalled = $false
[boolean]$condition_ServiceRunning = $false

try {
    $installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $installedApps += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    if ($installedApps | Where-Object { $null -ne $_.DisplayName -and $_.DisplayName -eq $App_DisplayName }) {
        $condition_AppInstalled = $true
    }

    $runningProcesses = Get-Process
    [int]$processCheckCounter = 0
    foreach ($requiredProcess in $requiredProcesses) {
        if ($runningProcesses | Where-Object { $_.Name -eq $requiredProcess }) {
            $processCheckCounter++
        }
    }
    $condition_ServiceRunning = $processCheckCounter -eq $requiredProcesses.Count
} catch {
    $condition_ScriptProcessing = $false
}

$hash = @{ 
    'Processing-Successful'   = $condition_ScriptProcessing; 
    'ApplicationInstalled'    = $condition_AppInstalled; 
    'DefinedProcessesRunning' = $condition_ServiceRunning;
}
return $hash | ConvertTo-Json -Compress