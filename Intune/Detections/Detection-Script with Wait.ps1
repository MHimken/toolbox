<#
.SYNOPSIS
    Snippet to run a detection script with a maximum runtime limit.
.DESCRIPTION
    This script runs a detection script and ensures it does not exceed a specified maximum runtime.
.PARAMETER MaximumRuntime
    The maximum runtime for the detection script in seconds. Default is 3000 seconds (50 minutes).
.PARAMETER VerifyEvery
    The interval in seconds to check the runtime. Default is 30 seconds.
.EXAMPLE
    .\Detection-ScriptWithWait.ps1 -MaximumRuntime 3600 -VerifyEvery 60
    Runs the detection script with a maximum runtime of 3600 seconds (1 hour) and checks every 60 seconds.
.NOTES
    The absolute maximum runtime should be below 50 minutes (3000 seconds) to comply with system constraints. Usually system maximum runtime is set to 60 minutes (3600 seconds) to allow buffer time.
    Version: 1.0
    Versionname: Detection-Script with Wait
    Initial creation date: 16.01.2026
    Last change date: 16.01.2026
    Latest changes: Initial Version
    Author: Martin Himken
#>
param(
    $MaximumRuntime = 3000,
    $VerifyEvery = 30 
)
$MaxCounter = [math]::Round($MaximumRuntime / $VerifyEvery) # Check every 30 seconds

while(-not($MaxCounter -le 0)){
    # Your main script logic goes here
    Write-Output "Script is running..."
    # Define your condition here
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\THEAPPGUIDORNAME"
    $x = if(Test-Path $RegistryPath){(Get-ItemPropertyValue -Path $RegistryPath -Name "DisplayVersion").Contains("2026.1.1")}else{ $false }
    # Check the condition and exit if met
    if($x){
        Write-Output "Condition met, exiting script."
        Exit 0
    }
    # Simulate work being done
    Start-Sleep -Seconds $VerifyEvery
    $MaxCounter--
}
Write-Output "Maximum runtime reached, exiting script."
Exit 1