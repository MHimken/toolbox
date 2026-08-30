<#
.SYNOPSIS
Detects whether the Windows Update settings reset is due.
.DESCRIPTION
Returns compliant when the remediation completed successfully within the last 24 hours.
Missing, invalid, or older timestamps request remediation.
.PARAMETER TimestampRegistryPath
Specifies the registry key that stores the successful remediation timestamp.
.PARAMETER ForceRun
Requests remediation once, then uses the normal success check during the force cooldown.
.PARAMETER ForceRunCooldownMinutes
Specifies how long another forced request is suppressed. The default is 15 minutes.
.NOTES
Version: 1.6
Author: Martin Himken
Initial creation date: 23.08.26
Last change: 24.08.26
Changes: see changelog.md

Intune Remediation settings:
* Run this script using the logged-on credentials: No
* Enforce script signature check: No
* Run script in 64-bit PowerShell: Yes
!!
Schedule this Remediation to run once. Do not configure a recurring schedule.
!!
#>

param(
    [ValidatePattern('^HKLM:\\')]
    [string]$TimestampRegistryPath = 'HKLM:\SOFTWARE\MHimken\Remediations\ResetWindowsUpdateSettings',
    [boolean]$ForceRun = $true,
    [ValidateRange(1, 1440)]
    [int]$ForceRunCooldownMinutes = 15
)

$TimestampName = 'LastSuccessUtc'
$ForceTimestampName = 'LastForceUtc'
$AutopilotSetupRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup'
$MinimumAge = New-TimeSpan -Hours 24
$ForceRunCooldown = New-TimeSpan -Minutes $ForceRunCooldownMinutes

function Set-ForceTimestamp {
    if (-not(Test-Path -LiteralPath $TimestampRegistryPath)) {
        New-Item -Path $TimestampRegistryPath -Force -ErrorAction Stop | Out-Null
    }
    $Timestamp = Get-Date -Format o
    New-ItemProperty -LiteralPath $TimestampRegistryPath -Name $ForceTimestampName -Value $Timestamp -PropertyType String -Force -ErrorAction Stop | Out-Null
}

try {
    $AutopilotSetupProperties = Get-ItemProperty -LiteralPath $AutopilotSetupRegistryPath -ErrorAction SilentlyContinue
    $ProvisioningStatus = $AutopilotSetupProperties.HasProvisioningCompleted
    $HasProvisioningCompleted = $ProvisioningStatus -eq "4294967295"
    if ($AutopilotSetupProperties -and -not($HasProvisioningCompleted)) {
        Write-Output 'Current: Enrollment Status Page active'
        exit 0
    }

    if ($ForceRun) {
        $TimestampProperties = Get-ItemProperty -LiteralPath $TimestampRegistryPath -ErrorAction SilentlyContinue
        $ForceTimestampValue = $TimestampProperties.$ForceTimestampName
        $ForceCooldownActive = $false
        if ($ForceTimestampValue) {
            try {
                $LastForceUtc = [DateTime]::ParseExact(
                    $ForceTimestampValue,
                    'o',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).ToUniversalTime()
                $CurrentUtc = (Get-Date).ToUniversalTime()
                $ForceElapsed = New-TimeSpan -Start $LastForceUtc -End $CurrentUtc
                $ForceCooldownActive = $LastForceUtc -gt $CurrentUtc -or $ForceElapsed -lt $ForceRunCooldown
            } catch [FormatException] {
                $ForceCooldownActive = $false
            }
        }
        if (-not($ForceCooldownActive)) {
            Set-ForceTimestamp
            Write-Output 'Due: Forced'
            exit 1
        }
    }

    $TimestampProperties = Get-ItemProperty -LiteralPath $TimestampRegistryPath -ErrorAction SilentlyContinue
    $TimestampValue = $TimestampProperties.$TimestampName
    if (-not($TimestampValue)) {
        Write-Output 'Due: Never run'
        exit 1
    }

    $LastSuccessUtc = [DateTime]::ParseExact(
        $TimestampValue,
        'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    ).ToUniversalTime()

    $CurrentUtc = (Get-Date).ToUniversalTime()
    if ($LastSuccessUtc -gt $CurrentUtc) {
        Write-Output 'Due: Future timestamp'
        exit 1
    }

    $SuccessAge = New-TimeSpan -Start $LastSuccessUtc -End $CurrentUtc
    if ($SuccessAge -lt $MinimumAge) {
        Write-Output "Current: $($LastSuccessUtc.ToString('u'))"
        exit 0
    }

    Write-Output "Due: $($LastSuccessUtc.ToString('u'))"
    exit 1
} catch {
    $ErrorText = ($_.Exception.Message -replace '\s+', ' ').Trim()
    if ($ErrorText.Length -gt 160) {
        $ErrorText = $ErrorText.Substring(0, 160)
    }
    Write-Output "Due: Detect error - $ErrorText"
    exit 1
}
