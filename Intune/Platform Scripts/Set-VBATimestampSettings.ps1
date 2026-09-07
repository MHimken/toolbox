<#
.SYNOPSIS
    Configure VBA digital signature timestamp settings for Entra user profiles.
.DESCRIPTION
    Runs as SYSTEM, discovers cloud-only Entra profiles by their S-1-12-1 SID,
    and configures the VBA timestamp settings in every profile hive. Unloaded
    NTUSER.DAT files are mounted temporarily and unloaded after configuration.
.NOTES
Version: 1.0
Author: Martin Himken
Initial creation date: 06.09.26
Last change: 06.09.26
Changes: see changelog.md

Intune Platform Script settings:
* Run this script using the logged-on credentials: No
* Enforce script signature check: No
* Run script in 64-bit PowerShell: Yes
#>

$ErrorActionPreference = 'Stop'

$profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$settingsSubPath = 'Software\Microsoft\VBA\Security'
$desiredValues = @(
    @{ Name = 'TimeStampURL'; Value = 'http://timestamp.digicert.com'; Type = 'String' }
    @{ Name = 'TimeStampRetryCount'; Value = 3; Type = 'DWord' }
    @{ Name = 'TimeStampRetryDelay'; Value = 1000; Type = 'DWord' }
)

function Get-EntraUserProfile {
    Get-ChildItem -LiteralPath $profileListPath -ErrorAction Stop |
        Where-Object { $_.PSChildName -match '^S-1-12-1-\d+-\d+-\d+-\d+$' } |
        ForEach-Object {
            $profilePath = [Environment]::ExpandEnvironmentVariables(
                (Get-ItemPropertyValue -LiteralPath $_.PSPath -Name 'ProfileImagePath' -ErrorAction Stop)
            )

            [PSCustomObject]@{
                Sid      = $_.PSChildName
                HivePath = Join-Path -Path $profilePath -ChildPath 'NTUSER.DAT'
            }
        }
}

function Mount-UserHive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $true)]
        [string]$HivePath
    )

    if (-not (Test-Path -LiteralPath $HivePath)) {
        return $false
    }

    & "$env:SystemRoot\System32\reg.exe" load "HKU\$Sid" $HivePath 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Dismount-UserHive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    & "$env:SystemRoot\System32\reg.exe" unload "HKU\$Sid" 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

try {
    if (-not [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        Write-Output 'ERROR: Platform script must run as SYSTEM.'
        exit 1
    }

    $profiles = @(Get-EntraUserProfile)
    if ($profiles.Count -eq 0) {
        Write-Output 'NOTAPPLICABLE: No cloud-only Entra user profiles were found.'
        exit 0
    }

    $failedProfiles = [System.Collections.Generic.List[string]]::new()

    foreach ($profile in $profiles) {
        $hiveRoot = "Registry::HKEY_USERS\$($profile.Sid)"
        $loadedByScript = $false
        $registryKey = $null
        $verifyKey = $null

        try {
            if (-not (Test-Path -LiteralPath $hiveRoot)) {
                if (-not (Mount-UserHive -Sid $profile.Sid -HivePath $profile.HivePath)) {
                    throw "Unable to load '$($profile.HivePath)'."
                }
                $loadedByScript = $true
            }

            $registryPath = "$hiveRoot\$settingsSubPath"
            if (-not (Test-Path -LiteralPath $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }

            $registryKey = Get-Item -LiteralPath $registryPath -ErrorAction Stop
            foreach ($desiredValue in $desiredValues) {
                if ($registryKey.GetValueNames() -contains $desiredValue.Name) {
                    $currentType = [string]$registryKey.GetValueKind($desiredValue.Name)
                    if ($currentType -ne $desiredValue.Type) {
                        Remove-ItemProperty -LiteralPath $registryPath -Name $desiredValue.Name -Force -ErrorAction Stop
                    }
                }

                New-ItemProperty -LiteralPath $registryPath -Name $desiredValue.Name `
                    -Value $desiredValue.Value -PropertyType $desiredValue.Type -Force | Out-Null

                $verifyKey = Get-Item -LiteralPath $registryPath -ErrorAction Stop
                $verifyType = [string]$verifyKey.GetValueKind($desiredValue.Name)
                $verifyValue = $verifyKey.GetValue($desiredValue.Name)
                if ($verifyType -ne $desiredValue.Type -or
                    [string]$verifyValue -ne [string]$desiredValue.Value) {
                    throw "Verification failed for '$($desiredValue.Name)'."
                }
            }

            Write-Output "SUCCESS: Entra profile $($profile.Sid) was configured successfully."
        } catch {
            $failedProfiles.Add($profile.Sid)
            Write-Output "ERROR: Entra profile $($profile.Sid). $($_.Exception.Message)"
        } finally {
            $registryKey = $null
            $verifyKey = $null
            if ($loadedByScript -and -not (Dismount-UserHive -Sid $profile.Sid)) {
                if (-not $failedProfiles.Contains($profile.Sid)) {
                    $failedProfiles.Add($profile.Sid)
                }
                Write-Output "ERROR: Unable to unload the registry hive for $($profile.Sid)."
            }
        }
    }

    if ($failedProfiles.Count -gt 0) {
        exit 1
    }

    Write-Output 'SUCCESS: All cloud-only Entra user profiles were configured successfully.'
    exit 0
} catch {
    Write-Output "ERROR: Platform script failed. $($_.Exception.Message)"
    exit 1
}