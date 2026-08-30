# Changes

## 2026

### 30th of August

* Change: Reset-WindowsUpdateSettings.ps1 - uses a five-minute base runtime plus the configured `GPUpdateTimeout` and `IntuneSyncTimeout`, with the combined runtime capped at 50 minutes.
* Fix: Reset-WindowsUpdateSettings.ps1 - retries stopping the Windows Update service twice and continues with a warning if all three attempts fail.

### 27th of August

* Add: Set-DisableClipSVCSubscription.ps1 - added a platform script that enforces the ClipSVC `DisableSubscription` registry value as DWORD `1`.

### 24th of August

* Fix: Detect-ResetWindowsUpdateSettings.ps1 - returns compliant during the Enrollment Status Page so the Windows Update reset cannot run before Autopilot provisioning completes.

### 23rd of August

* Change: Reset-WindowsUpdateSettings.ps1 - converted the script for use as an Intune Remediation with concise result reporting and distinct failure exit codes.
* Add: Detect-ResetWindowsUpdateSettings.ps1 - added registry timestamp detection to prevent successful remediation from running again within 24 hours.
* Add: Reset-WindowsUpdateSettings.ps1 - added a 50-second runtime limit that stops optional work early and reports timeout separately.
* Fix: Reset-WindowsUpdateSettings.ps1 - services, the working directory, and the ConfigMgr update URL are now restored through guaranteed cleanup paths.
* Fix: Reset-WindowsUpdateSettings.ps1 - captures `UpdateServiceUrlAlternate` before deleting the Windows Update policy key.
* Change: Reset-WindowsUpdateSettings.ps1 - backup failures are warnings and no longer stop registry cleanup.
* Change: Reset-WindowsUpdateSettings.ps1 - supports legacy ClientBrokerUpgrader and current Autopatch scheduled tasks without assuming tasks exist.
* Change: Reset-WindowsUpdateSettings.ps1 - queues a delayed, silent IME restart after successful remediation so Intune can record the result first.
* Change: Reset-WindowsUpdateSettings.ps1 - suppresses intermediate command output and emits only the final remediation result.
* Add: Reset-WindowsUpdateSettings.ps1 and Detect-ResetWindowsUpdateSettings.ps1 - added `TimestampRegistryPath` to override the registry key used for the 24-hour timestamp.
* Add: Detect-ResetWindowsUpdateSettings.ps1 - added registry-backed `ForceRun` and configurable `ForceRunCooldownMinutes` so forced remediation is requested once and post-remediation detection can verify success.
* Change: Reset-WindowsUpdateSettings.ps1 and Detect-ResetWindowsUpdateSettings.ps1 - replaced registry and current-time class calls with Windows PowerShell 5.1 cmdlets where direct equivalents are available.
* Fix: Detect-ResetWindowsUpdateSettings.ps1 - handles existing timestamp registry keys where `LastForceUtc` or `LastSuccessUtc` has not been created yet.

* 24th of January

  * Fix: Reset-WindowsUpdateSettings.ps1 - Microsoft removed the ClientBrokerUpgrader service. Updated the script to handle this change gracefully.
  * Change: Reset-WindowsUpdateSettings.ps1 - won't log to file by default anymore
  * Add: Reset-WindowsUpdateSettings.ps1 - switched the DeviceEnroller re-apply CSPs to use the MMPC enrollment GUID instead of the Intune enrollment GUID, as the latter didn't work reliably.

## 2025

### 29th of August

* Add: Set-TimeZoneUsingAzureMaps.ps1

### 4th of August

* Add: changelog.md for folder "Platform Scripts"
* Add: Set-BackgroundWallpaperAsUser.ps1
