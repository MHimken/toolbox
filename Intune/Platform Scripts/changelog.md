# Changes

## 2026

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
