# Changes

## 2026

### 30th of August

* Add: Add-EntraDeviceToGroupFromWebhook.ps1 - added webhook, scheduled cleanup, and dry-run modes for Entra device group membership.
* Add: BrokenAutopilotDeviceCleanup-Runbook.ps1 - added Azure Automation cleanup of stale Autopilot, Entra, and Intune device records.
* Fix: Repair-PrimaryUser.ps1 - based the estimated sign-in result count on the returned Graph values.

## 2025

### 08th of December

* Update: Add-InfoToEntraDeviceExtensions.ps1 - Outsourced Autopatch exclude to its own script and removed any remarks about Autopatch
* Add: Add-InfoToEntraDeviceExtensions.ps1 - "prevent overwrite" functionality for existing entries
* Add: Add-ExcludeTagsToEntraDeviceExtensions.ps1 - New script to add exclude markers to exclude devices from Autopatch
* New: Repair-PrimaryUser.ps1 - New script to repair primary user information on devices in Intune

### 25th of August

* Add: Minor additions to the description

### 4th of August

* Added folder "Runbooks"
* Added changelog.md for folder "Runbooks"
* Added PrimaryUserInfoToDevice_Runbook.ps1 and PrimaryUserInfoToDevice.md
