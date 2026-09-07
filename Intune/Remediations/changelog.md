# Changes

## 2026

### 6th of September

* Add: Detect-VBATimestampSettings.ps1 - added SYSTEM-context detection for VBA timestamp settings in all cloud-only Entra profile hives.
* Add: Remediate-VBATimestampSettings.ps1 - added SYSTEM-context remediation for VBA timestamp settings in all cloud-only Entra profile hives.

### 30th of August

* Add: Detect-GSA-Settings.ps1 - added detection for Global Secure Access, Kerberos timeout, and IPv4 preference registry settings.
* Add: Remediate-GSA-Settings.ps1 - added remediation for Global Secure Access, Kerberos timeout, and IPv4 preference registry settings.

### 27th of August

* Change: Detect-SSOPromptAdminControl.ps1 - replaced the static registry type enum call with PowerShell-native string comparison.
* Change: Remediate-SSOPromptAdminControl.ps1 - replaced the static registry type enum call with PowerShell-native string comparison.

### 23rd of August

* Add: Detect-SSOPromptAdminControl.ps1 - added detection for the Windows SSO prompt admin control policy value `AutoAcceptSsoPermission`.
* Add: Remediate-SSOPromptAdminControl.ps1 - added remediation to enforce the Windows SSO prompt admin control policy value `AutoAcceptSsoPermission`.
