# Changes

## 2026

### 16th of October

- Plan: Added Set-GSAInternalNetworkState.plan.md for event 4004 network detection, IP-to-DNS validation, GSA service control, and a persistent single-instance scheduled task.
- Plan: Documented the confirmed service dependency (Engine depends on Tunneling): stop Engine before Tunneling, start Tunneling before Engine.
- Plan: Added copy-ready test-device discovery scripts (service inventory, event 4004 location, reverse DNS probe, stop/start order, event trigger single-instance test).
- Plan: Changed the target runtime to Windows PowerShell 5.1 (64-bit) as a documented deviation from the script skill's PowerShell 7 requirement.
- Plan: Shortened the event 4004 test to query the confirmed NetworkProfile operational channel.
- Add: Set-GSAInternalNetworkState.ps1 - installs a single-instance event-triggered task to detect internal networks and control GSA services.
- Update: Documented implementation choices, static validation, and remaining test-device validation in Set-GSAInternalNetworkState.plan.md.
- Update: Excluded Set-GSAInternalNetworkState.plan.md from source control via the repository .gitignore.
- Fix: Use the SYSTEM account name in the scheduled-task XML principal to avoid rejecting the service-account logon principal during installation.

## 2025

### 29th of August

- Add: Get-GSAPolicyRuleIDandName.ps1

### Before

- Add: Script-ShowSignOutAndDisablePrivateAccessButton.ps1