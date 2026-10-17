# Toolbox

A collection of PowerShell solutions and scripts for Microsoft Intune, Windows Autopilot, Entra ID, Defender, Configuration Manager, Global Secure Access, Azure, and Windows migration.

> [!WARNING]
> Review and test every script in a non-production environment before deployment. The repository is provided as-is.

## Catalog conventions

- **Last updated** is the date of the most recent Git commit that changed the linked script or solution.
- **Finished** means the script, its README, and its changelog do not identify it as unfinished. It is not a support or production-readiness guarantee.
- **Unfinished** is used when the script, README, or changelog explicitly says that work is incomplete.
- **Moved** identifies an entry retained only as a pointer to another repository.

## Solutions

Multi-file solutions with dedicated documentation and supporting assets.

| Solution | Scripts | Description | Status | Last updated |
| --- | --- | --- | --- | --- |
| [Broken Autopilot Device Cleanup](Autopilot/Solutions/README.md) | [Cleanup script](Autopilot/Solutions/BrokenAutopilotDeviceCleanup.ps1) | Identifies duplicate or stale Autopilot, Intune, and Entra device records and optionally cleans them up. | **Unfinished** | 2026-08-30 |
| [Local Administrator Solution](Intune/Solutions/LocalAdminSolution/README.md) | [Detect](Intune/Solutions/LocalAdminSolution/Remediation/Detect-LocalAdminSolution.ps1) / [Remediate](Intune/Solutions/LocalAdminSolution/Remediation/Remediate-LocalAdminSolution.ps1) / [Deployment](Intune/Solutions/LocalAdminSolution/Deployment/Deploy-LocalAdminReporting.ps1) / [Lookup runbook](Intune/Solutions/LocalAdminSolution/Runbooks/Resolve-LocalAdminLookupNames.ps1) / [HTML export](Intune/Solutions/LocalAdminSolution/HTML/Export-LocalAdminResolvedHtml.ps1) / [Stress-test data](Intune/Solutions/LocalAdminSolution/New-LocalAdminSolutionStressTestData.ps1) | Inventories local administrators through Intune remediation, Azure Table Storage, an Azure Automation lookup runbook, Excel, and HTML reporting. | Finished | 2026-09-09 |
| [Local Administrator Solution (Interactive)](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/README.md) | [Detect](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/Remediation/Detect-LocalAdminSolution.ps1) / [Remediate](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/Remediation/Remediate-LocalAdminSolution.ps1) / [Deployment](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/Deployment/Deploy-LocalAdminReporting.ps1) / [Lookup runbook](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/Runbooks/Resolve-LocalAdminLookupNames.ps1) / [HTML export](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/HTML/Export-LocalAdminResolvedHtml.ps1) / [Backend](Intune/Solutions/LocalAdminSolution/LocalAdminSolutionInteractive/Backend/README.md) | Fresh-deployment variant with an interactive live report, Azure Functions backend, governance rules, and Conditional Access-protected Admin mode. | **Unfinished** | 2026-10-16 |
| [Repair Primary User](Intune/Solutions/Repair-PrimaryUser/README.md) | [Deployment](Intune/Solutions/Repair-PrimaryUser/Deployment/Deploy-RepairPrimaryUser.ps1) / [Daily collection](Intune/Solutions/Repair-PrimaryUser/Runbooks/Collect-PrimaryUserSignInData.ps1) / [Weekly repair](Intune/Solutions/Repair-PrimaryUser/Runbooks/Repair-PrimaryUserAssignments.ps1) | Repairs Intune primary-user assignments from 28 days of aggregated Windows sign-ins using Azure Automation and Azure Tables. | Finished | 2026-09-07 |

## Intune remediations

Each entry links to its detection script. The remediation script is linked separately where present.

| Remediation | Scripts | Status | Last updated |
| --- | --- | --- | --- |
| Disable domain credentials | [Detect](Intune/Remediations/Detect-DisableDomainCreds.ps1) / [Remediate](Intune/Remediations/Remediate-DisableDomainCreds.ps1) | Finished | 2025-10-17 |
| Disable WebDAV service | [Detect](Intune/Remediations/Detect-DisableWebDavService.ps1) / [Remediate](Intune/Remediations/Remediate-DisableWebDavService.ps1) | Finished | 2025-10-17 |
| Disable WPAD service | [Detect](Intune/Remediations/Detect-DisableWPADService.ps1) / [Remediate](Intune/Remediations/Remediate-DisableWPADService.ps1) | Finished | 2025-10-17 |
| Global Secure Access settings | [Detect](Intune/Remediations/Detect-GSA-Settings.ps1) / [Remediate](Intune/Remediations/Remediate-GSA-Settings.ps1) | Finished | 2026-08-30 |
| New Outlook device setting | [Detect](Intune/Remediations/Detect-NewOutlookDEVICE.ps1) / [Remediate](Intune/Remediations/Remediate-NewOutlookDEVICE.ps1) | Finished | 2025-02-19 |
| New Outlook user setting | [Detect](Intune/Remediations/Detect-NewOutlookUSER.ps1) / [Remediate](Intune/Remediations/Remediate-NewOutlookUSER.ps1) | Finished | 2025-02-19 |
| Print to PDF and XPS | [Detect](Intune/Remediations/Detect-PrintToPDFandXPS.ps1) / [Remediate](Intune/Remediations/Remediate-PrintToPDFandXPS.ps1) | Finished | 2025-02-19 |
| SSO prompt administrator control | [Detect](Intune/Remediations/Detect-SSOPromptAdminControl.ps1) / [Remediate](Intune/Remediations/Remediate-SSOPromptAdminControl.ps1) | Finished | 2026-08-30 |
| VBA timestamp settings | [Detect](Intune/Remediations/Detect-VBATimestampSettings.ps1) / [Remediate](Intune/Remediations/Remediate-VBATimestampSettings.ps1) | Finished | 2026-09-07 |
| Reset Windows Update settings | [Detect](Intune/Platform%20Scripts/Detect-ResetWindowsUpdateSettings.ps1) / [Remediate](Intune/Platform%20Scripts/Reset-WindowsUpdateSettings.ps1) | Finished | 2026-10-12 |

See the [Intune remediation changelog](Intune/Remediations/changelog.md) for detailed changes.

## Scripts

### Autopilot

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Add-GroupTagToAllAPDevices.ps1](Autopilot/Add-GroupTagToAllAPDevices.ps1) | Adds a group tag to Autopilot devices. | Finished | 2024-05-22 |

### ConfigMgr

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Invoke-BitlockerEscrowKey.ps1](ConfigMgr/Invoke-BitlockerEscrowKey.ps1) | Escrows a BitLocker recovery key through Configuration Manager. | Finished | 2026-08-30 |

### Defender

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [LDAPSigningAnalyzer.ps1](Defender/LDAPSigningAnalyzer.ps1) | Analyzes LDAP signing configuration and related domain controller events. | Finished | 2026-08-30 |
| [NTLMAuditAnalyse.ps1](Defender/NTLMAuditAnalyse.ps1) | Collects and exports NTLM audit data. | Finished | 2026-08-30 |
| [Set-WindowsProductKey.ps1](Defender/Set-WindowsProductKey.ps1) | Installs and activates a Windows product key from a Defender Live Response session. | Finished | 2026-08-30 |

### Entra

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [New-AzureADApplicationProxyApplicationCommunity.ps1](Entra/ApplicationManagement/New-AzureADApplicationProxyApplicationCommunity.ps1) | Creates an Entra application proxy application. | Finished | 2026-01-23 |
| [Create-CustomIntuneRoleUsingGraph.ps1](Entra/Create-CustomIntuneRoleUsingGraph.ps1) | Creates a custom Intune role through Microsoft Graph; retained as a reference where permissions are unsupported. | Finished | 2026-08-30 |
| [Create-RandomUsersUsingGraph.ps1](Entra/Create-RandomUsersUsingGraph.ps1) | Creates random test users through Microsoft Graph batch requests. | Finished | 2025-08-29 |

### Global Secure Access

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Get-GSAPolicyRuleIDandName.ps1](GlobalSecureAccess/Get-GSAPolicyRuleIDandName.ps1) | Lists Global Secure Access policy rule IDs and names. | Finished | 2025-08-29 |
| [Script-ShowSignOutAndDisablePrivateAccessButton.ps1](GlobalSecureAccess/Script-ShowSignOutAndDisablePrivateAccessButton.ps1) | Configures Global Secure Access client sign-out and Private Access controls. | Finished | 2024-10-01 |
| [Set-GSAInternalNetworkState.ps1](GlobalSecureAccess/Set-GSAInternalNetworkState.ps1) | Installs an event-triggered scheduled task that stops Global Secure Access services on the internal network, detected through reverse DNS, and starts them elsewhere. | Finished | 2026-10-16 |

### [Other](Other/README.md)

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Analyze-CSP-Header.ps1](Other/Analyze-CSP-Header.ps1) / [Demo report](Other/Analyze-CSP-Header-Demo.html) | Analyzes Content-Security-Policy response headers and creates a self-contained interactive HTML report. | Finished | 2026-09-01 |

### Intune: Autopatch, compliance, and detections

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Autopatch-FindFUEnrollingDevices.ps1](Intune/Autopatch/Autopatch-FindFUEnrollingDevices.ps1) | Finds Autopatch devices stuck in feature update enrollment. | **Unfinished** | 2025-07-02 |
| [Compliance_SentinelOne.ps1](Intune/Custom%20Compliance/Compliance_SentinelOne.ps1) and [JSON](Intune/Custom%20Compliance/Compliance_SentinelOne.json) | Reports SentinelOne state for Intune custom compliance. | Finished | 2025-08-05 |
| [Detection-Script with Wait.ps1](Intune/Detections/Detection-Script%20with%20Wait.ps1) | Provides a detection-script template with retry and wait behavior. | Finished | 2026-01-23 |

### Intune: Other

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [AutopilotDualDeviceFinder.ps1](Intune/Other/AutopilotDualDeviceFinder.ps1) | Finds and remediates duplicate Autopilot device records. | **Unfinished** | 2025-10-17 |
| [Connect-SettingsCatalog-To-Group.ps1](Intune/Other/Connect-SettingsCatalog-To-Group.ps1) | Assigns Settings Catalog policies to a group. | Finished | 2025-07-02 |
| [Convert-PolicySet.ps1](Intune/Other/Convert-PolicySet.ps1) | Converts an Intune policy set. | **Unfinished** | 2025-07-02 |
| [Disable-AllowComputerToTurnOffDeviceForNIC.ps1](Intune/Other/Disable-AllowComputerToTurnOffDeviceForNIC.ps1) | Disables the NIC power-management option that lets Windows turn off the device. | Finished | 2026-05-01 |
| [Find-WindowsUpdateNotifications.ps1](Intune/Other/Find-WindowsUpdateNotifications.ps1) | Correlates Windows Update notification and installation events. | **Unfinished** | 2026-08-30 |
| [Get-OutlookAddInsToWMI.ps1](Intune/Other/Get-OutlookAddInsToWMI.ps1) | Inventories Outlook add-ins across user profiles into WMI. | Finished | 2026-05-01 |
| [List-EAMApplications.ps1](Intune/Other/List-EAMApplications.ps1) | Lists Enterprise App Management applications. | Finished | 2025-07-02 |
| [Rename-ComputerRandomizer.ps1](Intune/Other/Rename-ComputerRandomizer.ps1) | Renames a computer using a randomized name. | **Unfinished** | 2025-07-02 |
| [ScriptWrapper.ps1](Intune/Other/ScriptWrapper.ps1) | Wraps script execution with shared logging and process behavior. | Finished | 2025-07-02 |
| [Send-EntraDeviceIDToWebhookDuringESP.ps1](Intune/Other/Send-EntraDeviceIDToWebhookDuringESP.ps1) | Sends the Entra device ID to a webhook during Enrollment Status Page provisioning. | Finished | 2026-08-30 |
| [Win32App-Wait.ps1](Intune/Other/Win32App-Wait.ps1) | Waits for a condition during Win32 app deployment. | Finished | 2025-07-02 |

### Intune: Platform scripts

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Set-BackgroundWallpaperAsUser.ps1](Intune/Platform%20Scripts/Set-BackgroundWallpaperAsUser.ps1) | Sets the desktop background in the user context. | Finished | 2025-08-05 |
| [Set-DisableClipSVCSubscription.ps1](Intune/Platform%20Scripts/Set-DisableClipSVCSubscription.ps1) | Configures the ClipSVC subscription setting. | Finished | 2026-08-30 |
| [Set-TimeZoneUsingAzureMaps.ps1](Intune/Platform%20Scripts/Set-TimeZoneUsingAzureMaps.ps1) | Sets the device time zone using location data and Azure Maps. | Finished | 2025-08-29 |
| [Set-VBATimestampSettings.ps1](Intune/Platform%20Scripts/Set-VBATimestampSettings.ps1) | Configures VBA digital signature timestamp settings in all cloud-only Entra user profile hives. | Finished | 2026-09-07 |
| [Test-IntunePlatformScriptStress.ps1](Intune/Platform%20Scripts/Test-IntunePlatformScriptStress.ps1) | Creates or removes unassigned Intune platform scripts to stress-test the tenant platform-script limit. | Finished | 2026-10-12 |

### Intune: Runbooks

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Add-EntraDeviceToGroupFromWebhook.ps1](Intune/Runbooks/Add-EntraDeviceToGroupFromWebhook.ps1) | Adds an Entra device to a group from a webhook request. | Finished | 2026-08-30 |
| [Add-ExcludeTagToEntraDeviceFromGroup.ps1](Intune/Runbooks/Add-ExcludeTagToEntraDeviceFromGroup.ps1) | Adds an exclusion extension attribute to devices in a group. | Finished | 2025-12-11 |
| [Add-InfoToEntraDeviceExtensions.ps1](Intune/Runbooks/Add-InfoToEntraDeviceExtensions.ps1) | Writes primary-user and Intune information to Entra device extension attributes. | Finished | 2025-12-11 |
| [BrokenAutopilotDeviceCleanup-Runbook.ps1](Intune/Runbooks/BrokenAutopilotDeviceCleanup-Runbook.ps1) | Runs analysis or cleanup of stale Autopilot-related device records in Azure Automation. | Finished | 2026-08-30 |
| [Delete-DevicesOlderThanDays.ps1](Intune/Runbooks/Delete-DevicesOlderThanDays.ps1) | Deletes devices older than a configured age. | Finished | 2026-05-01 |
| [Repair-PrimaryUser.ps1](Intune/Runbooks/Repair-PrimaryUser.ps1) | Repairs Intune primary-user assignments; superseded by the [Repair Primary User](Intune/Solutions/Repair-PrimaryUser/README.md) solution. | **Unfinished** | 2026-08-30 |

Additional setup guidance is available in the [runbook README](Intune/Runbooks/README.md).

### Intune: Tools

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Search-IntuneSetting.ps1](Intune/SearchIntuneSettings/Search-IntuneSetting.ps1) | Provides a Windows UI for searching exported Intune settings. | **Unfinished** | 2026-03-20 |

### Windows migration

| Script | Description | Status | Last updated |
| --- | --- | --- | --- |
| [Windows11BasicInformationCollection.ps1](Windows%20Migration/Windows11BasicInformationCollection.ps1) | Collects basic Windows 11 migration readiness information. | Finished | 2024-12-05 |

## Moved projects

| Project | Current location | Status | Last updated here |
| --- | --- | --- | --- |
| Intune Network Requirements | [Repository pointer](Intune/IntuneNetworkRequirements/readme.md) | Moved | 2025-08-30 |
| Azure Network Requirements | [Repository pointer](Azure/AzureNetworkRequirements/Test-AzureNetworkRequirements) | Moved | 2025-02-14 |

## Change history

See the [repository changelog](CHANGELOG.md) and the changelog in each category for detailed changes.
