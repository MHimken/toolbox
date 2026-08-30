# Broken Autopilot Device Cleanup

> [!WARNING]
> **UNFINISHED:** This solution is under development and is not ready for production use. Validate its decisions in a test environment and use dry-run mode before enabling cleanup actions.

This solution analyzes Windows Autopilot records and their linked Microsoft Entra and Intune device objects. It identifies stale or mismatched records and can recommend or perform retention, disablement, retirement, wipe, and removal actions according to configurable inactivity thresholds.

## Files

* [BrokenAutopilotDeviceCleanup.ps1](BrokenAutopilotDeviceCleanup.ps1) - interactive PowerShell implementation for analysis and optional cleanup.
* [BrokenAutopilotDeviceCleanup-flow.md](BrokenAutopilotDeviceCleanup-flow.md) - Mermaid source describing the decision flow.
* [BrokenAutopilotDeviceCleanup-flow.html](BrokenAutopilotDeviceCleanup-flow.html) - standalone HTML rendering of the decision flow.
* [changelog.md](changelog.md) - solution change history.
* [BrokenAutopilotDeviceCleanup-Runbook.ps1](../../Intune/Runbooks/BrokenAutopilotDeviceCleanup-Runbook.ps1) - related Azure Automation implementation.

## Operating modes

* Analysis only: reviews device state without submitting Microsoft Graph changes.
* Dry run: records planned cleanup actions and exports results without modifying devices.
* Cleanup: prepares the configured device actions for submission.

## Requirements

* PowerShell 7 or later.
* Microsoft Graph PowerShell authentication module.
* Microsoft Graph permissions appropriate for every enabled read or cleanup action.
* Certificate-based application authentication for the interactive script.

## Safety

Start with cleanup disabled and review the generated results. Confirm the inactivity thresholds, object relationships, Graph permissions, and configured action types before enabling any destructive operation. Keep dry-run exports as an audit record during testing.
