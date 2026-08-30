# Changes

## 2026

### 30th of August

* Add: BrokenAutopilotDeviceCleanup-flow.md and BrokenAutopilotDeviceCleanup-flow.html - added human-readable Markdown and HTML flow documentation for the cleanup process.
* Move: BrokenAutopilotDeviceCleanup.ps1 and its flow documents into the Autopilot Solutions folder.
* Add: README.md - documented the unfinished solution, its files, operating modes, and safety considerations.

### 23rd of August

* Add: Azure Automation runbook version of BrokenAutopilotDeviceCleanup.ps1 with webhook-driven serial input; see [BrokenAutopilotDeviceCleanup-Runbook](../../Intune/Runbooks/BrokenAutopilotDeviceCleanup-Runbook.ps1).
* Add: Dry-run support with planned cleanup action logging and CSV results export.
* Change: Centralized cleanup dates and action settings as script-scoped variables in the runbook.
* Change: Dry-run Graph scope validation to require read permissions only.
* Change: Graph permission documentation for Intune managed-device delete and retire actions.
* Fix: Prevent stale log filenames from being reused between script runs.
* Fix: Ensure dry-run executions enter the analysis path and export results.
* Fix: Preserve hashtable behavior for webhook serial matching in the runbook.
* Fix: Use the configured deletion and disable thresholds for Entra Autopilot-linked device actions.
