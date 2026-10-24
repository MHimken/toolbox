# Repair Primary User

This Azure Automation solution repairs Microsoft Intune primary-user assignments from successful Windows sign-ins. It uses two independently scheduled PowerShell 7.2 runbooks and compact Azure Table aggregates.

## Architecture

![Repair Primary User architecture: deployment, daily collection, weekly analysis, Azure Tables, and Microsoft Graph](Images/Repair-PrimaryUser-Solution.png)

The daily collector reads the previous completed UTC day, counts successful `Windows Sign In` events by device and user, and stores only the count and latest sign-in timestamp. Raw audit events are not stored.

The weekly analyzer requires every expected daily partition to be marked `Complete`. It totals the previous 28 days, selects the user with the most sign-ins, and uses the latest successful sign-in as a deterministic tie-breaker. Devices without eligible sign-ins are unchanged.

## Azure resources

The deployment creates:

- One StorageV2 account with shared-key access disabled.
- `PrimaryUserDaily`, `PrimaryUserState`, and `PrimaryUserAudit` Azure Tables.
- One Azure Automation Account with a system-assigned managed identity.
- `Storage Table Data Contributor` assignments scoped to the three solution tables.
- Published PowerShell 7.2 daily and weekly runbooks with UTC schedules.

The managed identity requires these Microsoft Graph application permissions:

- `AuditLog.Read.All`
- `DeviceManagementManagedDevices.ReadWrite.All`

The deployment script can grant both permissions. The administrator running it needs permission to deploy Azure resources and role assignments, plus a Microsoft Entra role permitted to grant application permissions. Microsoft Entra audit-log licensing and retention must cover the configured analysis period.

## Deployment

Run the deployment from PowerShell 7.2 on an administration workstation or Azure Cloud Shell. The script uses `bicep` from PATH if available. On Windows, if it is missing, the script asks to download a temporary Bicep executable from the official Azure Bicep release. Use `-InstallTemporaryBicep` to approve this download without a prompt.

The downloaded executable must have a valid Microsoft Authenticode signature before it is run. It is added to PATH only for this deployment; the original PATH is restored and the temporary directory is removed on success or failure. No administrator rights are normally required. On other platforms, install Bicep on PATH before deploying.

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-RepairPrimaryUser.ps1 `
    -SubscriptionId '<subscription-id>' `
    -TenantId '<tenant-id>' `
    -ResourceGroupName 'rg-repair-primary-user' `
    -Location 'westeurope' `
    -StorageAccountName '<globally-unique-storage-name>' `
    -InstallMissingModules `
    -InstallTemporaryBicep
```

Defaults:

- Daily collection: `03:00` UTC.
- Weekly analysis: Sunday at `05:00` UTC.
- Analysis window: 28 completed UTC days.
- Daily aggregate retention: 35 days.
- Assignment mode: apply changes.

The weekly time must be at least one hour after the daily collection time. Override the defaults with `-CollectorStartTimeUtc`, `-AnalyzerStartTimeUtc`, and `-AnalyzerDayOfWeek`.

Use `-SkipGraphPermissionGrant` only when both Graph application permissions will be assigned to the Automation Account managed identity separately.

## Initial warm-up

The analyzer intentionally fails without making changes until all 28 required daily partitions exist. This protects assignments from incomplete evidence. After first deployment, either allow 28 daily collections to complete or backfill an inclusive date range with `CollectionDate` and `CollectionEndDate`.

The [date-range example under Daily collection](#daily-collection) collects September 24 through October 21, 2026: 28 completed UTC days. Replace those dates with the 28 days ending yesterday to prepare for the scheduled analyzer. Backfilling requires those dates to remain available in your tenant's sign-in logs; split larger collections into smaller ranges if needed. Disable the weekly schedule during backfill, then run a preview before enabling scheduled changes.

For controlled testing, start the analyzer manually with a smaller `DaysToAnalyze` value after collecting those dates explicitly. Restore the scheduled value to 28 before production use.

## Table schema

`PrimaryUserDaily` stores one row per UTC date, device, and user:

- `PartitionKey`: collection date as `yyyyMMdd`.
- `RowKey`: `<device-guid>|<user-guid>`.
- `DeviceId`: Microsoft Entra device ID.
- `UserId`: Microsoft Entra user ID.
- `SignInCount`: successful sign-ins for that day.
- `LatestSignIn`: latest successful sign-in in UTC.

`PrimaryUserState` stores collection status, analysis locks, and run summaries. Collection rows use partition `Collection`; weekly summaries use `AnalysisRuns`.

`PrimaryUserAudit` stores one row per evaluated Intune device and weekly run. Its partition key is the unique run ID. Outcomes include `Unchanged`, `Preview`, `Updated`, and `Failed`.

## Running a single job in the Azure portal

You can run either published runbook once with custom parameters without changing its schedule:

1. Open the deployed **Automation Account** in the Azure portal, select **Runbooks**, then select `Collect-PrimaryUserSignInData` or `Repair-PrimaryUserAssignments`.
2. Select **Start** and enter `StorageAccountName`. Leave other inputs at their defaults unless you want to override them for this job.
3. For collection, enter `CollectionDate` for a single completed UTC day, or also enter `CollectionEndDate` for an inclusive range. Use `yyyy-MM-dd`; set `ForceRecollect` to `true` only to rebuild already-completed days.
4. For analysis, set `Preview` to `true` to write recommendations without changing Intune. For a historical window, also set `AnalysisEndDate` to its last completed UTC day and, if needed, `DaysToAnalyze`.
5. Confirm **Start**, then inspect the job's **Output** and **Errors**. Wait for collection to finish successfully before starting analysis.

Boolean inputs use `true` or `false` in the portal, not PowerShell's `$true` or `$false`. Parameters apply only to that job; the weekly schedule still applies assignments by default.

## Daily collection

The scheduled collector processes the previous completed UTC date. To recollect a specific date after a failed or incorrect run:

```powershell
Start-AzAutomationRunbook `
    -ResourceGroupName 'rg-repair-primary-user' `
    -AutomationAccountName '<automation-account>' `
    -Name 'Collect-PrimaryUserSignInData' `
    -Parameters @{
        StorageAccountName = '<storage-account>'
        CollectionDate = '2026-09-01'
        ForceRecollect = $true
    }
```

Collection uses replacement semantics. An incomplete date partition is deleted and rebuilt, so restarting it does not double-count sign-ins. Completed dates are skipped unless `ForceRecollect` is supplied.

`ForceRecollect` is a Boolean runbook input, defaulting to `false`. In the portal select `true` to rebuild completed dates. When invoking the script directly, use `-ForceRecollect $true`.

For smaller environments, backfill an inclusive range in a single job by supplying `CollectionDate` and `CollectionEndDate`, both in `yyyy-MM-dd` format:

```powershell
Start-AzAutomationRunbook `
    -ResourceGroupName 'rg-repair-primary-user' `
    -AutomationAccountName '<automation-account>' `
    -Name 'Collect-PrimaryUserSignInData' `
    -Parameters @{
        StorageAccountName = '<storage-account>'
        CollectionDate = '2026-09-24'
        CollectionEndDate = '2026-10-21'
    }
```

This collects all 28 days from September 24 through October 21, oldest first, processing and retaining aggregates for only one day in memory at a time. `CollectionEndDate` requires `CollectionDate`; the end must be on or after the start, and all dates must be completed UTC days. Omitting both dates still collects only yesterday.

Each day has its own completion state. If one day fails, the job stops; rerun the same range to skip completed dates and retry the failed and remaining dates. `ForceRecollect` rebuilds every date in the range, including completed dates. Keep ranges within your tenant's available sign-in log history and the Automation job runtime limit; use smaller ranges or separate jobs for larger environments. Do not overlap range jobs with another collector job for the same dates.

## Data retention

Both runbooks delete expired rows in Table Storage entity group transactions of up to 100 rows per request. Queries request only `PartitionKey` and `RowKey` and are processed page by page, so deleting a day with tens of thousands of device/user rows takes a few hundred requests instead of one request per row.

- **Collector (`RetentionDays`, default 35):** after a successful job, every `PrimaryUserDaily` row and `Collection` state row dated more than `RetentionDays` before the last collected date is deleted. This includes days left incomplete by failed collections. Keep retention greater than the analysis window; 35 days provides seven days of recovery margin.
- **Analyzer (`AuditRetentionDays`, default 180):** at the end of each weekly run, including preview runs and failed analyses, `PrimaryUserAudit` partitions and `AnalysisRuns` summaries older than `AuditRetentionDays` are deleted while the analysis lock is still held. A failed cleanup is reported as a warning and does not change the run result.

The deployed weekly schedule does not pass `AuditRetentionDays`, so the default applies. To keep a different period, add the parameter to the `RepairPrimaryUser-WeeklyAnalysis` schedule link or start the runbook manually with it.

## Weekly analysis

Assignments are applied by default. Run a preview manually before enabling production changes or after changing policy:

```powershell
Start-AzAutomationRunbook `
    -ResourceGroupName 'rg-repair-primary-user' `
    -AutomationAccountName '<automation-account>' `
    -Name 'Repair-PrimaryUserAssignments' `
    -Parameters @{
        StorageAccountName = '<storage-account>'
        Preview = $true
    }
```

Preview recommendations are written to `PrimaryUserAudit` and no Intune assignment request is submitted. The scheduled run omits `Preview` and therefore applies changes.

`Preview` is a Boolean runbook input, defaulting to `false`. Select `true` in the portal to preview, or use `-Preview $true` when invoking the script directly.

The analyzer:

1. Acquires an Azure Table lock to prevent overlapping weekly runs.
2. Verifies all expected collection states.
3. Aggregates daily device/user counts.
4. Pages company-owned Windows Intune devices.
5. Skips unchanged devices.
6. Sends changed assignments in Microsoft Graph batches of at most 20.
7. Retries throttled and transient requests and records each outcome.
8. Deletes audit history older than `AuditRetentionDays`, then releases the lock.

## Monitoring and recovery

- Check Azure Automation job output and errors for both runbooks.
- Inspect the `Collection` partition in `PrimaryUserState` for missing or non-`Complete` dates.
- Recollect a missing date with `CollectionDate` and `ForceRecollect`, then rerun the analyzer.
- Inspect `AnalysisRuns` in `PrimaryUserState` for weekly totals and terminal status.
- Inspect the matching run-ID partition in `PrimaryUserAudit` for device-level recommendations and failures.
- A stale analysis lock is replaced after 12 hours by default. Lower `StaleLockHours` only when a complete analysis is known to finish sooner.

The analyzer fails closed: missing daily data, Graph retrieval failures, or lock conflicts stop the run before new assignments are submitted. Individual batch failures are audited and do not hide successful updates from the same run.

## Cost and scale

Storage contains compact aggregates rather than raw audit events. Approximate daily row count is the number of distinct device/user combinations that signed in that day, not the number of sign-in events. Azure Automation and Microsoft Graph limits still vary by tenant size; review job memory, duration, throttling, and table growth before broad production rollout.

## Removal

Unregister and remove the two schedules, remove the two Automation runbooks, revoke the managed identity's two Graph app-role assignments, and delete the resource group if it contains only this solution. Deleting the resource group permanently removes aggregate and audit history.

## Change history

See [changelog.md](changelog.md).
