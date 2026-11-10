# Changes

## 2026

### 10th of November

* Analyzer previews now list example devices that would change. The new `PreviewDeviceCount` parameter (0 to 1000, default 50) sets how many. Each row shows device name, Intune device ID, current and new primary user, both users' sign-in counts, the new user's share of device sign-ins, distinct users, the new user's latest sign-in, last Intune sync, and change reason. Every run also prints the number of changes per reason.
* Audit rows now also store both users' UPNs, the current user's sign-in count, total device sign-ins, distinct users, and a `ChangeReason` for changed devices.
* The collector now stores the user principal name from each user's latest sign-in in `PrimaryUserDaily`. Older rows show user IDs in the preview until those dates are recollected with `ForceRecollect`.
* The collector has a new `MinimumSignInCount` parameter (default 1). A day below it is saved as `LowSignInCount` instead of `Complete`, with a warning. The range continues, then the job fails and lists the affected dates. Rerunning the range collects those dates again; `MinimumSignInCount 0` accepts an expected empty day. Complete dates from earlier versions below the minimum are also collected again.
* The analyzer's incomplete-collection error now shows each date's collection status.

### 9th of November

* A deployment resume no longer requires the runbook source files when the checkpoint shows they were already imported. Those runbooks are verified as published instead, and a warning reports that content changes were not checked. A runbook missing from both Azure and disk still stops the deployment.

### 3rd of November

* The deployment script now finds each runbook in `..\Runbooks` first, then beside the deployment script. A missing runbook stops the deployment before the checkpoint changes and lists both checked paths.
* Fixed a strict-mode `id` property error during resource inventory: `Invoke-AzRestMethod` error responses are now checked by HTTP status. Not-found codes, including `ParentResourceNotFound` for tables of a missing storage account, mark resources as missing. Other errors stop with the HTTP status and response.
* Accounts without `Microsoft.Authorization/roleAssignments/write`, such as `Contributor`, can now deploy. `main.bicep` has a new `assignTableRoles` parameter. When ARM denies the table role assignments, or reports them as already existing, the script redeploys without them. It finishes the remaining stages and prints the manual `Storage Table Data Contributor` assignment steps. `-Resume` verifies those assignments before marking the deployment complete.

### 24th of October

* Sped up table deletes: both runbooks now delete rows in Table Storage entity group transactions of up to 100 rows, query only `PartitionKey` and `RowKey`, and stream results page by page. Batches rolled back by an already-deleted row fall back to single deletes that ignore HTTP 404.
* Collector retention now removes every expired aggregate and collection state row with one range query, including days left incomplete by failed collections. It runs once per job relative to the last collected date instead of after every day, and follows all result pages.
* Added `AuditRetentionDays` (default 180) to the analyzer. Expired `PrimaryUserAudit` partitions and `AnalysisRuns` summaries are deleted at the end of each run while the analysis lock is held; cleanup failures only produce a warning.
* Added `Tests\TableRetention.Tests.ps1`.

### 23rd of October

* Fixed analysis lock creation failing with HTTP 400: Table Storage Insert Entity requests must not include `If-None-Match`. Duplicate inserts still fail with HTTP 409 and stop competing analyses.
* Changed runbook inputs `Preview` and `ForceRecollect` from switches to Booleans for Azure Automation. Both default to false; direct PowerShell callers must supply an explicit value.

### 22nd of October

* Added optional inclusive `CollectionEndDate` ranges to the daily collector. Days run sequentially with separate aggregates and completion states; failed ranges can be resumed by rerunning the same dates, while scheduled single-day collection remains unchanged.
* Fixed checkpoint resource lookups selecting an unsupported API version for table-scoped role assignments. Inventory reads now call ARM directly with each resource provider's API version from the Bicep template, avoiding Az.Resources API-version negotiation.
* Added resumable deployment with an atomic local JSON checkpoint containing configuration, discovered Azure resource IDs, the managed-identity principal ID, and per-stage completion.
* Added `-Resume`, `-DeploymentStatePath`, and `-ForceRecreate`; continuation validates Azure resources, published runbooks, and schedule links, preserves completed schedules, and rechecks Graph permissions.
* Existing deployments without checkpoints can be reconciled with the original parameters using incremental Bicep deployment. Local template and runbook hashes invalidate changed stages.
* Renamed `$filter` variables, which share their name with the PowerShell `filter` keyword, to `$partitionFilter`, `$expiredStateFilter`, `$signInFilter`, and `$managedDeviceFilter`.
* All three scripts now save the original `$ErrorActionPreference` and restore it in a `finally` block.
* Fixed deployment failing during the Graph permission grant: `$ManagedIdentityPrincipalId?` was parsed as a variable name including `?`.
* Added optional temporary Bicep bootstrap to deployment: reuse Bicep on PATH or approve a Windows download with `-InstallTemporaryBicep` or an interactive prompt, verify its Microsoft signature, and restore PATH and clean up on exit.
* Fixed both runbooks failing under `Set-StrictMode` on the last Graph page, where `@odata.nextLink` is absent.
* Fixed retry handling: `Retry-After` is now read from the typed `HttpResponseMessage` header, and errors without an HTTP response no longer mask the original exception.
* Transient network failures and timeouts are now retried alongside HTTP 429 and 5xx responses.
* Graph batch error messages are read safely when a failed response has no error body.

### 7th of September

* Added daily collection: `Runbooks/Collect-PrimaryUserSignInData.ps1` streams one completed UTC day of successful Windows sign-ins into retry-safe Azure Table aggregates.
* Added weekly repair: `Runbooks/Repair-PrimaryUserAssignments.ps1` validates 28 complete days, calculates deterministic primary users, supports preview, submits Graph batches, and audits outcomes.
* Added automated deployment: `Deployment/main.bicep` creates Storage, three Azure Tables, an Automation Account managed identity, and table-scoped role assignments.
* Added deployment bootstrap: `Deployment/Deploy-RepairPrimaryUser.ps1` imports and publishes both runbooks, creates daily and weekly UTC schedules, and grants the required Graph application permissions.
* Added implementation and operations documentation in `README.md`.
