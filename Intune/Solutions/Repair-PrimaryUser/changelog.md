# Changes

## 2026

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
