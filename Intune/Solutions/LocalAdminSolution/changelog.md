# Changes

## 2026

### 8th of September

* Renamed the detection, remediation, and stress-data scripts to use the `LocalAdminSolution` name and updated all repository references.
* Added interval-based detection: applicable devices now remain compliant until `LastSuccessfulRunUtc` under `HKLM:\Software\LocalAdminSolution` is older than the adjustable four-hour default.
* Added successful-run tracking: remediation records the UTC registry timestamp only after all Azure Table uploads complete successfully.

### 7th of September

* Renamed the solution folder to `LocalAdminSolution` and updated repository navigation links.
* Normalized local administrator rows: LocalAdminCollection now stores `PrincipalID`, `PrincipalType`, `MembershipType`, and optional `AssignedThroughGroupID` instead of mutually exclusive `UserID` and `GroupID` fields.
* Preserved access paths: direct assignments and one-level Active Directory group-derived assignments now remain independently visible, removable, and reactivatable with stable numeric RowKeys.
* Expanded resolved reports: live HTML, generated HTML, CSV, and Excel now show Membership type and Added through group with SID-safe detail links.
* Improved live HTML grouping: directly assigned groups now appear as nested, initially collapsed sections within each computer, while direct users remain visible and duplicate direct/transitive user paths stay separate.
* Expanded stress coverage: deterministic data now includes direct users and groups, nested group observations, direct-plus-transitive users, and users assigned through multiple groups while keeping Entra groups direct-only.

### 6th of September

* Added automated deployment: Deployment/main.bicep - creates the Storage account, three Azure Tables, Automation account identity, optional Table CORS configuration, and lookup-table-scoped data role assignments.
* Added deployment bootstrap: Deployment/Deploy-LocalAdminReporting.ps1 - performs interactive Azure and Graph authentication, deploys resources, imports and schedules the reconciliation runbook, and idempotently grants its Graph application permissions.
* Added explicit SAS delivery controls: the bootstrap creates separate endpoint and reporting tokens and lets the user save a protected plaintext file, confirm one-time console output, or withhold token output. Token values are excluded from logs and generated secret files are ignored by Git.
* Fixed managed identity permission deployment: the Graph service-principal lookup now preserves the object ID when appending its query string.
* Added reporting frontend selection: Live HTML now configures Table CORS automatically, while generated HTML and Excel remove browser CORS configuration.
* Reduced reconciliation frequency: new and existing deployments use a four-hour Automation schedule by default.
* Expanded end-to-end testing: stress data supports exact 5,000-row increments through 20,000 rows and can include specified Microsoft Entra group object IDs; reconciliation output identifies resolved and unresolved Entra objects.
* Fixed protected token replacement: overwriting a token file now retains its existing owner and replaces access rules without requiring `SeSecurityPrivilege`.
* Added temporary Bicep support: missing Bicep can be downloaded with user approval, verified as Microsoft-signed, used only for the current process, and removed when deployment ends without requiring elevation in standard environments.

### 3rd of September

* Reduced lookup writes: Remediation/Remediate-LocalAdminSolution.ps1 - skips unchanged lookup rows and submits only newer, differing AD/local observations as candidate properties with ETag conflict protection.
* Added canonical reconciliation: Runbooks/Resolve-LocalAdminLookupNames.ps1 - uses an Azure Automation managed identity and Microsoft Graph to resolve Entra names, promote validated candidates, and consolidate immutable RowKeys with create-before-delete ordering.
* Made reports deterministic: HTML and Excel readers - select one canonical lookup row per SID while legacy duplicates exist and do not display unpromoted candidates.
* Expanded stress coverage: New-LocalAdminSolutionStressTestData.ps1 - emits lookup observation metadata and optional fallback, rename-candidate, and legacy-duplicate scenarios.
* Documented migration and permissions: README.md - separates endpoint SAS rights from the runbook identity's Graph and Azure Table data roles.

### 2nd of September

* Added opt-in connection persistence: HTML/LocalAdminResolvedLive.html - saves a validated storage account name and read-only SAS in browser local storage only after a successful refresh, restores fields without automatically querying Azure, and provides an immediate forget action.
* Hardened live reporting: HTML/LocalAdminResolvedLive.html - validates required Table, Object, Read, HTTPS, and future-expiry SAS settings and disables referrer transmission.
* Documented browser-storage security: README.md - described same-origin script and shared-profile risks, dedicated-origin guidance, and snapshot isolation from saved connections.
* Improved remediation reliability: Remediation/Remediate-LocalAdminSolution.ps1 - sends Azure Table JSON as explicit UTF-8 so localized account names remain consistent between entity URIs and request bodies.
* Improved remediation diagnostics: Remediation/Remediate-LocalAdminSolution.ps1 - reports the failing Azure table, entity identity, HTTP status, and Azure response body without exposing the SAS token.
* Improved Entra administrator collection: Remediation/Remediate-LocalAdminSolution.ps1 - resolves SIDs directly from WinNT member objects and reports contextual details for unresolved entries.
* Improved Entra group naming: Remediation/Remediate-LocalAdminSolution.ps1 - reads cached IdentityStore display names when available and stores the SID as the group name when translation is unavailable.
* Updated device-name validation: Remediation/Remediate-LocalAdminSolution.ps1 - accepts up to 63 Unicode code points and rejects malformed surrogate sequences.

### 31st of August

* Added grouping: HTML/LocalAdminResolvedLive.html - enabled computer-object grouping by default with accessible, initially collapsed headers while preserving search, filters, pagination, detail links, and CSV exports.
* Improved ordering: HTML/LocalAdminResolvedLive.html - ordered grouped results by computer name and defaulted ungrouped results to computer name followed by entry number.
* Fixed grouped pagination: HTML/LocalAdminResolvedLive.html - made page size and navigation count computer objects instead of their administrator entries when grouping is enabled.
* Published demo: HTML/LocalAdminResolvedDemo.html - linked the generated [synthetic demonstration](https://intune.best/LocalAdminResolvedDemo.html).

### 30th of August

* Add: README.md - documented solution deployment, reporting options, data schema, and operational guidance.
* Add: Excel/LocalAdminResolved.pq - added the resolved local-administrator summary query for Excel.
* Add: HTML/LocalAdminResolvedDemo.html - added a standalone demonstration of the HTML report with sample data.
* Add: HTML/.gitignore - excluded the locally generated HTML snapshot from source control.

### 29th of August

* Introduced: New-LocalAdminSolutionStressTestData.ps1 - added deterministic, schema-valid Azure Table stress-test data generation.
* Expanded: New-LocalAdminSolutionStressTestData.ps1 - increased the default dataset to 10,008 main rows across 834 synthetic computers.
* Enriched demo data: New-LocalAdminSolutionStressTestData.ps1 - distributed removed states, localized Administrators group names, and varied report timestamps across synthetic entries.
* Improved: New-LocalAdminSolutionStressTestData.ps1 - reused bounded HTTP connections for reliable high-volume Azure Table operations.
* Added cleanup: New-LocalAdminSolutionStressTestData.ps1 - added commands to remove generated stress-test entities or clear every entity from all three solution tables.
* Added HTML reporting: HTML/Export-LocalAdminResolvedHtml.ps1 and HTML/LocalAdminResolvedLive.html - added standalone snapshot and live Azure reports with resolved names, linked details, filters, sorting, pagination, and CSV export.
* Added manual refresh: HTML/LocalAdminResolvedLive.html - added an explicit Azure refresh button, disabled repeated refresh requests while loading, and displayed a patience warning during pagination.
* Preserved navigation state: HTML/LocalAdminResolvedLive.html - restored the previous search, filters, sorting, pagination, and scroll position after returning from user or group details.
* Enhanced: Excel/GetAzureAdminTable.pq - followed Azure Table continuation headers so Power Query retrieves results beyond the first 1,000 entities.
* Added reporting: Excel/AdminUserDetails.pq, Excel/AdminGroupDetails.pq, and Excel/LocalAdminLinkMap.pq - added user and group detail views with exact SID-based link mapping.
* Added navigation: Excel/LocalAdminLinks.bas - added clickable links from the resolved summary to matching user and group details.
* Organized: Excel and HTML reporting assets - moved format-specific files into dedicated `Excel` and `HTML` subfolders.
* Organized remediation: Detect-LocalAdminSolution.ps1 and Remediate-LocalAdminSolution.ps1 - moved both Intune scripts into the `Remediation` subfolder.
* Relocated the remediation and reporting files into `Intune/Solutions/LocalAdminSolution`.

### 20th of August

* Released: Remediate-LocalAdminSolution.ps1 - updated the remediation to version 2.0.
* Restructured: Remediate-LocalAdminSolution.ps1 - changed Azure Table entities to use SID-backed partition keys and schema-valid string row keys.
* Added lookups: Remediate-LocalAdminSolution.ps1 - added user and group lookup entities with principal source information.
* Improved reconciliation: Remediate-LocalAdminSolution.ps1 - retained missing administrator entries with `Removed` set to `1` and reactivated entries when they returned.
* Strengthened validation: Remediate-LocalAdminSolution.ps1 - added entity validation, typed UTC dates, and insert-or-replace writes.

### 7th of August

* Initial release: Remediate-LocalAdminSolution.ps1 - added the local Administrators collection remediation.
