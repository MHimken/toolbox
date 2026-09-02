# Changes

## 2026

### 2nd of September

* Added opt-in connection persistence: HTML/LocalAdminResolvedLive.html - saves a validated storage account name and read-only SAS in browser local storage only after a successful refresh, restores fields without automatically querying Azure, and provides an immediate forget action.
* Hardened live reporting: HTML/LocalAdminResolvedLive.html - validates required Table, Object, Read, HTTPS, and future-expiry SAS settings and disables referrer transmission.
* Documented browser-storage security: README.md - described same-origin script and shared-profile risks, dedicated-origin guidance, and snapshot isolation from saved connections.
* Improved remediation reliability: Remediation/Remediate-Write-AdminsToAZTable.ps1 - sends Azure Table JSON as explicit UTF-8 so localized account names remain consistent between entity URIs and request bodies.
* Improved remediation diagnostics: Remediation/Remediate-Write-AdminsToAZTable.ps1 - reports the failing Azure table, entity identity, HTTP status, and Azure response body without exposing the SAS token.

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

* Introduced: New-WriteAdminsStressTestData.ps1 - added deterministic, schema-valid Azure Table stress-test data generation.
* Expanded: New-WriteAdminsStressTestData.ps1 - increased the default dataset to 10,008 main rows across 834 synthetic computers.
* Enriched demo data: New-WriteAdminsStressTestData.ps1 - distributed removed states, localized Administrators group names, and varied report timestamps across synthetic entries.
* Improved: New-WriteAdminsStressTestData.ps1 - reused bounded HTTP connections for reliable high-volume Azure Table operations.
* Added cleanup: New-WriteAdminsStressTestData.ps1 - added commands to remove generated stress-test entities or clear every entity from all three solution tables.
* Added HTML reporting: HTML/Export-LocalAdminResolvedHtml.ps1 and HTML/LocalAdminResolvedLive.html - added standalone snapshot and live Azure reports with resolved names, linked details, filters, sorting, pagination, and CSV export.
* Added manual refresh: HTML/LocalAdminResolvedLive.html - added an explicit Azure refresh button, disabled repeated refresh requests while loading, and displayed a patience warning during pagination.
* Preserved navigation state: HTML/LocalAdminResolvedLive.html - restored the previous search, filters, sorting, pagination, and scroll position after returning from user or group details.
* Enhanced: Excel/GetAzureAdminTable.pq - followed Azure Table continuation headers so Power Query retrieves results beyond the first 1,000 entities.
* Added reporting: Excel/AdminUserDetails.pq, Excel/AdminGroupDetails.pq, and Excel/LocalAdminLinkMap.pq - added user and group detail views with exact SID-based link mapping.
* Added navigation: Excel/LocalAdminLinks.bas - added clickable links from the resolved summary to matching user and group details.
* Organized: Excel and HTML reporting assets - moved format-specific files into dedicated `Excel` and `HTML` subfolders.
* Organized remediation: Detect-Write-AdminsToAZTable.ps1 and Remediate-Write-AdminsToAZTable.ps1 - moved both Intune scripts into the `Remediation` subfolder.
* Relocated: Write-AdminsToAZTable solution - moved the remediation and reporting files into `Intune/Solutions/Write-AdminsToAZTable`.

### 20th of August

* Released: Remediate-Write-AdminsToAZTable.ps1 - updated the remediation to version 2.0.
* Restructured: Remediate-Write-AdminsToAZTable.ps1 - changed Azure Table entities to use SID-backed partition keys and schema-valid string row keys.
* Added lookups: Remediate-Write-AdminsToAZTable.ps1 - added user and group lookup entities with principal source information.
* Improved reconciliation: Remediate-Write-AdminsToAZTable.ps1 - retained missing administrator entries with `Removed` set to `1` and reactivated entries when they returned.
* Strengthened validation: Remediate-Write-AdminsToAZTable.ps1 - added entity validation, typed UTC dates, and insert-or-replace writes.

### 7th of August

* Initial release: Remediate-Write-AdminsToAZTable.ps1 - added the local Administrators collection remediation.
