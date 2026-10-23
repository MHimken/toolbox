# Changes

## 2026

### 21st of October

* Added local-first principal and assigned-through group lookup to rule proposals. SAS-only searches remain offline; authorized signed-in searches fall back to Entra only after no local match and an 800 ms typing pause. Results are bounded and cached in memory, obsolete searches are cancelled, and synced identities expose separate Entra and AD SID choices.
* Added a protected, rate-limited BFF identity lookup endpoint and opt-in `-ConfigureBffDirectoryLookup` permission grants for the Function managed identity. No new SPA Graph scopes or npm dependencies are required.
* Added informational principal name/UPN snapshots to SID-only rules and governance displays/exports.
* Preserved assigned-through group SIDs in review rows and normalized collector source codes (`L`, `E`, `A`) so selected identities and group-scoped previews match collected inventory correctly.
* Added Users/Groups identity drill-downs for loaded computers, membership paths and related rules; snapshot exports retain this read-only feature without directory calls.

### 20th of October

* Fixed generated snapshots failing to start: the exporter did not provide the table-layout helpers, `normalizeSidInput`, or `saveRecoveryProfile` that LiveHTML now imports. Each module is now bundled in its own scope, with aliased imports, and export fails closed on unresolved imports, missing template markers, or remaining external resources.
* Hardened CSV export against spreadsheet formula injection by prefixing text that begins with `=`, `+`, `-`, `@`, tab, or carriage return. Added CSV quoting and Unicode tests.
* Hardened Entra deployment against app-registration and security-group display-name collisions: Create mode now fails closed unless existing IDs are checkpointed as deployment-owned; privileged groups are never adopted by name. The BFF now requires access-token `azp`/`appid` to match the configured SPA client ID.
* Added clickable rule-match previews for proposers and approvers, including governance-row and approval-confirmation summaries. The read-only preview lists matching loaded review entries without losing the underlying form and explains the limits of the scope estimate.
* Fixed sign-out popups remaining open and leaving the main report signed in: state-only logout callbacks now reach the MSAL redirect bridge, and logout explicitly returns the popup to the configured SPA redirect URI without reloading the main report.
* Moved Sign out into the title bar, visible once a Microsoft Entra account is signed in. Cloud profile reload remains in Settings.
* Fixed pasted principal and assigned-through group SIDs containing Unicode hyphens being rejected. Proposal validation, match previews and submission now use ASCII SID separators.
* Documented that page reload clears the in-memory report sign-in and Admin mode without signing out the Microsoft Entra browser session.

### 19th of October

* Fixed title-bar button hover contrast without changing disabled controls on hover. Added a collapsible box showing only the current sign-in/Admin-mode status, with a local up/down arrow beside the timers and automatic expansion on errors. The arrow appears without a full-width bar.
* Moved Microsoft Entra sign-in, Enter Admin mode and their status messages to the top right of the title bar, and moved the matching-rows count into the report mode bar. A dark-red Retry button replaces the popup warning bar. Cloud profile reload and sign-out remain in Settings.
* Added an explicit Retry authentication control for closed or abandoned MSAL 5 popups, including Admin-mode step-up. Retrying cancels the previous bridge wait without reloading the report, and superseded results cannot replace the active attempt.
* Kept the page header and Admin-mode controls visible while scrolling, and added a live idle-timeout countdown that resets on activity without extending the absolute Admin-mode expiry.
* Added a total-timeout countdown alongside the idle timer, using the backend's session expiry so activity cannot reset it.

### 18th of October

* Fixed Admin-mode entry returning HTTP 404: Azure Functions reserves routes beginning with `admin`, so the session route is now `/v1/sessions/admin`. Updated the browser client and API contract, and made deployment readiness check both profile and Admin-mode routes.
* Added `-RepublishBff` to publish backend code on a resumed deployment without rerunning completed infrastructure or SAS stages, while preserving existing Function App settings.
* The deployment now creates four Admin-mode Entra security groups (`sg-<name>-governance-readers`, `-governance-approvers`, `-governance-selfapprovers`, `-action-operators`) and assigns the matching API app roles. Added `-SkipAdminGroups` and `-AdminGroupNamePrefix`. Groups created by the deployment are removed by `-RemoveDeployment`; reused groups are preserved.
* `-AppRegistrationMode Create` now adds the `LocalAdmin.*` app roles automatically.
* Derived Azure names follow the [Azure Periodic Table](https://www.azureperiodictable.com/) abbreviations: `aa-` for the Automation account, `asp-` for the Function plan, and `appi-` for Application Insights. Existing deployments keep their recorded names; `-FunctionPlanName` and `-ApplicationInsightsName` pin existing names when using `-ForceRecreate`.
* Added an after-deployment report (Markdown and JSON) that lists the tenant, subscription, deployed resources, naming checks, identities and role assignments, endpoints, app registrations, groups, and remaining manual steps. Added `-DeploymentReportPath`.
* Deployment checkpoint version 4 records the plan, Application Insights, and group names.
* Added `-InstallTemporaryNode`: when npm is missing, the deployment downloads a checksum- and signature-verified Node.js 22 LTS into TEMP to build the BFF and removes it afterwards.

### 12th of October

* Implemented Admin mode: backend-enforced API app roles, Conditional Access authentication-context step-up (default `c1`) via MSAL claims challenge, a 30-minute absolute and 15-minute idle limit, and audited entry/exit.
* Added governance rule proposals (idempotent) with a preview editor, and ETag-protected approve/reject/revoke with four-eyes approval plus an opt-in `LocalAdmin.Governance.SelfApprove` role for small tenants.
* Added action listing and operator cancellation endpoints.
* Added `-ConfigureApiAppRoles`, `-AdminAuthContextId`, and `-AdminSessionMaxMinutes` to the deployment script, Admin-mode Function settings, and Function access to `LocalAdminAllowRules`.

### 9th of October

* Recognized Azure's automatically created Application Insights Smart Detection action group during teardown, explained why it remains, and required separate confirmation before removing it and continuing resource-group deletion.
* Replaced token-file `Set-Acl` hardening with DACL-only access control that does not require `SeSecurityPrivilege`, and protected a temporary file before writing credentials so failed exports no longer delete an existing destination.
* Added the configured SPA redirect URI to public runtime configuration so MSAL uses the exact Entra registration value instead of deriving `/` from an IIS default-document URL.
* Removed the browser-supplied BFF correlation header; Azure Functions platform CORS preflight handling does not allow that custom header, while the BFF continues to generate and return correlation IDs.
* Escaped the CSV filename field's literal hyphen for modern HTML pattern Unicode `v`-mode parsing, preventing a console error when opening Settings.
* Prevented cloud-profile application from invoking the table renderer while Settings or Usage guidance is active, avoiding an undefined `rows` error after signing in.
* Made the recovery-profile remember checkbox persist or remove the active recovery code immediately, restored its checked state on reload, and clarified when a future generated or imported code will be stored.
* Replaced browser-native number datalists in Settings with free numeric text fields and consistently styled 30/60/90/180 quick-select buttons.
* Aligned the live report with its visual and accessibility conventions by using shared color tokens, restrained control rounding, announced recovery status, accessible table sort state, explanatory disabled-control titles, and hiding row totals on static panels.
* Added ordered multi-column table sorting. Click a column once for ascending order, twice for descending order, and three times to remove it; additional columns become tie-breakers in selection order.
* Added per-view resizable and reorderable table columns, readable default SID/ID widths, keyboard equivalents, cloud/local profile persistence, CSV order matching, and a reset-columns action. Saved order now survives normalization while newly introduced columns append safely.
* Made **Remember connection on this device** persist validated inventory and governance SAS credentials immediately when selected, and remove them immediately when cleared.

### 8th of October

* Added state-driven deployment teardown with `-RemoveDeployment`, optional empty resource-group removal, safe preservation of reused Entra app registrations, and a documented resource inventory.
* Excluded generated logs and npm restore directories from Git, documented the pre-commit cleanup boundary, and added MSAL vendor provenance plus the required MIT license notice.

### 2nd of October

* Added a non-secret local deployment checkpoint that records each completed deployment stage and the effective deployment configuration.
* Added authenticated Azure-state verification and explicit resume confirmation before recorded configuration replaces supplied parameters.
* Added stage-aware retries that skip completed app-registration, Bicep, Graph-permission, runbook, BFF, SAS, and host-configuration work.
* Added `-ForceRecreate` for intentionally replacing the checkpoint and restarting deployment.
* Clarified token-file destination prompting and made file/ACL failures terminate without masking the original error.
* Added the MSAL 5 redirect bridge so popup authorization responses are broadcast back to the report and the completed popup closes without starting the report application inside it.
* Set `Cross-Origin-Opener-Policy: same-origin-allow-popups` in the IIS and Apache examples so Microsoft Entra popup authentication can return to the report window.
* Bound the browser Fetch API to the global window before profile requests, preventing an `Illegal invocation` after successful Microsoft Entra sign-in.
* Configured Azure Functions platform CORS for the exact BFF origins so host-handled OPTIONS responses include the required allow-origin, method, and header metadata.

### 1st of October

* Finalized the governance API contract for immutable profile ownership, rule validation and precedence, action states, optimistic concurrency, idempotency, and append-only auditing.
* Added a shared browser/snapshot rule evaluator with explicit governance allow, governance deny, equal-specificity conflict, personal acknowledgement, pending, expired, and unmatched outcomes.
* Preserved policy classification separately when device freshness or Entra-presence conditions take priority in the Review queue.
* Added focused Node tests for owner keys, rule precedence, action transitions, and fail-closed ETag handling.
* Replaced the descriptive Settings placeholder with editable landing-view, paging, grouping, time-display, freshness, review-window, and CSV filename preferences.
* Added Web Crypto recovery-profile generation and import using 256-bit base64url secrets and SHA-256 owner keys, with explicit consent before browser persistence and a local forget operation.
* Kept recovery operations disabled in generated snapshots and documented that local forgetting does not revoke a cloud credential.
* Added an Azure Functions TypeScript BFF foundation with strict Entra JWT validation, immutable owner derivation, recovery authentication, managed-identity Azure Table access, exact-origin CORS, structured errors, and correlation IDs.
* Added owner-isolated profile read/create/update, ETag enforcement, recovery rotation/revocation, append-only audit writes, and explicit partial-failure reporting across non-transactional tables.
* Added strict TypeScript builds and focused backend tests for configuration, recovery ownership, profile isolation, ETag conflicts, rotation, revocation, settings validation, and audit failures.
* Added public LiveHTML runtime configuration for Storage account defaults, optional BFF/SPA identifiers, host-locked fields, and automatic manual-entry fallback.
* Added capability gating so Governance and Admin mode remain visibly disabled with explanations until their account, credential, BFF, and Entra prerequisites are configured.
* Added IIS and Apache hardening examples that allow public `config.json`, disable directory browsing, and deny private configuration and common secret-file paths.
* Added an IIS ARR/URL Rewrite reverse-proxy example for presenting a separately hosted Azure Functions BFF under the same report origin.
* Added explicit wildcard BFF CORS support with exact-origin guidance and documented why browser-visible values cannot be securely obfuscated.
* Added optional Azure Functions BFF deployment with Function hosting, Application Insights, managed-identity table RBAC, API/SPA app-registration creation or reuse, package publication, readiness validation, and generated LiveHTML configuration.
* Added the `LocalAdminAuditRecords` table to the Azure deployment.
* Expanded stress-test data with optional deterministic Governance and Review scenarios for human validation.
* Fixed deployment authentication to use normal interactive Azure and Microsoft Graph browser sign-in instead of forcing an unsupported device-code parameter, while preserving caller-owned Graph sessions.
* Split API scope creation and SPA pre-authorization into ordered Graph updates and added detailed Graph validation errors for failed app-registration changes.
* Fixed Linux Consumption BFF publication by replacing unsupported Kudu web-app ZIP publication with a private Blob package URL, container-scoped managed-identity access, trigger synchronization, and readiness validation.

### 9th of September

* Improved synthetic data realism: stress generation now defaults to deterministic fictional international device, user, UPN, and group names while preserving exact row counts and direct/transitive access paths.
* Added naming compatibility: `-LegacyNaming` reproduces the original stress names, and all newly generated entities carry explicit synthetic profile markers.
* Improved cleanup compatibility: stress removal now uses explicit markers and stable principal SIDs while retaining legacy prefix detection and protecting identities referenced by non-synthetic inventory.

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
* Updated the isolated deployment defaults to use the requested `AA-` Automation account and `rb-` runbook naming prefixes.
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

### 24th of September

* Started the fresh-deployment interactive implementation in an isolated solution copy.
* Added `LocalAdminDevices`, collector heartbeat and deterministic inventory hashing.
* Added paged Entra or Intune device synchronization to the reconciliation runbook.
* Split the maintained report into HTML, CSS, application, connection, data service, and storage modules.
* Added Stale devices, Review, Governance, Settings, and Usage guidance surfaces.
* Separated governance tables into a dedicated Storage account to protect them from the endpoint account SAS.
* Updated the exporter to assemble a self-contained snapshot from split source assets.
* Added fresh deployment resources and Graph permissions for Entra and Intune device observations.
* Replaced the device-source toggle with independent Entra, Intune, and collector observations.
* Added source-owned `E_`, `I_`, and `C_` rows and report correlation through Entra device ID.
* Separated Entra registration, Intune management, and collector freshness states in the report.
* Added managed-identity token role validation and refresh retries for newly granted Graph permissions.
