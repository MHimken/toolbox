# Local administrator reporting

This package builds Excel and interactive HTML views over the inventory, lookup, device, and governance Azure Tables used by the solution. Detection and remediation scripts are stored in the `Remediation` folder, Excel assets in `Excel`, and HTML assets in `HTML`.

## Interactive implementation status

This isolated fresh-deployment variant starts the `LocalAdminSolution-plan.md` implementation without changing the original solution. The current milestone includes:

- Split Live HTML source: `HTML\index.html`, `styles.css`, `bootstrap.js`, `app.js`, `connection.js`, `dataService.js`, and `storage.js`.
- `LocalAdminDevices` source-owned Entra (`E_`), Intune (`I_`), and collector (`C_`) observations.
- Deterministic collector inventory hashing. Unchanged runs update only the device heartbeat.
- Microsoft Graph synchronization of both Entra `devices` and Intune `managedDevices`.
- Stale devices, Review, Governance, Settings, and Usage guidance report tabs.
- Read-only governance display and contract-based SID/exact-name rule evaluation.
- A versioned governance API contract with owner-key rules, allow/deny precedence, action states, ETag concurrency, idempotency, and audit requirements.
- Editable local report settings and validated 256-bit recovery-profile generation/import with explicit browser-storage consent.
- An Azure Functions TypeScript BFF foundation for Entra/recovery authentication, owner-isolated cloud profiles, ETag concurrency, managed-identity Table access, recovery rotation/revocation, and audit records.
- Separate inventory and governance Storage accounts so the endpoint write SAS cannot modify allow rules or review history.
- A self-contained generated snapshot assembled from the split source files.

Admin mode requires the BFF, Entra sign-in, an assigned `LocalAdmin.*` API app role, and a Conditional Access policy targeting the authentication context (default `c1`). It enables governance rule approval/rejection/revocation (four-eyes unless `LocalAdmin.Governance.SelfApprove` is assigned) and operator cancellation; any signed-in user with a governance role can propose rules from the Review view. Admin mode ends after 15 idle minutes, 30 minutes after step-up, or on sign-out/account change. Endpoint and directory changes are not executed. Browser-driven profile writes and Entra SPA sign-in become available when the protected backend is deployed and the generated public configuration is hosted with the LiveHTML. Visible disabled controls document any missing configuration or integration boundary. See [Admin mode Conditional Access setup](#admin-mode-conditional-access-setup).

Local recovery-profile generation and import prepare an owner identity and synchronize settings when the BFF is configured. **Forget this browser** removes only the local copy and does not revoke the cloud credential.

The backend source and local development instructions are in [`Backend\README.md`](Backend/README.md). The deployment script can create or reuse its app registrations, deploy the Function App and audit table, assign managed-identity access, publish the package, and generate the browser configuration.

The backend contract to implement is defined in [`API-CONTRACT.md`](API-CONTRACT.md). The browser uses the matching `HTML\apiContract.js` evaluator for read-only classification, but browser results never authorize a write or privileged action.

The repository does not contain a Node.js runtime. `Backend\node_modules` and `HTML\node_modules`
are local npm restore directories and are excluded from Git. Keep the pinned `package-lock.json`
files and restore dependencies with `npm ci`. The two MSAL browser bundles required by the hosted
report are retained under `HTML\vendor`; their version, regeneration procedure, and MIT license are
documented in [`HTML\vendor\README.md`](HTML/vendor/README.md).

This variant supports fresh deployments only. It does not migrate existing table data, infer freshness from `LocalAdminCollection`, or support the previous single-file Live HTML entry point.

## New storage layout

The inventory Storage account contains `LocalAdminCollection`, `AdminUserNames`, `AdminGroups`, and `LocalAdminDevices`. Its endpoint SAS uses Table/Object Read, Add, and Update permissions.

The separate governance Storage account contains `LocalAdminAllowRules`, `LocalAdminUserSettings`, `LocalAdminReviewActions`, and append-only `LocalAdminAuditRecords`. The deployment creates only a read-only governance reporting SAS. No browser or endpoint write credential is created for this account; the Function managed identity receives narrowly scoped profile and audit table access.

The reconciliation managed identity receives contributor access to `AdminUserNames`, `AdminGroups`, and `LocalAdminDevices`. It receives no access to the governance account.

## Device observations and Graph permissions

The scheduled runbook queries both device populations on every successful run:

- Entra observations use `E_<EntraDeviceId>` rows and require `Device.Read.All`.
- Intune observations use `I_<ManagedDeviceId>` rows and require `DeviceManagementManagedDevices.Read.All`.
- Endpoint collector observations use `C_<ComputerSid>` rows and are written only by the remediation script.

The report correlates observations through `EntraDeviceId`, with `ComputerSid` retained for collector and inventory joins. Entra registration, Intune management, and collector reporting are displayed as independent states. The runbook marks a source observation absent only after every page for that specific Graph population completes successfully.

The managed identity also retains `User.Read.All` and `Group.Read.All` for lookup reconciliation.

## CSV export behavior

CSV export uses the current view, search, filters, and sort order. It exports every matching underlying row, regardless of the current page or grouped expansion state. Every field is quoted, embedded quotation marks are doubled, and files use UTF-8 with a BOM and CRLF line endings. Text values beginning with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with an apostrophe so spreadsheet applications do not evaluate endpoint- or proposer-supplied text as formulas. Only the view's defined columns are exported; SAS tokens, access tokens, and Admin-mode controls are never included.

Exports never include SAS values, OAuth tokens, or recovery codes. Treat Review and Governance exports as protected operational and audit data.

## Capabilities

The solution can:

- Inventory direct members of the localized Windows Administrators group and one-level members of directly assigned Active Directory groups on domain-joined, Microsoft Entra joined, and hybrid-joined devices.
- Resolve local users, Active Directory users and groups, and Microsoft Entra principals into three linked Azure Tables.
- Suppress unchanged lookup writes and reconcile renamed principals centrally with an Azure Automation managed identity.
- Preserve previously reported members and mark missing entries as removed.
- Display current Azure data in a standalone live HTML report with search, filters, sorting, pagination, linked details, and CSV export.
- Generate a self-contained HTML snapshot that can be viewed without an Azure connection.
- Load and resolve the same data in Excel Power Query, with optional VBA links to user and group details.
- Generate, remove, and clear deterministic stress-test data for performance and demonstration testing.

## Contents

- [Live Azure HTML report](#live-azure-html-report)
- [Automated Azure deployment](#automated-azure-deployment)
- [Read-only SAS for the live report](#read-only-sas-for-the-live-report)
- [Generated HTML snapshot](#generated-html-snapshot)
- [Workbook setup](#workbook-setup)
- [Clickable names in Excel](#clickable-names-in-excel)
- [SAS security and permissions](#sas-security-and-permissions)
- [Remove an Azure deployment](#remove-an-azure-deployment)
- [Central lookup reconciliation](#central-lookup-reconciliation)
- [Local administrator schema](#local-administrator-schema)
- [Query outputs](#query-outputs)
- [Stress-test data](#stress-test-data)
- [SAS settings for stress testing](#sas-settings-for-stress-testing)
- [Remove stress-test data](#remove-stress-test-data)
- [Clear all table data](#clear-all-table-data)
- [Change history](#change-history)

## Automated Azure deployment

`Deployment\Deploy-LocalAdminReporting.ps1` provides an interactive deployment path for the Azure resources and reconciliation service. It deploys `Deployment\main.bicep`, imports and schedules the PowerShell 7 reconciliation runbook, grants its managed identity the required Microsoft Graph application permissions, and optionally creates separate endpoint and reporting SAS tokens.

The deployment creates:

- One inventory StorageV2 account with `LocalAdminCollection`, `AdminUserNames`, `AdminGroups`, and `LocalAdminDevices`.
- One governance StorageV2 account with `LocalAdminAllowRules`, `LocalAdminUserSettings`, `LocalAdminReviewActions`, and `LocalAdminAuditRecords`.
- An Azure Automation account with a system-assigned managed identity.
- `Storage Table Data Contributor` assignments scoped only to `AdminUserNames`, `AdminGroups`, and `LocalAdminDevices`.
- A Table service CORS rule when the Live HTML frontend is selected.
- A published PowerShell 7.2 reconciliation runbook and four-hour schedule by default.

Run the deployment from PowerShell 7. Azure resource names follow the abbreviations from the [Azure Periodic Table](https://www.azureperiodictable.com/). Names you pass are used as given; derived names use these prefixes:

| Component | Prefix | Example or derived name |
| --- | --- | --- |
| Resource group | `rg-` | `rg-localadmin-prod` (you provide it) |
| Inventory Storage account | `st` | `stlocaladmininv<suffix>` (you provide it) |
| Governance Storage account | `st` | `<inventory storage>gov` |
| Automation account | `aa-` | `aa-<inventory storage without leading st>` |
| Function App | `func-` | `func-localadmin-bff-<suffix>` (you provide it) |
| Function host Storage account | `st` | `stlocaladminfunc<suffix>` (you provide it) |
| App Service plan | `asp-` | `asp-<Function App name without func->` |
| Application Insights | `appi-` | `appi-<Function App name without func->` |
| Entra security groups | `sg-` | `sg-<resource group without rg->-<purpose>` |

The reconciliation runbook name starts with `rb-`. Deployments resumed from an older checkpoint keep their recorded names, so existing resources are never renamed. When rerunning an older deployment with `-ForceRecreate`, pass its existing names with `-AutomationAccountName`, `-FunctionPlanName`, and `-ApplicationInsightsName`; otherwise new resources with the default names are created. Pass `-AutomationAccountName` if the derived Automation account name is outside Azure's 6–50 character limit:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
   -SubscriptionId '<subscription-id>' `
   -TenantId '<tenant-id>' `
   -ResourceGroupName 'rg-localadmin-prod' `
   -Location 'westeurope' `
   -StorageAccountName 'stlocaladmininv<suffix>' `
   -InstallMissingModules `
   -InstallTemporaryBicep
```

At startup, the script lists its prerequisite behavior. Missing PowerShell modules can be installed from PowerShell Gallery for the current user. If Bicep is unavailable on `PATH`, the script requests permission to download the official Microsoft-signed Windows executable to a unique directory under the current user's TEMP folder. `-InstallTemporaryBicep` provides that approval noninteractively. The temporary directory is added only to the deployment process `PATH` and is removed when the script finishes, including after an error.

With `-BackendMode AzureFunctions`, the script uses npm to build the TypeScript BFF and to bundle its production dependencies into the Function package. If npm is unavailable on `PATH`, the script requests permission to download the latest Node.js 22 LTS ZIP (matching the Function runtime) from nodejs.org, verifies it against the published `SHASUMS256.txt` and the OpenJS Foundation signature of `node.exe`, and uses it only for this process. `-InstallTemporaryNode` provides that approval noninteractively. The npm cache is kept in the same temporary directory, which is removed when the script finishes. Node.js is not needed when the BFF publish stage is already complete or no BFF is deployed.

Current-user module installation and temporary Bicep and Node.js downloads do not normally require administrator rights, so the script does not self-elevate. Azure and Microsoft Graph permissions are still required for cloud operations. Environments that block PowerShell Gallery, GitHub release downloads, nodejs.org, the npm registry, TEMP execution, or Microsoft-signed application execution must have those controls adjusted by an administrator or provide the prerequisites centrally.

`-ReportingFrontend LiveHtml` is the default and creates the required Table CORS rule. When `-AllowedCorsOrigins` is omitted, the rule allows `*`. For hosted reports, restrict it to the exact origin, for example `-AllowedCorsOrigins 'https://reports.contoso.com'`. Select `-ReportingFrontend GeneratedHtml` or `-ReportingFrontend Excel` to remove Table CORS because those frontends do not make browser requests to Azure Storage. Use `-SkipGraphPermissionGrant` only when `User.Read.All`, `Group.Read.All`, `Device.Read.All`, and `DeviceManagementManagedDevices.Read.All` will be assigned to the Automation managed identity separately.

LiveHTML deployments write a non-secret `HTML\config.json` next to the report by default. Use `-SkipConfigJson` to suppress it or `-ConfigJsonPath` to choose the web-root destination. The file contains public defaults such as resolved Storage account names, an optional BFF URL, and optional SPA identifiers; it never contains SAS tokens, OAuth tokens, recovery codes, Storage keys, or client secrets. `-LockHostConfig` prevents browser editing of host-provided account names while credentials remain user supplied.

For an already deployed or IIS-proxied BFF, provide:

```powershell
-BffBaseUrl '/localadmin-api/v1' `
-SpaTenantId '<tenant-guid>' `
-SpaClientId '<spa-client-guid>' `
-BffApiScope 'api://<api-app-id>/access_as_user' `
-LockHostConfig
```

These values are written to public `config.json`. To deploy the current profile BFF for validation, select `-BackendMode AzureFunctions` and provide globally unique Function App and Function host Storage names plus the exact hosted LiveHTML URL:

```powershell
-BackendMode AzureFunctions `
-FunctionAppName 'func-localadmin-bff-<suffix>' `
-FunctionStorageAccountName 'stlocaladminfunc<suffix>' `
-AppRegistrationMode Create `
-SpaRedirectUri 'https://reports.contoso.com/localadmin/index.html'
```

This creates or reconciles dedicated API and SPA app registrations without client secrets, exposes the `access_as_user` delegated scope and the four `LocalAdmin.*` app roles, pre-authorizes the SPA, deploys the Function App and Application Insights, grants its managed identity table-level access to `LocalAdminUserSettings` and `LocalAdminAuditRecords`, publishes the reviewed TypeScript package, checks that unauthenticated access is rejected, and writes the resulting public URL and identifiers to `config.json`.

The Linux Consumption Function runs from a ZIP in a private container in its host Storage account. The Function system-assigned managed identity receives `Storage Blob Data Reader` only on that package container; no package SAS is stored in configuration. The deployment uploads a uniquely named package, updates `WEBSITE_RUN_FROM_PACKAGE`, restarts the Function, synchronizes triggers, and waits for the protected endpoint to return the expected unauthenticated response.

With `-BackendMode AzureFunctions`, the deployment also creates four Admin-mode Entra security groups and assigns the API app roles to them:

| Default group | App roles |
| --- | --- |
| `sg-<name>-governance-readers` | `LocalAdmin.Governance.Read` |
| `sg-<name>-governance-approvers` | `LocalAdmin.Governance.Approve` |
| `sg-<name>-governance-selfapprovers` | `LocalAdmin.Governance.Approve`, `LocalAdmin.Governance.SelfApprove` |
| `sg-<name>-action-operators` | `LocalAdmin.Actions.Operate` |

`<name>` is the resource group name without `rg-`. Use `-AdminGroupNamePrefix 'sg-localadmin'` to choose another prefix, or `-SkipAdminGroups` to manage role assignments yourself. An unrecorded group with a matching name is never adopted: deployment fails closed so a pre-created group cannot inherit privileged roles. Rename the collision, choose a unique prefix, or skip group creation and manage assignments yourself. Resumed deployment reuses only groups whose ID and deployment-created ownership are in the checkpoint. The groups have no members; add admins directly or make them eligible through PIM for Groups. Group-based app role assignment requires Microsoft Entra ID P1, and the deploying account needs the Microsoft Graph `Group.ReadWrite.All` permission (for example, the Groups Administrator role). Roles that are missing from an existing API registration are reported and retried on the next run; add them with `-ConfigureApiAppRoles`.

Use `-AppRegistrationMode Existing` with explicitly verified `-ApiClientId`, `-SpaClientId`, and `-BffApiScope` to retain separately managed registrations. In `Create` mode, an unrecorded app registration matching either generated display name causes deployment to fail instead of being adopted; choose unique display names or use `Existing` mode with verified client IDs. The BFF accepts delegated API tokens only when their `azp` (or v1 `appid`) claim matches the configured SPA client ID. `-UseExistingAzureContext` reuses a validated Az context. When Azure or Graph authentication is required, the script uses the normal interactive browser sign-in rather than forcing device-code authentication. `-ForceTokenOutput` acknowledges protected token-file creation for unattended deployment.

After every successful deployment stage, the script writes a non-secret checkpoint to `Deployment\.localadmin-deployment-state.json`. On a later run it restores the recorded configuration, authenticates to the recorded tenant and subscription, verifies that the resource group, Storage accounts, Automation account, and optional running Function App still exist, and asks before ignoring newly supplied deployment parameters. When approved, completed stages such as Bicep deployment, Graph grants, runbook publication, BFF publication, SAS generation, and `config.json` generation are skipped. The state file contains identifiers and configuration but no SAS values, account keys, OAuth tokens, or recovery secrets, and is excluded from Git. Use `-ForceRecreate` with a complete parameter set only when intentionally replacing the checkpoint and rerunning the deployment stages.

At the end of every completed run, the script writes an after-deployment report to `Deployment\LocalAdminReporting-DeploymentReport_<timestamp>.md` with a matching `.json` file. Use `-DeploymentReportPath` to choose another folder. The report lists the tenant, subscription, deploying account, resource group, every deployed resource with its status, naming check and portal link, the tables, managed identities and their role assignments, runbook schedule, endpoints, CORS origins, app registrations, Admin-mode groups and assigned roles, local files, completed stages, and the remaining manual steps. It contains no SAS tokens, keys, connection strings, or OAuth tokens, and is excluded from Git. A failure while writing the report does not fail the deployment.

The complete resource list, ownership rules, and teardown behavior are documented in
[`Deployment\RESOURCE-INVENTORY.md`](Deployment/RESOURCE-INVENTORY.md).

To publish backend code changes to an existing deployment without redeploying Azure resources, use
`-RepublishBff`. With a valid checkpoint, completed infrastructure, group, SAS, and configuration
stages remain skipped, and existing Function App settings (including `ADMIN_AUTH_CONTEXT_ID`) are
preserved:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 -RepublishBff -InstallTemporaryNode
```

Approve resuming the existing deployment when prompted. Publish the matching updated HTML files to
your web server as well if the browser API contract changed. Deployment readiness checks require both
the profile and Admin-mode session endpoints to return the BFF's unauthenticated `401` response.

## Remove an Azure deployment

`-ForceRecreate` does not delete Azure resources. Use `-RemoveDeployment` to remove the resources
recorded in `Deployment\.localadmin-deployment-state.json`. The operation deletes the two solution
Storage accounts and their data, the Automation account, the optional Function resources, associated
deployment records, the generated local `config.json`, and finally the checkpoint. It preserves app
registrations supplied through `AppRegistrationMode Existing` and any registration whose ownership is
not explicitly recorded.

Always preview first:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
   -RemoveDeployment `
   -UseExistingAzureContext `
   -WhatIf
```

Run the same command without `-WhatIf` and type `YES` to perform the teardown. Add
`-RemoveResourceGroup` to remove the group after tracked resources are deleted. Azure may create an
`Application Insights Smart Detection` action group alongside Application Insights without recording
it in the deployment template. If that exact resource remains, the script explains its origin and
requires a second `YES` before removing it. The script still refuses to remove the resource group if
any other untracked resources remain. Keep the checkpoint until teardown succeeds because it is the
authoritative inventory for removal.

The browser falls back to manual entry when `config.json` is missing or invalid. `config.example.json` documents the schema. The generated `redirectUri` makes MSAL use the exact `SpaRedirectUri` configured in Entra instead of deriving a potentially different default-document URL from the browser address bar. Values used by browser JavaScript cannot be hidden from an authorized user: Base64, minification, encryption with a browser-delivered key, and other obfuscation only slow casual inspection. If the endpoint itself must not be exposed, route access through IIS aliases or the BFF instead of sending direct Storage configuration to the browser.

`HTML\web.config` and `HTML\.htaccess` intentionally allow public `config.json`, disable directory browsing, and block private variants and common secret files. Blocking `config.json` itself would also prevent the LiveHTML from loading it. Keep private configuration outside the web root whenever possible.

The script uses these modules:

- `Az.Accounts`, `Az.Resources`, `Az.Storage`, and `Az.Automation` for Azure deployment, runbook configuration, and account SAS generation.
- `Az.Websites` when the Azure Functions BFF is deployed and published.
- `Microsoft.Graph.Authentication` for interactive Graph sign-in and direct `Invoke-MgGraphRequest` calls. The complete Microsoft Graph SDK is not required.

The script also requires Bicep to compile `Deployment\main.bicep`. It uses an existing `bicep` command when available and otherwise offers the temporary installation described above.

Before committing this variant, remove generated `*.log` files and local `node_modules` directories.
Both are ignored by Git, but deleting them keeps the working directory small and prevents accidental
copying or archiving outside Git. Do not remove `package-lock.json`, `HTML\vendor`, or the vendor
license files. Before release, regenerate and review a third-party license inventory from both npm
lockfiles. The current lockfiles declare only MIT, Apache-2.0, BSD-3-Clause, ISC, and 0BSD
dependencies; this inventory must be repeated whenever either lockfile changes.

The Azure identity performing the deployment needs permission to create the resource group resources and Azure role assignments. It also needs permission to list Storage account keys because Azure Table account SAS tokens are signed with an account key. The Graph sign-in requires `Application.Read.All`, `Application.ReadWrite.All`, and `AppRoleAssignment.ReadWrite.All` delegated consent and a directory role permitted to create app registrations and grant application permissions.

Shared-key access remains enabled on this dedicated Storage account because Azure Table account SAS tokens are signed with an account key and are rejected when shared-key authorization is disabled. These are account-level tokens, so their Table/Object permissions apply to every table in this Storage account. Keep unrelated tables in separate Storage accounts.

Token delivery is always explicit. The default `Prompt` mode offers:

1. Save the tokens to a protected plaintext file.
2. Display the tokens once in the console after an additional warning and confirmation.
3. Do not expose the generated tokens.

Use `-TokenOutputMode None` to skip SAS generation. In `File` mode, `-TokenOutputPath` can provide a destination, but the script still warns and requests confirmation before writing. On Windows, inheritance is removed and file access is granted only to the current user without changing privileged owner or audit information. Credentials are written only after a temporary file has been protected, then the protected file replaces the destination; a hardening or write failure leaves an existing destination untouched. Generated files following `LocalAdminReporting-Secrets_*.txt` are ignored by Git. The file describes each token's permissions, expiry, and intended use.

The token file remains a plaintext credential container. Move its values into their final management systems and securely delete it afterwards. Account SAS tokens cannot be revoked individually; rotating the signing Storage account key invalidates all SAS tokens signed by that key.

## Live Azure HTML report

Open `HTML\index.html` through an HTTP(S) server to query Azure Table Storage directly from the browser. ES modules are not reliably available when the file is opened directly with `file://`. Enter the inventory Storage account and read-only SAS. To load Governance data, also enter the separate governance Storage account and its read-only SAS. The page does not send any Azure request on load and does not refresh on a timer.

The live report provides the resolved summary, user and group detail links, search, filters, sorting, pagination, and CSV export. After opening user or group details, either the browser Back function or **Back to local admins** restores the previous search, filters, sort order, page, page size, and scroll position.

Host-configured account names are populated from `config.json`. If the governance account or governance SAS is missing, the Governance tab remains visible but disabled and explains what is required. Admin mode remains disabled when BFF or Entra SPA configuration is absent.

### What the Azure Function does

The Azure Function is the protected BFF/API process, not part of the static HTML. It receives profile and future admin requests, validates the user's Entra API token or recovery proof, derives the owner from immutable identity claims, enforces ETags and authorization, accesses governance Tables with managed identity, and writes audit records. This keeps governance write credentials and privileged Graph/Intune operations out of the browser.

Azure Functions provides the HTTP runtime, scaling, managed identity, application settings, TLS endpoint, diagnostics, and deployment unit around the TypeScript handlers. The current BFF source implements profile read/write plus recovery rotation/revocation. Admin action endpoints and Graph/Intune workers remain future plan work.

### IIS and the BFF

The Function cannot run inside the IIS static-site worker. For an IIS-first deployment, deploy it separately to Azure Functions and reverse proxy `/localadmin-api/` through IIS using URL Rewrite and Application Request Routing. Then set `bffBaseUrl` in `config.json` to `/localadmin-api/v1`. The browser sees the same IIS origin while IIS forwards API calls to the Function.

`HTML\iis-bff-reverse-proxy.example.config` contains an example rule. Alternatively, run a separately supervised Node/container service on the IIS server and proxy to it. Do not use Azure Functions Core Tools as a production server.

### CORS choices

For both Azure Table Storage and the BFF, exact HTTPS origins are recommended. The Storage deployment currently permits `*` when no LiveHTML origins are supplied. The BFF also accepts an explicit `ALLOWED_ORIGINS=*` for controlled testing or intentionally broad hosting. With a wildcard, any website can attempt API requests, so users must understand that JavaScript which obtains their bearer token or recovery code can submit it. The BFF does not use cookie credentials.

When IIS reverse proxies the BFF under the report's own origin, browser-to-BFF CORS is normally unnecessary. Storage CORS is still required while the browser queries Azure Table Storage directly.

**Group by computer** is enabled by default in the Local Admins table. Each computer starts collapsed; select its header to show or hide its administrator entries. In grouped mode, the page-size control and pagination count computers rather than administrator entries. Search, filters, and CSV export continue to operate on the matching administrator entries. Grouped results are ordered by computer name; ungrouped results default to computer name and then entry number.

### Read-only SAS for the live report

In the storage account's **Shared access signature** page, generate an **account SAS** with only these options selected:

- Allowed services: **Table**.
- Allowed resource types: **Object**.
- Allowed permissions: **Read**.
- Allowed protocols: **HTTPS only**.

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **Delete**, **List**, **Add**, **Create**, **Update**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The resulting scope is equivalent to `ss=t`, `srt=o`, and `sp=r`.

The report queries entities from the known `LocalAdminCollection`, `AdminUserNames`, and `AdminGroups` tables. It does not list, create, modify, or delete tables or entities, so **List** and all write permissions are unnecessary. Set the shortest practical expiry and, where possible, restrict the SAS to the public outbound IPv4 address or range used by report viewers.

By default, the page keeps the SAS token in its password field and browser memory for the current page only. Select **Remember connection on this device** to immediately save the validated storage account names and SAS tokens in browser `localStorage`. The page restores the fields on future visits but never refreshes automatically. Clearing the checkbox removes the saved credentials immediately; **Forget saved connection** also removes them immediately, clears both fields, and leaves the currently loaded report data available.

Browser storage is a convenience, not a secure credential vault. Any script running on the same origin can read `localStorage`, and anyone using the same browser profile can recover the saved SAS. Host this report on a dedicated, trusted origin without unrelated scripts, avoid shared devices and browser profiles, keep the read-only SAS short-lived and least-privileged, and use **Forget saved connection** when persistence is no longer needed. Browser-side encryption would not protect the token from same-origin script execution. The SAS also remains visible in browser developer tools and request URLs, so never use the remediation or stress-test token in the browser.

### CORS settings

Direct browser access requires one Azure Storage CORS rule for the Table service:

- Allowed origins: the exact origin hosting the HTML, such as `https://reports.contoso.com`. Opening the file directly requires `*`, which is broader and should be limited to controlled environments.
- Allowed methods: `GET`.
- Allowed headers: `x-ms-version`.
- Exposed headers: enter `x-ms-continuation-NextPartitionKey,x-ms-continuation-NextRowKey` together in the same field and rule.

Do not create a separate CORS rule for each continuation header. The single rule must expose both headers so the browser can follow pages that return partition-key and row-key continuation values.

After **Refresh from Azure** is selected, the button is disabled and the page displays a warning while it follows every continuation page. Wait until the success or error message appears before trying again.

## Identity lookup and where used

The proposal dialog accepts a manually entered SID or a lookup by UPN, account/group name, or Entra object ID. Both the principal and optional assigned-through group picker search the **loaded inventory first**, regardless of whether inventory was loaded using SAS or Entra. Selecting an identity fills its SID; selecting an assigned-through group also selects Transitive membership.

SAS-only users never make directory requests. If no local identity matches, a signed-in user with a governance API role can search Entra through the BFF. The browser waits for **800 ms without another input change**, requires 3-128 characters, and cancels superseded searches. Direct SID input does not trigger a directory search. Each search returns at most 20 directory objects; narrow the query if results are truncated. Security-group searches use name/mail prefixes, user searches use UPN/display-name prefixes, and an exact object ID is supported for either type. Synced identities offer separate **Entra** and **AD** SID choices; choose the one appropriate to the observed access path rather than assuming one SID works for all join states.

Successful results, including no matches, are cached in browser memory for five minutes per account/query/type, with at most 100 cached searches. Sign-out clears this cache. The backend also has a five-minute bounded cache and a per-instance limit of ten requests per caller per minute; Microsoft Graph throttling and permission failures are shown explicitly. This reduces directory requests and Function invocations; it is not a promise of per-query Graph billing savings.

Enable directory lookup by granting the **Function** managed identity `User.Read.All` and `Group.Read.All` Graph application permissions. The Automation identity's existing permissions do not grant the Function access. This is opt-in:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
    -RepublishBff `
    -ConfigureBffDirectoryLookup `
    -UseExistingAzureContext `
    -InstallTemporaryNode
```

The switch works with the existing deployment checkpoint and records `BffDirectoryPermissionsGranted`; permission grants require an appropriately privileged deployment operator and may need time to propagate. It cannot be combined with `-SkipGraphPermissionGrant`. No SPA Graph permissions, client secrets, or new npm dependencies are needed. Publish `identityLookup.js` alongside the updated `app.js`, `adminMode.js`, `apiContract.js`, `dataService.js`, `profileClient.js`, `index.html`, and `styles.css`.

Rules still store and match only the selected SID. Optional `PrincipalDisplayName` and `PrincipalUserPrincipalName` values are bounded, proposer-supplied snapshots for display, not directory-verified authorization claims or matching inputs. Governance tables/CSV and approval summaries show this context without changing rule precedence.

In **Users** and **Groups**, click an identity's SID or name to open **Where identity is used**. The read-only panel shows loaded computers and membership paths (including removed entries), plus direct rule references and rules whose scopes match those paths. Inactive rules are included and each table displays up to 250 rows. Load governance data to include its rules; this is not a tenant-wide directory-membership search or a final policy evaluation. The drill-down also works offline in generated snapshots and makes no directory calls.

## Admin mode Conditional Access setup

Microsoft Entra sign-in, **Enter Admin mode** and their status messages appear at the top right of the title bar. **Sign out** appears there once an account is signed in and exits Admin mode before signing out. The sign-out popup returns to the configured SPA redirect URI, where the MSAL redirect bridge relays its state-only response and closes the popup; the main report updates in place without reloading. Deploy `bootstrap.js` alongside `auth.js` so both sign-in and sign-out callbacks reach the bridge. Cloud profile reload remains in Settings. MSAL 5 cannot reliably detect a manually closed authentication popup because browser opener-isolation policies can sever its window connection. While a popup request is pending, a dark-red **Retry** button appears beside the disabled sign-in button. Close any remaining authentication popups before selecting it; this explicitly replaces the pending attempt without reloading the report. It works for normal sign-in and Admin-mode step-up. If you do not retry, the pending request eventually reports a timeout and leaves Admin mode inactive. Closing a popup is not itself evidence that the backend rejected authentication.

Reloading or closing the page clears the report sign-in and Admin mode by design: MSAL accounts, OAuth tokens and the local Admin-mode state live only in memory, not local or session storage. This does not sign out the Microsoft Entra browser session or revoke an already-issued access token. Sign in and enter Admin mode again after a reload.

Rule proposals accept pasted Unicode hyphens (`U+2010` and non-breaking `U+2011`) in the principal and assigned-through group SID fields. The browser converts these to ordinary ASCII hyphens before validation, match preview and submission; stored rules and backend SID validation remain unchanged.

Proposers can click the **Preview: matches ...** summary in the proposal dialog to inspect the matching review entries and computers. Approvers get the same clickable summary beside the governance actions and inside the approval confirmation dialog. Closing the read-only preview preserves the underlying proposal or approval form. Load inventory first using the report connection; loading governance rules from the BFF alone does not load inventory. Previews use all loaded review entries, regardless of report filters, and apply the rule's principal, source, membership, group, device, join-state and device-age constraints. They show matching scope, not a final policy-change prediction: rule status, validity dates, precedence and competing rules still determine the outcome. Refresh inventory before relying on these counts.

The page header and Admin-mode controls stay visible while scrolling. Only the current sign-in and Admin-mode messages appear in a collapsed status box, not a message history; select its arrow to expand or collapse it. Error lines are highlighted. Authentication and Admin-mode errors expand it automatically. The locally drawn arrow sits to the right of the timers, or by itself beneath the Admin-mode button when no timers are running, without a full-width bar. When Admin mode is active, an **Idle timeout** countdown shows the time remaining before 15 minutes of inactivity ends the session, and a **Total timeout** countdown shows the time until the backend's absolute session expiry. Clicks, taps, and key presses reset only the idle countdown. Admin mode ends when either countdown reaches zero; this does not sign you out of the report.

Admin mode uses a Conditional Access **authentication context** to force a fresh sign-in. When **Enter Admin mode** is selected, the LiveHTML asks Entra for a token with the authentication context. Every privileged BFF request then checks three things:

- the token carries the context in its `acrs` claim;
- the token was issued within `ADMIN_SESSION_MAX_MINUTES` (default 30);
- the caller has a `LocalAdmin.*` app role.

If any check fails, the BFF returns a claims challenge and the browser asks the user to sign in again.

Requirements:

- **Licensing:** Microsoft Entra ID P1 for Conditional Access and for assigning app roles through groups. PIM for Groups additionally needs Entra ID P2 or Entra ID Governance.
- **Admin roles:** Conditional Access Administrator (or Security Administrator) to create the context and policy. Application Administrator, or Graph `Application.ReadWrite.All`, for the deployment script.

### 1. Create the authentication context

1. Open the [Microsoft Entra admin center](https://entra.microsoft.com).
2. Go to **Entra ID** > **Conditional Access** > **Authentication contexts**, then select **New authentication context**.
3. Fill in the fields:
   - **Name:** `LocalAdmin Admin mode`
   - **Description:** `Step-up for privileged LocalAdminSolution actions`
4. Under **ID**, choose `c1`. If `c1` is already used, choose any free ID from `c1` to `c99` and pass it to the deployment as `-AdminAuthContextId`.
5. Select **Publish to apps**, then **Save**.

### 2. Create the Conditional Access policy

1. Go to **Entra ID** > **Conditional Access** > **Policies**, then select **New policy**.
2. **Name:** `LocalAdmin - Admin mode step-up`
3. **Users:**
   - **Include:** select the group that holds the `LocalAdmin.*` roles (or the individual admins).
   - **Exclude:** your emergency-access (break-glass) accounts.
4. **Target resources:** change the selector from **Resources (formerly cloud apps)** to **Authentication context**, then tick the context from step 1 (`c1`). Don't also target the API or SPA app here, or every normal sign-in will get the step-up.
5. **Conditions:** none are required. Add device or location conditions only if your policy needs them.
6. **Grant:**
   - Select **Grant access** > **Require authentication strength** > **Phishing-resistant MFA**.
   - Use **Multifactor authentication** only if your admins don't have phishing-resistant methods yet.
7. **Session:**
   - Select **Sign-in frequency** > **Every time**.
   - Without this, Entra can reuse an earlier sign-in, so entering Admin mode won't prompt the user again.
8. **Enable policy:** set to **Report-only** first. Check the sign-in logs, then switch to **On**.
9. Select **Create**.

### 3. Deploy the app roles and Admin-mode settings

With `-AppRegistrationMode Create`, the deployment adds the four app roles automatically. For existing registrations, rerun the deployment with the switch below. The switch adds the four app roles to the API app registration and keeps any roles that already exist.

```powershell
.\Deployment\Deploy-LocalAdminReporting.ps1 <your usual parameters> -ConfigureApiAppRoles -AdminAuthContextId c1 -AdminSessionMaxMinutes 30
```

The deployment writes `ADMIN_AUTH_CONTEXT_ID` and `ADMIN_SESSION_MAX_MINUTES` to the Function App. Republish the backend, then copy the updated HTML files to IIS: `adminMode.js`, `app.js`, `auth.js`, `apiContract.js`, `profileClient.js`, `connection.js`, `index.html` and `styles.css`.

### 4. Assign the app roles

The deployment creates the four `sg-<name>-*` security groups and assigns the roles to them (see [Automated Azure deployment](#automated-azure-deployment)). Add your admins as members of the matching group. The after-deployment report lists the group names and any role that could not be assigned.

If you used `-SkipAdminGroups`, go to **Entra ID** > **Enterprise applications**, open the API application, and go to **Users and groups** > **Add user/group**. Assign the roles to groups where possible.

| Role | Grants |
| --- | --- |
| `LocalAdmin.Governance.Read` | Read governance rules and propose new ones. |
| `LocalAdmin.Governance.Approve` | Approve, reject and revoke rules. Rules you proposed yourself need a second approver. |
| `LocalAdmin.Governance.SelfApprove` | Use with Approve. Lets you approve your own proposals, which suits small tenants. Each self-approval is audited. |
| `LocalAdmin.Actions.Operate` | Cancel other users' requests. |

To make the roles just-in-time, make admins *eligible* members of the group through **PIM for Groups** instead of permanent members. App roles are only added to a token at sign-in. After activating PIM membership, sign out of the LiveHTML and sign in again, then enter Admin mode.

### 5. Verify

1. Sign in to the LiveHTML and select **Enter Admin mode**. Entra should prompt for phishing-resistant MFA, even if you signed in moments ago.
2. In **Entra ID** > **Monitoring & health** > **Sign-in logs**, open the sign-in. On the **Conditional Access** tab, the policy should show **Success**.
3. Test the failure cases:
   - an account without a role: privileged buttons stay disabled with an explanation;
   - an eligible PIM member who hasn't activated: the BFF returns `403`;
   - cancelling the MFA prompt: the page stays out of Admin mode;
   - waiting longer than `ADMIN_SESSION_MAX_MINUTES`: Admin mode ends and asks for a fresh sign-in.

Troubleshooting:

- **`admin_auth_context_required` keeps returning:** one of these is the cause:
  - the context isn't published to apps;
  - the policy is in Report-only mode or doesn't include the user;
  - `-AdminAuthContextId` doesn't match the context ID.
- **`admin_session_expired` immediately after step-up:** **Sign-in frequency** isn't set to **Every time**, so Entra returned an older token.

## Generated HTML snapshot

Generate a standalone interactive report containing the same resolved summary, user details, and group details as the live report and Excel workbook:

```powershell
pwsh.exe -NoProfile -File .\HTML\Export-LocalAdminResolvedHtml.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-only-sas-token>'
```

The exporter uses the same least-privilege account SAS settings as the live report: **Table** service, **Object** resource type, **Read** permission, and **HTTPS only**. It retrieves every continuation page from the four inventory tables and, when configured, the governance allow-rule and review-action tables. It does not modify Azure data.

The generated `HTML\LocalAdminResolved.html` provides:

- Search across all visible columns.
- Join-state and active or removed filters.
- Sortable, resizable, and reorderable columns with per-view layouts saved in browser preferences and cloud profiles.
- Clickable user and group names that open the matching SID-based detail view.
- CSV export of the current filtered view.

Drag a column header to reorder it, or focus the header and press **Alt+Left/Right**. Drag the divider at the header's right edge to resize it, or focus the divider and use **Left/Right**; hold **Shift** for larger increments. **Reset columns** restores the original order and widths for the active view. Layout changes are stored locally immediately and synchronized to the active cloud profile when one is connected.

Use `-OutputPath` to choose another report location and `-OpenReport` to open it after export:

```powershell
pwsh.exe -NoProfile -File .\HTML\Export-LocalAdminResolvedHtml.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-only-sas-token>' -OutputPath C:\Reports\LocalAdmins.html -OpenReport
```

The generated report embeds inventory data but not either SAS token, hides the live connection controls, uses snapshot-safe no-op browser storage functions, and requires regeneration to obtain newer data. The exporter bundles each source module in its own scope and replaces sign-in, cloud-profile, recovery and Admin-mode modules with inert stubs. Export fails if a source module imports a name that the snapshot neither inlines nor stubs, if a template marker is missing, or if any external script, stylesheet, image or frame reference would remain. Protect the HTML according to the sensitivity of the reported device and account information.

The hosted [Local administrator inventory demo](https://intune.best/LocalAdminResolvedDemo.html) is a publishable snapshot generated from 5,000 deterministic synthetic main rows. It contains no SAS token or real inventory data and can be opened without an Azure connection. The generated `HTML\LocalAdminResolvedDemo.html` file can be uploaded to replace the hosted version.

Regenerate the demo after loading the synthetic stress-test data:

```powershell
pwsh.exe -NoProfile -File .\HTML\Export-LocalAdminResolvedHtml.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-only-sas-token>' -OutputPath .\HTML\LocalAdminResolvedDemo.html
```

## Workbook setup

1. Save the workbook as an Excel macro-enabled workbook (`.xlsm`) if clickable detail links are required.
2. In the Power Query Editor, select **Home > Manage Parameters > New Parameter** and create both parameters below. The parameter names are case-sensitive:
   - Name: `StorageAccountUrl`; Type: **Text**; Suggested Values: **Any value**; Current Value: `https://<storage-account-name>.table.core.windows.net`
   - Name: `StorageSasToken`; Type: **Text**; Suggested Values: **Any value**; Current Value: the SAS token, with or without its leading `?`.

   After selecting **OK**, both parameters must appear in the left **Queries** pane with parameter icons. If **Manage Parameters** is unavailable in your Excel version, create two blank queries instead and enter these expressions in their Advanced Editors:

   ```powerquery-m
   // Query name: StorageAccountUrl
   "https://<storage-account-name>.table.core.windows.net"
   ```

   ```powerquery-m
   // Query name: StorageSasToken
   "paste-the-SAS-token-here"
   ```

   Set both fallback queries to **Connection Only**. Do not include the comment lines when pasting.
3. For each query below, right-click the empty **Queries** pane and select **New Query > Other Sources > Blank Query**. Do not select a `.pq` file from **Recent Sources**. Rename the new query in **Query Settings > Name**, select **Home > Advanced Editor**, replace all existing text with the corresponding file contents, and select **Done**:
   1. `GetAzureAdminTable` from `Excel\GetAzureAdminTable.pq`.
   2. `AdminUserDetails` from `Excel\AdminUserDetails.pq`.
   3. `AdminGroupDetails` from `Excel\AdminGroupDetails.pq`.
   4. `LocalAdminLinkMap` from `Excel\LocalAdminLinkMap.pq`.
   5. `LocalAdminResolved` from `Excel\LocalAdminResolved.pq`.
4. When Excel requests credentials for the Web source, select **Anonymous** at the `https://<storage-account-name>.table.core.windows.net/` level. Authorization is supplied by the SAS query parameter.
5. When Excel requests privacy levels, select **Organizational** for every `https://<storage-account-name>.table.core.windows.net/` entry and select **Save**. All entries represent the same confidential organizational data source. Do not select **Public** or enable **Ignore Privacy Levels checks for this file**.
6. Configure query loading:
   - Load `AdminUserDetails`, `AdminGroupDetails`, and `LocalAdminResolved` to separate worksheets as tables.
   - Load `LocalAdminLinkMap` to a worksheet as a table, then hide that worksheet.
   - Set `GetAzureAdminTable` to **Connection Only**.
7. Keep the generated Excel table names identical to their query names. The hyperlink helper locates tables by name, so worksheet names may be changed safely.

The built-in Azure Table Storage Power Query connector accepts account-key authentication. These queries use `Web.Contents` with the Azure Table JSON REST format so the existing read-enabled SAS can be used without requiring the storage account key. This also avoids Atom/OData version negotiation errors in older Excel Power Query builds.

`GetAzureAdminTable` follows Azure Table continuation headers automatically, so queries return more than the service's 1,000-entity page size.

If the existing `GetAzureAdminTable` query reports HTTP 415 or mentions Atom format, replace its complete **Advanced Editor** contents with the current `Excel\GetAzureAdminTable.pq`, select **Done**, and refresh the other queries.

If `LocalAdminResolved` reports that `PrincipalID`, `PrincipalType`, or `AssignedThroughGroupID` was not found, replace the complete **Advanced Editor** contents of both `GetAzureAdminTable` and `LocalAdminResolved` with their current files in the `Excel` folder. Azure Table Storage is schemaless, so the current queries combine all entity property names and create absent optional columns as null before joining.

## Clickable names in Excel

Power Query cannot create active worksheet hyperlinks by itself. To add them:

1. Open the VBA editor with `Alt+F11`.
2. Import `Excel\LocalAdminLinks.bas` into the workbook.
3. Run `RefreshLocalAdminView` instead of **Refresh All**.

The macro refreshes every query, waits for asynchronous queries, and then links each populated `UserName`, `GroupName`, or `AddedThroughGroupName` cell in `LocalAdminResolved` to the matching row in the appropriate detail worksheet. It uses `LocalAdminLinkMap` and immutable SIDs internally, so duplicate display names still resolve to the correct detail row.

`BuildLocalAdminDetailLinks` can be run independently if the workbook was already refreshed.

## Intune remediation interval

Upload `Remediation\Detect-LocalAdminSolution.ps1` and `Remediation\Remediate-LocalAdminSolution.ps1` as an Intune Remediations script package. Configure **Run this script using the logged-on credentials** as **No** and **Run script in 64-bit PowerShell** as **Yes** so both scripts use the same system-level registry location.

The detection script defaults `$RemediationIntervalHours` to `4`. Because Intune Remediations does not pass custom command-line arguments to detection scripts, change that default in the uploaded detection file when a different interval is required. The Intune assignment schedule may run more frequently; the detection script reports compliant until the configured interval expires.

After every complete Azure Table upload, remediation writes an invariant UTC timestamp to `LastSuccessfulRunUtc` under `HKLM:\Software\LocalAdminSolution`. Missing, invalid, or expired values cause detection to report noncompliant. Failed or partial uploads do not advance the timestamp and are retried at the next Intune evaluation.

## SAS security and permissions

- Treat `StorageSasToken` as a credential. Use the narrowest permissions and shortest practical expiry.
- The current queries require **Read** access to table entities. **List** is not required because the table names are already known.
- When the SAS expires, replace the value of the existing `StorageSasToken` parameter. Excel does not store a second SAS token in **Data Source Settings**; it stores the source URL's authentication mode (`Anonymous`) and privacy level (`Organizational`) there. Normally, changing the parameter and refreshing is sufficient. If an authentication error remains cached, clear the permissions for `https://<storage-account-name>.table.core.windows.net/` under **Data Source Settings**, refresh, then select **Anonymous** and **Organizational** again.
- Anyone who receives the workbook can potentially inspect its Power Query parameters and recover the SAS token.

Use separate SAS tokens for reading reports and writing inventory whenever practical:

| Workflow | Service | Resource type | Permissions |
| --- | --- | --- | --- |
| Live HTML, HTML exporter, and Excel | Table | Object | Read |
| Intune remediation | Table | Object | Read, Add, Update |
| Azure Automation reconciler | Managed identity | Lookup table entities | Read, Add, Update, Delete |
| Stress-test upload | Table | Object | Add, Update |
| Stress-test removal or table clearing | Table | Object | Read, Delete |
| Complete stress-test lifecycle with one temporary token | Table | Object | Read, Delete, Add, Update |

Use **HTTPS only** for every token. **Service**, **Container**, **List**, and **Create** are not needed because the workflows address known tables that already exist. Do not reuse a write-enabled token in the browser or workbook.

### Least-privilege remediation SAS

For `Remediation\Remediate-LocalAdminSolution.ps1`, generate an **account SAS** with only these portal options selected:

- Allowed services: **Table**.
- Allowed resource types: **Object**.
- Allowed permissions: **Read**, **Add**, and **Update**.
- Allowed protocols: **HTTPS only**.

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **Delete**, **List**, **Create**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The resulting access is equivalent to `ss=t`, `srt=o`, and `sp=rau`.

The remediation uses **Read** to compare lookup partitions and device state, **Add** to create missing rows, and **Update** to submit inventory, heartbeat, and newer AD/local name candidates. Identical observations, existing Entra rows, domain-unavailable SID fallbacks, and older candidates are not rewritten. All four inventory tables must already exist; the script does not create or delete tables. Use the shortest practical expiry and restrict the SAS to known outbound IPv4 addresses where applicable.

See Microsoft's [account SAS permissions by operation](https://learn.microsoft.com/rest/api/storageservices/create-account-sas#account-sas-permissions-by-operation) for the Table service mapping.

This remediation SAS is intentionally insufficient for `New-LocalAdminSolutionStressTestData.ps1 -ClearTables` or `-RemoveStressData`, which also require **Delete**.

## Central lookup reconciliation

`Runbooks\Resolve-LocalAdminLookupNames.ps1` is a PowerShell 7 Azure Automation runbook that owns canonical lookup names. Configure its Automation Account managed identity with:

- `Storage Table Data Contributor` on the storage account, or a narrower custom data role that permits entity read, add, update, and delete on `AdminUserNames` and `AdminGroups`.
- Microsoft Graph application permissions `User.Read.All` and `Group.Read.All`, with tenant administrator consent.
- The `Az.Accounts` module in the Automation Account runtime.

Create a schedule and pass `StorageAccountName`. For a user-assigned identity, also pass `ManagedIdentityClientId`. No SAS token or webhook is required. Use `-WhatIf` from a test worker before the first production run.

Endpoints add `ObservedAt` and `ResolutionState` to new lookup rows. Newer, differing AD/local observations are stored in `CandidateGroupName`, or `CandidateSamAccountName` and `CandidateUserPrincipalName`, with `CandidateObservedAt`. Equal candidates are strict no-ops. Entra names remain Graph-authoritative and endpoints never replace an existing Entra row.

The runbook resolves Entra SIDs through Graph, validates newer AD/local candidates, writes the target RowKey before deleting obsolete rows, and clears candidate properties through replacement. Repeated runs converge safely after interruption. Only the managed identity needs Delete permission; do not add Delete to endpoint SAS tokens.

Deploy the remediation and current HTML or Excel readers together, then schedule the runbook. The normalized `LocalAdminCollection` schema is a clean break and the readers do not support legacy main rows containing `UserID` or `GroupID`. Clear pre-release main-table data before testing this version. Lookup-table rows remain compatible; all included readers choose `Resolved` first, then newest `ObservedAt` or Azure `Timestamp`, then RowKey as a deterministic tie-breaker. Candidate values are not displayed before promotion.

## Local administrator schema

Each `LocalAdminCollection` entity represents one access path to the localized Administrators group on one computer. Numeric RowKeys remain stable while a path is active, removed, and later reactivated.

| Property | Required | Meaning |
| --- | --- | --- |
| `PrincipalID` | Yes | SID of the user or group represented by this row. |
| `PrincipalType` | Yes | `User` or `Group`. |
| `MembershipType` | Yes | `Direct` or `Transitive`. |
| `AssignedThroughGroupID` | Transitive only | SID of the directly assigned Active Directory group that produced the one-level expanded member. |

Examples:

| PrincipalType | PrincipalID | MembershipType | AssignedThroughGroupID | Meaning |
| --- | --- | --- | --- | --- |
| `User` | `S-1-5-21-...-1101` | `Direct` | | User is directly in Administrators. |
| `Group` | `S-1-5-21-...-2101` | `Direct` | | Group is directly in Administrators. |
| `User` | `S-1-5-21-...-1102` | `Transitive` | `S-1-5-21-...-2101` | User was returned by one-level expansion of the direct group. |
| `Group` | `S-1-5-21-...-2201` | `Transitive` | `S-1-5-21-...-2101` | Nested group was observed during one-level expansion; its members are not expanded. |

The same principal can have multiple rows when it is assigned directly and through a group, or through multiple directly assigned groups. Direct paths are identified by `PrincipalType|PrincipalID|Direct`; transitive paths are identified by `PrincipalType|PrincipalID|AssignedThroughGroupID`.

Only directly assigned Active Directory groups are expanded, and only one membership level is read. Local and Microsoft Entra groups are reported as direct group principals but are not expanded. `AdminUserNames` and `AdminGroups` remain independent canonical SID-to-name lookup tables.

## Query outputs

### LocalAdminResolved

Contains the source `LocalAdminCollection` fields with `ComputerName` first and `SID` second. `PrincipalID` is presented in either `UserName` or `GroupName`, according to `PrincipalType`. `AssignedThroughGroupID` is presented as `AddedThroughGroupName`. `EntraOrHybrid` is translated to `Entra joined`, `Hybrid joined`, or `Domain joined`. `RowKey` is converted to a number and sorted ascending.

The presentation applies these mappings:

- `Computername` becomes `ComputerName` and moves to the first column.
- `PartitionKey` becomes `SID` and moves to the second column.
- A user `PrincipalID` becomes `UserName` and contains the resolved `SamAccountName` from `AdminUserNames`.
- A group `PrincipalID` becomes `GroupName` and contains the resolved group name from `AdminGroups`.
- `MembershipType` shows whether the principal is direct or transitive.
- `AssignedThroughGroupID` becomes `AddedThroughGroupName` and resolves through `AdminGroups`.

If a lookup is missing, the original SID remains visible instead of being discarded. Removed records remain in the result and can be filtered with the `Removed` column.

### AdminUserDetails

Contains one canonical row per `UserID` (SID), including `SamAccountName`, `UserPrincipalName`, `LocalOrEntraOrAD`, `ObservedAt`, `ResolutionState`, and the Azure entity `Timestamp`.

### AdminGroupDetails

Contains one canonical row per `GroupID` (SID), including `GroupName`, `LocalOrEntraOrAD`, `ObservedAt`, `ResolutionState`, and the Azure entity `Timestamp`.

Source codes are `L` for local, `E` for Microsoft Entra ID, and `A` for Active Directory.

## Stress-test data

`New-LocalAdminSolutionStressTestData.ps1` creates deterministic, schema-valid test data for validating Excel refresh and transformation performance. Its defaults create:

- 10,008 `LocalAdminCollection` rows across 834 synthetic computers.
- 5,004 linked `AdminUserNames` observations.
- 5,004 linked `AdminGroups` observations.
- A mix of local, Microsoft Entra ID, and Active Directory principals and device join states.
- Direct users and groups, transitive users and nested groups, users that are both direct and transitive, and users assigned through multiple direct groups.
- Microsoft Entra groups only as direct principals; their membership is not synthesized.
- Deterministically distributed removed entries for status filtering and demonstrations.
- Localized Administrators group names in English, German, French, Spanish, Italian, and Dutch.
- Report timestamps distributed across a six-hour period.
- Fictional international Contoso names such as `BER-LT-0001`, `ines.davis-2560`, and `GG-Amsterdam-Deployment-Operators-5yc1u`.
- Reserved `contoso.example` UPNs for non-local users; no production identities or routable mail domains are used.
- With `-IncludeGovernanceScenarios`, seven deterministic governance rules covering approval, denial, pending, expiry, device-prefix scope, and an equal-specificity conflict.
- With `-IncludeGovernanceScenarios`, six deterministic review actions covering Requested, Queued, InProgress, AwaitingInventory, Succeeded, and Failed states.

Use `-EntryCount` to select an exact main-table stress level of `5000`, `10000`, `15000`, or `20000` rows. The script distributes those rows across the required number of computers. Use `-EntraGroupObjectIds` to include specific Microsoft Entra groups whose names were unavailable locally. Duplicate object IDs are ignored; when IDs are supplied, other synthetic principals use local or Active Directory identities so reconciliation output remains focused on those groups.

Realistic naming is the default. Pass `-LegacyNaming` to reproduce the original `STRESS*`, `StressUsr*`, `StressGroup*`, and `stress.example` values. Both profiles preserve the same deterministic SIDs, direct/transitive paths, row counts, removed-state distribution, and repeatable upsert keys.

### SAS settings for stress testing

The dry run does not connect to Azure and requires no SAS token. For operations that do connect, create an **account SAS** and always select:

- Allowed services: **Table**.
- Allowed resource types: **Object**.
- Allowed protocols: **HTTPS only**.

Then select permissions according to the operation:

- `-Execute`: **Add** and **Update**. Azure Table insert-or-replace upserts require both permissions. The scope is equivalent to `ss=t`, `srt=o`, and `sp=au`.
- `-RemoveStressData -WhatIf` or `-ClearTables -WhatIf`: **Read**. A preview reads entities but does not delete them.
- `-RemoveStressData` or `-ClearTables`: **Read** and **Delete**. The script first reads the known tables to identify entities and then deletes those entities.
- One temporary token for upload, verification, and cleanup: **Read**, **Delete**, **Add**, and **Update**. Revoke or rotate this token as soon as the test is complete.

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **List**, **Create**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The script never creates, lists, or deletes the table resources themselves; `-ClearTables` deletes all entities while retaining the four inventory tables.

For the narrowest access, use one **Add + Update** token for `-Execute`, a separate **Read** token for report validation, and one short-lived **Read + Delete** token for cleanup. All four inventory tables must exist before the test begins.

Run a dry run first:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1
```

Write the entities by passing the target storage account and SAS token:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -Execute
```

Add human-verifiable Governance and Review scenarios by supplying the separate governance account and a temporary governance Add + Update SAS:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 `
   -StorageAccountName '<inventory-storage-account>' `
   -SasToken '<inventory-add-update-sas>' `
   -GovernanceStorageAccountName '<governance-storage-account>' `
   -GovernanceSasToken '<governance-add-update-sas>' `
   -EntryCount 5000 `
   -IncludeReconciliationScenarios `
   -IncludeGovernanceScenarios `
   -Execute
```

The governance scenarios are marked with `StressData = 1` and can be removed with `-RemoveStressData -IncludeGovernanceScenarios`. They deliberately do not create user profiles or audit records directly; those are tested through the deployed BFF so ownership, ETags, managed identity, and append-only auditing remain part of the test.

Add deterministic reconciliation cases, including SID fallbacks, a newer AD rename candidate, and a legacy duplicate RowKey:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -IncludeReconciliationScenarios -Execute
```

Generate exactly 5,000 main rows and include specific Microsoft Entra groups for runbook validation:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 `
   -StorageAccountName '<storage-account-name>' `
   -SasToken '<endpoint-sas-token>' `
   -EntryCount 5000 `
   -EntraGroupObjectIds '<group-object-id-1>','<group-object-id-2>' `
   -Execute
```

The defaults exceed 10,000 main rows because 834 computers multiplied by 12 entries equals 10,008. The following tested configuration creates exactly 20,000 main rows:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ComputerCount 1000 -EntriesPerComputer 20 -Execute
```

The generated keys and names are deterministic. Running the same profile again replaces the same entities rather than creating duplicates. Every generated main and lookup entity includes `StressData = 1` and a `SyntheticProfile` value so cleanup does not depend on realistic display names.

Changing between realistic and legacy naming changes lookup RowKeys. Remove the existing stress data before uploading the other profile to avoid retaining both names for the same synthetic SID:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-delete-sas-token>' -RemoveStressData -Force
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<add-update-sas-token>' -EntryCount 5000 -Execute
```

After generating test data, replace the workbook's `GetAzureAdminTable` query with `Excel\GetAzureAdminTable.pq` before refreshing. This version follows Azure Table continuation headers and retrieves every page beyond 1,000 entities.

## Remove stress-test data

Preview removal of only the deterministic stress-test entities:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -RemoveStressData -WhatIf
```

Remove the stress-test entities while preserving collected device data:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -RemoveStressData
```

The script identifies current generated rows through `StressData = 1`. It also recognizes the legacy `STRESS`, `StressUsr`, and `StressGroup` prefixes so datasets uploaded before marker-based main rows remain removable. Lookup rows are additionally matched by the stable principal SIDs referenced from synthetic main rows, which keeps cleanup effective after the reconciliation runbook renames or replaces lookup rows. A lookup SID that is also referenced by non-synthetic inventory is protected from SID-derived deletion. The script requests confirmation before deletion. Add `-Force` for unattended execution.

## Clear all table data

Preview removal of every entity in the four inventory tables. This command does not clear governance data:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ClearTables -WhatIf
```

Clear `LocalAdminCollection`, `AdminUserNames`, and `AdminGroups`:

```powershell
pwsh.exe -NoProfile -File .\New-LocalAdminSolutionStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ClearTables
```

This operation retains the Azure Table resources but removes every entity they contain. It requests confirmation before deletion. Add `-Force` for unattended execution. The SAS token must include **Read** and **Delete** permissions as described in [SAS settings for stress testing](#sas-settings-for-stress-testing).

## Change history

See [changelog.md](changelog.md) for the solution change history.
