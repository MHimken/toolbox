# Local administrator reporting

This package builds Excel and interactive HTML views over the three Azure Tables written by `Remediation\Remediate-Write-AdminsToAZTable.ps1`. Detection and remediation scripts are stored in the `Remediation` folder, Excel assets in `Excel`, and HTML assets in `HTML`.

## Capabilities

The solution can:

- Inventory direct members of the localized Windows Administrators group on domain-joined, Microsoft Entra joined, and hybrid-joined devices.
- Resolve local users, Active Directory users and groups, and Microsoft Entra principals into three linked Azure Tables.
- Preserve previously reported members and mark missing entries as removed.
- Display current Azure data in a standalone live HTML report with search, filters, sorting, pagination, linked details, and CSV export.
- Generate a self-contained HTML snapshot that can be viewed without an Azure connection.
- Load and resolve the same data in Excel Power Query, with optional VBA links to user and group details.
- Generate, remove, and clear deterministic stress-test data for performance and demonstration testing.

## Contents

- [Live Azure HTML report](#live-azure-html-report)
- [Read-only SAS for the live report](#read-only-sas-for-the-live-report)
- [Generated HTML snapshot](#generated-html-snapshot)
- [Workbook setup](#workbook-setup)
- [Clickable names in Excel](#clickable-names-in-excel)
- [SAS security and permissions](#sas-security-and-permissions)
- [Query outputs](#query-outputs)
- [Stress-test data](#stress-test-data)
- [SAS settings for stress testing](#sas-settings-for-stress-testing)
- [Remove stress-test data](#remove-stress-test-data)
- [Clear all table data](#clear-all-table-data)
- [Change history](#change-history)

## Live Azure HTML report

Open `HTML\LocalAdminResolvedLive.html` to query Azure Table Storage directly from the browser. Enter only the storage account name and a read-only account SAS token, then select **Refresh from Azure**. The page constructs `https://<storage-account-name>.table.core.windows.net` internally. It does not send any Azure request on load and does not refresh on a timer. Every refresh must be started explicitly.

The live report provides the resolved summary, user and group detail links, search, filters, sorting, pagination, and CSV export. After opening user or group details, either the browser Back function or **Back to local admins** restores the previous search, filters, sort order, page, page size, and scroll position.

**Group by computer** is enabled by default in the Local Admins table. Each computer starts collapsed; select its header to show or hide its administrator entries. In grouped mode, the page-size control and pagination count computers rather than administrator entries. Search, filters, and CSV export continue to operate on the matching administrator entries. Grouped results are ordered by computer name; ungrouped results default to computer name and then entry number.

### Read-only SAS for the live report

In the storage account's **Shared access signature** page, generate an **account SAS** with only these options selected:

- Allowed services: **Table**.
- Allowed resource types: **Object**.
- Allowed permissions: **Read**.
- Allowed protocols: **HTTPS only**.

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **Delete**, **List**, **Add**, **Create**, **Update**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The resulting scope is equivalent to `ss=t`, `srt=o`, and `sp=r`.

The report queries entities from the known `LocalAdminCollection`, `AdminUserNames`, and `AdminGroups` tables. It does not list, create, modify, or delete tables or entities, so **List** and all write permissions are unnecessary. Set the shortest practical expiry and, where possible, restrict the SAS to the public outbound IPv4 address or range used by report viewers.

By default, the page keeps the SAS token in its password field and browser memory for the current page only. Select **Remember connection on this device** to save the validated storage account name and SAS token in browser `localStorage` after a successful refresh. The page restores the fields on future visits but never refreshes automatically. Clearing the checkbox removes a previously saved connection after the next successful refresh; **Forget saved connection** removes it immediately, clears both fields, and leaves the currently loaded report data available.

Browser storage is a convenience, not a secure credential vault. Any script running on the same origin can read `localStorage`, and anyone using the same browser profile can recover the saved SAS. Host this report on a dedicated, trusted origin without unrelated scripts, avoid shared devices and browser profiles, keep the read-only SAS short-lived and least-privileged, and use **Forget saved connection** when persistence is no longer needed. Browser-side encryption would not protect the token from same-origin script execution. The SAS also remains visible in browser developer tools and request URLs, so never use the remediation or stress-test token in the browser.

### CORS settings

Direct browser access requires one Azure Storage CORS rule for the Table service:

- Allowed origins: the exact origin hosting the HTML, such as `https://reports.contoso.com`. Opening the file directly requires `*`, which is broader and should be limited to controlled environments.
- Allowed methods: `GET`.
- Allowed headers: `x-ms-version`.
- Exposed headers: enter `x-ms-continuation-NextPartitionKey,x-ms-continuation-NextRowKey` together in the same field and rule.

Do not create a separate CORS rule for each continuation header. The single rule must expose both headers so the browser can follow pages that return partition-key and row-key continuation values.

After **Refresh from Azure** is selected, the button is disabled and the page displays a warning while it follows every continuation page. Wait until the success or error message appears before trying again.

## Generated HTML snapshot

Generate a standalone interactive report containing the same resolved summary, user details, and group details as the live report and Excel workbook:

```powershell
pwsh.exe -NoProfile -File .\HTML\Export-LocalAdminResolvedHtml.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-only-sas-token>'
```

The exporter uses the same least-privilege account SAS settings as the live report: **Table** service, **Object** resource type, **Read** permission, and **HTTPS only**. It retrieves every continuation page from the three known tables and does not modify Azure data.

The generated `HTML\LocalAdminResolved.html` provides:

- Search across all visible columns.
- Join-state and active or removed filters.
- Sortable columns and adjustable pagination.
- Clickable user and group names that open the matching SID-based detail view.
- CSV export of the current filtered view.

Use `-OutputPath` to choose another report location and `-OpenReport` to open it after export:

```powershell
pwsh.exe -NoProfile -File .\HTML\Export-LocalAdminResolvedHtml.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<read-only-sas-token>' -OutputPath C:\Reports\LocalAdmins.html -OpenReport
```

The generated report embeds inventory data but not the SAS token, hides the live connection controls, never reads or writes saved connection data, and requires regeneration to obtain newer data. Protect the HTML according to the sensitivity of the reported device and account information.

The hosted [Local administrator inventory demo](https://intune.best/LocalAdminResolvedDemo.html) is a publishable snapshot generated from 20,000 deterministic synthetic main rows. It contains no SAS token or real inventory data and can be opened without an Azure connection. The generated `HTML\LocalAdminResolvedDemo.html` file can be uploaded to replace the hosted version.

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

If `LocalAdminResolved` reports that `_UserSID` or `_GroupSID` was not found, replace the complete **Advanced Editor** contents of both `GetAzureAdminTable` and `LocalAdminResolved` with their current files in the `Excel` folder. Azure Table Storage is schemaless, so `UserID` and `GroupID` occur on different entities; the current queries combine all entity property names and create absent optional columns as null before joining.

## Clickable names in Excel

Power Query cannot create active worksheet hyperlinks by itself. To add them:

1. Open the VBA editor with `Alt+F11`.
2. Import `Excel\LocalAdminLinks.bas` into the workbook.
3. Run `RefreshLocalAdminView` instead of **Refresh All**.

The macro refreshes every query, waits for asynchronous queries, and then links each populated `UserName` or `GroupName` cell in `LocalAdminResolved` to the matching row in the appropriate detail worksheet. It uses `LocalAdminLinkMap` and the original SID internally, so duplicate display names still resolve to the correct detail row.

`BuildLocalAdminDetailLinks` can be run independently if the workbook was already refreshed.

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
| Stress-test upload | Table | Object | Add, Update |
| Stress-test removal or table clearing | Table | Object | Read, Delete |
| Complete stress-test lifecycle with one temporary token | Table | Object | Read, Delete, Add, Update |

Use **HTTPS only** for every token. **Service**, **Container**, **List**, and **Create** are not needed because all workflows address three tables that already exist. Do not reuse a write-enabled token in the browser or workbook.

### Least-privilege remediation SAS

For `Remediation\Remediate-Write-AdminsToAZTable.ps1`, generate an **account SAS** with only these portal options selected:

- Allowed services: **Table**.
- Allowed resource types: **Object**.
- Allowed permissions: **Read**, **Add**, and **Update**.
- Allowed protocols: **HTTPS only**.

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **Delete**, **List**, **Create**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The resulting access is equivalent to `ss=t`, `srt=o`, and `sp=rau`.

The remediation uses **Read** to query existing entities and **Add** plus **Update** for insert-or-replace upserts. All three tables must already exist; the script does not create or delete tables or entities. Use the shortest practical expiry and restrict the SAS to known outbound IPv4 addresses where applicable.

See Microsoft's [account SAS permissions by operation](https://learn.microsoft.com/rest/api/storageservices/create-account-sas#account-sas-permissions-by-operation) for the Table service mapping.

This remediation SAS is intentionally insufficient for `New-WriteAdminsStressTestData.ps1 -ClearTables` or `-RemoveStressData`, which also require **Delete**.

## Query outputs

### LocalAdminResolved

Contains the source `LocalAdminCollection` fields with `ComputerName` first and `SID` second. The source `UserID` and `GroupID` fields are presented as `UserName` and `GroupName`, containing resolved names rather than SIDs. `EntraOrHybrid` is translated to `Entra joined`, `Hybrid joined`, or `Domain joined`. `RowKey` is converted to a number and sorted ascending.

The presentation applies these mappings:

- `Computername` becomes `ComputerName` and moves to the first column.
- `PartitionKey` becomes `SID` and moves to the second column.
- `UserID` becomes `UserName` and contains the resolved `SamAccountName` from `AdminUserNames`.
- `GroupID` becomes `GroupName` and contains the resolved group name from `AdminGroups`.

If a lookup is missing, the original SID remains visible instead of being discarded. Removed records remain in the result and can be filtered with the `Removed` column.

### AdminUserDetails

Contains `UserID` (SID), `SamAccountName`, `UserPrincipalName`, `LocalOrEntraOrAD`, and the Azure entity `Timestamp`.

### AdminGroupDetails

Contains `GroupID` (SID), `GroupName`, `LocalOrEntraOrAD`, and the Azure entity `Timestamp`.

Source codes are `L` for local, `E` for Microsoft Entra ID, and `A` for Active Directory.

## Stress-test data

`New-WriteAdminsStressTestData.ps1` creates deterministic, schema-valid test data for validating Excel refresh and transformation performance. Its defaults create:

- 10,008 `LocalAdminCollection` rows across 834 synthetic computers.
- 7,506 linked `AdminUserNames` rows.
- 2,502 linked `AdminGroups` rows.
- A mix of local, Microsoft Entra ID, and Active Directory principals and device join states.
- Deterministically distributed removed entries for status filtering and demonstrations.
- Localized Administrators group names in English, German, French, Spanish, Italian, and Dutch.
- Report timestamps distributed across a six-hour period.

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

Leave **Blob**, **File**, **Queue**, **Service**, **Container**, **Write**, **List**, **Create**, **Process**, **Immutable storage**, and **Permanent delete** unselected. The script never creates, lists, or deletes the table resources themselves; `-ClearTables` deletes all entities while retaining the three tables.

For the narrowest access, use one **Add + Update** token for `-Execute`, a separate **Read** token for report validation, and one short-lived **Read + Delete** token for cleanup. All three tables must exist before the test begins.

Run a dry run first:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1
```

Write the entities by passing the target storage account and SAS token:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -Execute
```

The defaults exceed 10,000 main rows because 834 computers multiplied by 12 entries equals 10,008. The following tested configuration creates exactly 20,000 main rows:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ComputerCount 1000 -EntriesPerComputer 20 -Execute
```

The generated keys and names are deterministic. Running the command again replaces the same entities rather than creating duplicates. Synthetic computer names start with `STRESS`, user names start with `StressUsr`, and group names start with `StressGroup`.

After generating test data, replace the workbook's `GetAzureAdminTable` query with `Excel\GetAzureAdminTable.pq` before refreshing. This version follows Azure Table continuation headers and retrieves every page beyond 1,000 entities.

## Remove stress-test data

Preview removal of only the deterministic stress-test entities:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -RemoveStressData -WhatIf
```

Remove the stress-test entities while preserving collected device data:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -RemoveStressData
```

The script identifies generated rows by the `STRESS`, `StressUsr`, and `StressGroup` prefixes. It requests confirmation before deletion. Add `-Force` for unattended execution.

## Clear all table data

Preview removal of every entity in all three solution tables:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ClearTables -WhatIf
```

Clear `LocalAdminCollection`, `AdminUserNames`, and `AdminGroups`:

```powershell
pwsh.exe -NoProfile -File .\New-WriteAdminsStressTestData.ps1 -StorageAccountName '<storage-account-name>' -SasToken '<sas-token>' -ClearTables
```

This operation retains the Azure Table resources but removes every entity they contain. It requests confirmation before deletion. Add `-Force` for unattended execution. The SAS token must include **Read** and **Delete** permissions as described in [SAS settings for stress testing](#sas-settings-for-stress-testing).

## Change history

See [changelog.md](changelog.md) for the solution change history.
