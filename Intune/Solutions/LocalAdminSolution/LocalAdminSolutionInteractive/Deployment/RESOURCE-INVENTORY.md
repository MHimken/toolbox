# Local administrator reporting resource inventory

`Deploy-LocalAdminReporting.ps1` records the concrete deployment names in
`.localadmin-deployment-state.json`. The state file is local, contains no credentials, and is the
authoritative input for `-RemoveDeployment`. Do not delete it before tearing down a deployment.

## Azure resources

| Resource | Name | Created when | Removal behavior |
|---|---|---|---|
| Resource group | `ResourceGroupName` | When the selected group does not exist | Retained by default; removed only with `-RemoveResourceGroup` and only when empty |
| Inventory Storage account | `StorageAccountName` | Always | Removed with all inventory tables and data |
| Inventory tables | `LocalAdminCollection`, `AdminUserNames`, `AdminGroups`, `LocalAdminDevices` | Always | Removed with the inventory Storage account |
| Governance Storage account | `GovernanceStorageAccountName` | Always | Removed with all governance tables and data |
| Governance tables | `LocalAdminAllowRules`, `LocalAdminUserSettings`, `LocalAdminReviewActions`, `LocalAdminAuditRecords` | Always | Removed with the governance Storage account |
| Automation account | `AutomationAccountName` | Always | Removed with its managed identity, runbook, schedule, jobs, and configuration |
| Table role assignments | Deterministic GUIDs scoped to solution tables | Always | Removed with their scopes or managed identities |
| Function App | `FunctionAppName` | `BackendMode AzureFunctions` | Removed |
| Function Consumption plan | `<FunctionAppName>-plan` | `BackendMode AzureFunctions` | Removed |
| Application Insights | `<FunctionAppName>-ai` | `BackendMode AzureFunctions` | Removed |
| Application Insights Smart Detection action group | `Application Insights Smart Detection` | Azure may create it automatically with Application Insights | Explained and removed only after separate confirmation when `-RemoveResourceGroup` is used |
| Function host Storage account | `FunctionStorageAccountName` | `BackendMode AzureFunctions` | Removed with package container and uploaded packages |
| Function role assignments | Deterministic GUIDs scoped to allow-rule, profile, review-action, audit, and package resources | `BackendMode AzureFunctions` | Removed with their scopes or managed identity |
| Resource-group deployment records | `LocalAdminReporting-*` | Every Bicep deployment | Removed |

Deleting either Storage account permanently deletes its tables and data. Existing SAS values become
invalid when their Storage account is deleted.

## Microsoft Entra resources

`AppRegistrationMode Existing` app registrations are never owned by this deployment and are preserved.

For `AppRegistrationMode Create`, the script may either create a registration or reconcile an existing
registration with the same display name. State version 3 records ownership separately for the API and
SPA registrations. `-RemoveDeployment` deletes an app registration and its service principal only when
that checkpoint explicitly records that the script created it. Older checkpoints and reused
registrations are preserved because ownership cannot be proven safely.

`-ConfigureApiAppRoles` adds or updates the four `LocalAdmin.*` Admin-mode app roles on the API
registration in either mode. Unrelated roles are preserved. These roles are not removed by
`-RemoveDeployment` for preserved registrations; user role assignments remain an administrator task.

The Automation account's managed identity and Microsoft Graph app-role assignments disappear when the
Automation account is removed. The Function App managed identity disappears with the Function App.

## Local generated files

After successful cloud teardown, the removal operation deletes:

- the generated `config.json` path recorded in the checkpoint;
- `Deployment\.localadmin-deployment-state.json`.

Deployment logs and protected SAS token files are retained because they may be stored outside the
solution directory and can contain information needed for audit or incident response. Delete token
files securely when they are no longer required.

## Removal

Preview the operation:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
    -RemoveDeployment `
    -UseExistingAzureContext `
    -WhatIf
```

Remove tracked resources while retaining the resource group:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
    -RemoveDeployment `
    -UseExistingAzureContext
```

Also remove the resource group after verifying that no untracked resources remain:

```powershell
pwsh.exe -NoProfile -File .\Deployment\Deploy-LocalAdminReporting.ps1 `
    -RemoveDeployment `
    -RemoveResourceGroup `
    -UseExistingAzureContext
```

The script requires the exact confirmation text `YES`. When Azure's automatically created
`Application Insights Smart Detection` action group remains, the script explains why it exists and
requires a second `YES` before removing it. Any other untracked resource still blocks resource-group
deletion. A partial or failed removal retains the checkpoint so the operation can be retried. The
checkpoint is deleted only after all requested cloud and local cleanup succeeds.
