# Entra Group Explorer

Exports Entra groups and direct or nested counts of users, devices, and groups to JSON, then builds a self-contained HTML explorer. The viewer starts with a centered live search. Selecting a group shows its parent groups above it and nested groups below it. It does not export individual membership objects.

## Requirements

- PowerShell 7
- `Microsoft.Graph.Authentication` with `Invoke-MgGraphRequest` parameters `-SkipHttpErrorCheck`, `-StatusCodeVariable`, and `-ResponseHeadersVariable`
- Delegated Microsoft Graph permission `GroupMember.Read.All`
- For hidden-membership groups, `Member.Read.Hidden` and a supported Entra role

The generator is read-only. It reads group properties and memberships. It does not modify Entra.

## Generate an export

```powershell
Connect-MgGraph -Scopes 'GroupMember.Read.All'
.\Export-EntraGroupExplorer.ps1
```

By default, the script writes timestamped `.json` and `.html` files under `Output\`. Pass `-TenantId` to choose a tenant during sign-in. If the current Graph context lacks a required scope, connect with that scope before running the script.

Use the synthetic demo file to generate a local report without Graph access:

```powershell
.\Export-EntraGroupExplorer.ps1 `
    -DataFile .\Demo\EntraGroupExplorer-demo.json `
    -OutputPath .\Output
```

`-DataFile` always creates new timestamped files and never overwrites its input. Use `-SkipHtml` to export JSON only and `-OpenReport` to open the generated HTML.

## Viewer options

| Parameter | Default | Description |
| --- | --- | --- |
| `OutputPath` | `Output\` | Output directory. |
| `OutputName` | `EntraGroupExplorer` | Base filename for generated files. |
| `MaxNameLength` | `30` | Abbreviation limit; also sets the width of the tree cards. Use `0` to disable. |
| `AbbreviationStyle` | `Middle` | `Middle` retains the start and end; `End` retains the start. |
| `InitialDepth` | `2` | Initially expanded levels above and below the selected group. |
| `AutoExpandLimit` | `10` | Nested branches with more related groups start collapsed. Use `0` to disable. |
| `DangerousGroup` | none | Group object ids, exact names, or wildcard name patterns. |
| `DangerousGroupFile` | `Config\DangerousGroups.json` | Optional schema-version-1 rule file. |
| `TreatRoleAssignableAsDangerous` | off | Also marks role-assignable groups. |
| `IncludeHiddenMembership` | off | Requests the hidden-membership permission. |
| `IncludeMembershipRule` | off | Includes dynamic membership rule text in JSON. |
| `BatchSize` | `20` | Graph sub-requests per batch, from 1 to 20. |
| `MaxRetries` | `6` | Retries for throttled or transient Graph responses. |
| `MaxUnavailablePercent` | `10` | Exit code 2 threshold for groups with unavailable counts. |
| `DataFile` | none | Rebuilds derived data and HTML from a prior JSON snapshot. |
| `SkipHtml` | off | Writes only JSON. |
| `OpenReport` | off | Opens the generated HTML report. |

Example dangerous-group rules are in `Config\DangerousGroups.sample.json`. Copy the sample to `Config\DangerousGroups.json` and edit it locally. The real config and all files in `Output\` are ignored by git. Keep generated exports and logs within approved storage because group names, ids, descriptions, and membership counts are tenant data.

## Share a selected group

Selecting a group adds its object id to the URL fragment as `#group=<id>`. Copy the URL from the browser to share the selected center group. Opening the link selects that group automatically; Back and Forward move between previously selected groups. Links with `?group=<id>` are also accepted.

This works with a local HTML file in browsers that support same-document history updates for `file:` URLs. A local `C:\...` link only works on that machine; recipients need access to the same file path, such as a shared network location. For broader sharing, host the self-contained HTML report on a web server. If the linked group is not part of that report's snapshot, the page displays a message and leaves the search available.

## Tenant behavior probes

`Tests\Test-GraphProbe.ps1` runs read-only probes and prints statuses, counts, and Graph resource units. It writes no group or member data to disk. Supply only test-group ids whose membership shape you know:

```powershell
.\Tests\Test-GraphProbe.ps1 `
    -GroupId '<group-id>' `
    -TransitiveCountGroupId '<two-child-groups-with-one-shared-user>' `
    -ServicePrincipalGroupId '<group-with-a-service-principal>' `
    -DistributionGroupId '<assigned-distribution-group>'
```

The T1 scope probe is conclusive only when the Graph session has exactly `GroupMember.Read.All`; run it in a fresh session. Probe hidden-membership behavior separately after connecting with both `GroupMember.Read.All` and `Member.Read.Hidden`. The T4 fixture must have no direct users and exactly two child groups, each containing the same single user.

## Tests

```powershell
pwsh -NoProfile -File .\Tests\GroupGraph.Tests.ps1
pwsh -NoProfile -File .\Tests\HtmlOutput.Tests.ps1
node .\Tests\Viewer.Logic.Tests.js
```

The tests do not require Pester or tenant credentials. A live Graph run and browser accessibility checks remain environment-specific validation.
