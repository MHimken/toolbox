#Requires -Version 7.0
<#
.SYNOPSIS
    Exercises group classification and relationship logic without Microsoft Graph access.
.DESCRIPTION
    Extracts the pure generator functions from the script and tests type call plans, cycle-safe
    relationship resolution, and dangerous-group propagation. Pester is not required.
#>

Set-StrictMode -Version Latest
$GeneratorPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Export-EntraGroupExplorer.ps1'
$Tokens = $null
$ParseErrors = $null
$GeneratorAst = [System.Management.Automation.Language.Parser]::ParseFile($GeneratorPath, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors | Out-String) }
$FunctionNamesToLoad = @(
    'Get-GraphField', 'Get-GroupType', 'Get-GroupCallPlan', 'New-CountRequest',
    'Add-GroupFlag', 'Set-CountResult', 'Set-GroupChildrenFromResponse', 'Get-MembershipCount',
    'Resolve-GroupRelationship', 'Set-DangerousGroupFlag', 'Import-DangerousGroupDefinition'
)
$FunctionAsts = @($GeneratorAst.FindAll({
    param($SyntaxNode)
    $SyntaxNode -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $SyntaxNode.Name -in $FunctionNamesToLoad
}, $true))
if ($FunctionAsts.Count -ne $FunctionNamesToLoad.Count) { throw 'A required test function was not found in the generator.' }
$FunctionSource = ($FunctionAsts | ForEach-Object { $_.Extent.Text }) -join "`n"
. ([scriptblock]::Create($FunctionSource))

$DangerousGroup = @()
$DangerousGroupFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'Config\DangerousGroups.sample.json'
$TreatRoleAssignableAsDangerous = $false

function Test-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Write-Log {}

function Invoke-GraphBatch {
    param([object[]]$Requests)
    foreach ($Request in $Requests) {
        $RequestUrl = [string]$Request.url
        $GroupIdMatch = [regex]::Match($RequestUrl, '^/groups/([^/]+)/')
        $GroupIdValue = $GroupIdMatch.Groups[1].Value
        $Count = 0
        if ($RequestUrl -match 'transitiveMembers/microsoft\.graph\.user') {
            $Count = 3
        } elseif ($RequestUrl -match 'transitiveMembers/microsoft\.graph\.device') {
            $Count = 4
        } elseif ($RequestUrl -match 'members/microsoft\.graph\.user') {
            $Count = if ($GroupIdValue -eq 'm365') { 2 } elseif ($GroupIdValue -eq 'security') { 1 } else { 1 }
        } elseif ($RequestUrl -match 'members/microsoft\.graph\.device') {
            $Count = if ($GroupIdValue -eq 'security') { 2 } else { 1 }
        } elseif ($RequestUrl -match 'members/microsoft\.graph\.group') {
            $Count = if ($GroupIdValue -eq 'security') { 1 } else { 0 }
        }
        $Body = @{ '@odata.count' = $Count }
        if ($RequestUrl -match 'members/microsoft\.graph\.group' -and $GroupIdValue -eq 'security') {
            $Body.value = @(@{ id = 'child' })
        }
        [pscustomobject]@{ id = $Request.id; status = 200; body = $Body; headers = @{} }
    }
}

$BatchSize = 20
$Script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'
$Script:UnavailableGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$MembershipGroups = @(
    [ordered]@{ id = 'm365'; groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false; type = ''; membership = ''; counts = $null; children = @(); parents = @(); flags = @() }
    [ordered]@{ id = 'security'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; type = ''; membership = ''; counts = $null; children = @(); parents = @(); flags = @() }
    [ordered]@{ id = 'child'; groupTypes = @(); mailEnabled = $false; securityEnabled = $true; type = ''; membership = ''; counts = $null; children = @(); parents = @(); flags = @() }
)
$MembershipIndex = Get-MembershipCount -Groups $MembershipGroups
Test-Condition ($MembershipIndex -is [System.Collections.Generic.Dictionary[string, object]]) 'Membership collection returns an id index'
Test-Condition ($MembershipIndex['m365'].type -eq 'm365') 'Membership collection preserves group classification'
Test-Condition ($MembershipIndex['m365'].counts.nested.users -eq 2) 'Leaf nested user count equals the direct count'
Test-Condition ($MembershipIndex['m365'].counts.direct.devices -eq 0) 'Unsupported device count is zero for a Microsoft 365 group'
Test-Condition ($MembershipIndex['security'].counts.direct.groups -eq 1) 'Direct child count is collected'
Test-Condition ($MembershipIndex['security'].children[0] -eq 'child') 'Direct child id is collected from the batch response'
Test-Condition ($MembershipIndex['security'].counts.nested.users -eq 3) 'Transitive user count is collected'
Test-Condition ($MembershipIndex['security'].counts.nested.devices -eq 4) 'Transitive device count is collected'

$M365 = [pscustomobject]@{ groupTypes = @('Unified'); mailEnabled = $true; securityEnabled = $false }
$DynamicSecurity = [pscustomobject]@{ groupTypes = @('DynamicMembership'); mailEnabled = $false; securityEnabled = $true }
$Distribution = [pscustomobject]@{ groupTypes = @(); mailEnabled = $true; securityEnabled = $false }
$Unknown = [pscustomobject]@{ groupTypes = @(); mailEnabled = $false; securityEnabled = $false }
Test-Condition ((Get-GroupType $M365).Type -eq 'm365') 'Microsoft 365 group type'
Test-Condition ((Get-GroupCallPlan $M365) -join ',' -eq 'users') 'Microsoft 365 call plan'
Test-Condition ((Get-GroupCallPlan $DynamicSecurity) -join ',' -eq 'users,devices') 'Dynamic security call plan'
Test-Condition ((Get-GroupCallPlan $Distribution) -join ',' -eq 'users,groups') 'Distribution call plan'
Test-Condition ((Get-GroupCallPlan $Unknown) -join ',' -eq 'users,devices,groups') 'Unknown type fallback call plan'

$GroupA = [pscustomobject]@{ id = 'a'; name = 'Dangerous Root'; children = @('b', 'c'); parents = @(); counts = @{ nested = @{ groups = 0 } }; roleAssignable = $false }
$GroupB = [pscustomobject]@{ id = 'b'; name = 'Branch B'; children = @('d'); parents = @(); counts = @{ nested = @{ groups = 0 } }; roleAssignable = $false }
$GroupC = [pscustomobject]@{ id = 'c'; name = 'Branch C'; children = @('d'); parents = @(); counts = @{ nested = @{ groups = 0 } }; roleAssignable = $false }
$GroupD = [pscustomobject]@{ id = 'd'; name = 'Cycle Leaf'; children = @('a'); parents = @(); counts = @{ nested = @{ groups = 0 } }; roleAssignable = $false }
$GroupE = [pscustomobject]@{ id = 'e'; name = 'Container'; children = @('a'); parents = @(); counts = @{ nested = @{ groups = 0 } }; roleAssignable = $false }
$Groups = @($GroupA, $GroupB, $GroupC, $GroupD, $GroupE)
$GroupIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($Group in $Groups) { $GroupIndex[$Group.id] = $Group }
Resolve-GroupRelationship -Groups $Groups -GroupIndex $GroupIndex
Test-Condition ($GroupA.counts.nested.groups -eq 3) 'Cycle-safe distinct descendant count'
Test-Condition ($GroupD.parents.Count -eq 2) 'Diamond parent inversion'

$DangerRule = [pscustomobject]@{ id = 'a'; reason = 'Synthetic test rule' }
Set-DangerousGroupFlag -Groups $Groups -Rules @($DangerRule) -GroupIndex $GroupIndex
Test-Condition ($GroupA.danger.self) 'Danger rule matches the selected group id'
Test-Condition ($GroupA.danger.nestedCount -eq 0) 'Danger propagation does not count the group itself'
Test-Condition ($GroupE.danger.nestedCount -eq 1) 'Dangerous descendant propagates to its parent'
Test-Condition ($GroupB.danger.ancestorCount -eq 1) 'Dangerous ancestor propagates through nested groups'
Test-Condition ($GroupD.danger.ancestorCount -eq 1) 'Danger propagation remains cycle-safe'

$SampleRules = @(Import-DangerousGroupDefinition)
Test-Condition ($SampleRules.Count -eq 1 -and $SampleRules[0].namePattern -eq 'SG-Tier0-*') 'Sample dangerous-group rule loads'

Write-Output 'Group graph checks passed.'
