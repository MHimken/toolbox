#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Extracts Office AddIn registry key names from all user profiles and exports them to a custom WMI class.
.DESCRIPTION
    Reads Office AddIns paths under HKEY_USERS\<SID>\Software\Microsoft\Office\<Product>\Addins for
    every user profile on the local machine (local, AD and Entra should work). Covered products are Outlook, Excel, Word, PowerPoint,
    Access, MS Project, OneNote, and Visio. Only subkey names are collected — no values or properties.
    Key names are gathered with their original casing as stored in the registry. Results are written to
    the WMI class Custom_OfficeAddins under root/cimv2.

    User hives that are not currently loaded are temporarily mounted with 'reg load' and dismounted
    after collection. Any hive that cannot be mounted is skipped with a warning.
    
    The WMI class can then be collected by ConfigMgr or queried by other inventory tools to get a complete picture of installed AddIns across all users on the device.
.NOTES
    - Requires local administrator rights (hive mounting + WMI class management).
    - Run once or multiple times per device, e.g. as an Intune Platform Script, scheduled task or remediation.
    - Existing instances in Custom_OfficeAddins are purged before each run to keep data fresh.
    Version: 0.1
    Versionname: Initial 
    Initial creation date: 16.04.2026
    Last change date: 16.04.2026
    Author: Martin Himken
    Latest changes: Initial script development.
#>

[CmdletBinding()]
param ()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$WMINamespace         = 'root/cimv2'
$WMIClassName         = 'Custom_OfficeAddins'
$OfficeAddInsTargets  = @(
    [PSCustomObject]@{ Product = 'Outlook';   SubPath = 'Software\Microsoft\Office\Outlook\Addins' },
    [PSCustomObject]@{ Product = 'Excel';     SubPath = 'Software\Microsoft\Office\Excel\Addins' },
    [PSCustomObject]@{ Product = 'Word';      SubPath = 'Software\Microsoft\Office\Word\Addins' },
    [PSCustomObject]@{ Product = 'PowerPoint';SubPath = 'Software\Microsoft\Office\PowerPoint\Addins' },
    [PSCustomObject]@{ Product = 'Access';    SubPath = 'Software\Microsoft\Office\Access\Addins' },
    [PSCustomObject]@{ Product = 'Project';   SubPath = 'Software\Microsoft\Office\Project\Addins' },
    [PSCustomObject]@{ Product = 'Project';   SubPath = 'Software\Microsoft\Office\MS Project\Addins' },
    [PSCustomObject]@{ Product = 'OneNote';   SubPath = 'Software\Microsoft\Office\OneNote\Addins' },
    [PSCustomObject]@{ Product = 'Visio';     SubPath = 'Software\Microsoft\Office\Visio\Addins' }
)

#region -- WMI helpers -------------------------------------------------------------------

function Initialize-WMIClass {
    <#
    .SYNOPSIS  Drops (if present) and re-creates the Custom_OfficeAddins WMI class.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $Namespace,
        [Parameter(Mandatory)][string] $ClassName
    )

    # Purge existing instances, then delete the class definition.
    try {
        $existingInstances = Get-WmiObject -Namespace $Namespace -Class $ClassName -ErrorAction Stop
        if ($existingInstances) {
            $existingInstances | Remove-WmiObject -ErrorAction SilentlyContinue
        }
        $existingClass = Get-WmiObject -Namespace $Namespace -List |
            Where-Object { $_.Name -eq $ClassName }
        if ($existingClass) {
            $existingClass.Delete()
            Write-Verbose "Deleted existing WMI class '$ClassName'."
        }
    } catch {
        # Class does not exist yet — nothing to remove.
        Write-Verbose "WMI class '$ClassName' not found; will create fresh."
    }

    # Build the new class definition.
    $newClass            = New-Object System.Management.ManagementClass($Namespace, [string]::Empty, $null)
    $newClass['__CLASS'] = $ClassName

    # UserSID + Product + AddInName together form the composite key.
    $newClass.Properties.Add('UserSID',   [System.Management.CimType]::String, $false)
    $newClass.Properties['UserSID'].Qualifiers.Add('Key', $true)

    $newClass.Properties.Add('Product',   [System.Management.CimType]::String, $false)
    $newClass.Properties['Product'].Qualifiers.Add('Key', $true)

    $newClass.Properties.Add('AddInName', [System.Management.CimType]::String, $false)
    $newClass.Properties['AddInName'].Qualifiers.Add('Key', $true)

    $newClass.Properties.Add('Username',  [System.Management.CimType]::String, $false)

    $newClass.Put() | Out-Null
    Write-Verbose "Created WMI class '$ClassName' in namespace '$Namespace'."
}

function Write-WMIInstance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $Namespace,
        [Parameter(Mandatory)][string] $ClassName,
        [Parameter(Mandatory)][string] $UserSID,
        [Parameter(Mandatory)][string] $Product,
        [Parameter(Mandatory)][string] $AddInName,
        [Parameter(Mandatory)][string] $Username
    )

    $wmiClass            = [WMIClass]"\\.\$Namespace`:$ClassName"
    $instance            = $wmiClass.CreateInstance()
    $instance.UserSID    = $UserSID
    $instance.Product    = $Product
    $instance.AddInName  = $AddInName
    $instance.Username   = $Username
    $instance.Put() | Out-Null
}

#endregion

#region -- Registry helpers -------------------------------------------------------------------

function Get-AllUserProfiles {
    <#
    .SYNOPSIS  Returns all user profiles (SID + hive path) from the ProfileList registry key.
    #>
    $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    Get-ChildItem -Path $profileListPath -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -or $_.PSChildName -match '^S-1-12-' } |
        ForEach-Object {
            [PSCustomObject]@{
                SID         = $_.PSChildName
                ProfilePath = $_.GetValue('ProfileImagePath')
                HivePath    = Join-Path $_.GetValue('ProfileImagePath') 'NTUSER.DAT'
            }
        }
}

function Get-LoadedUserSIDs {
    <#
    .SYNOPSIS  Returns SIDs whose hives are already mounted under HKEY_USERS.
    #>
    Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { ($_.PSChildName -match '^S-1-5-21-' -or $_.PSChildName -match '^S-1-12-') -and $_.PSChildName -notmatch '_Classes$' } |
        Select-Object -ExpandProperty PSChildName
}

function Mount-UserHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $SID,
        [Parameter(Mandatory)][string] $HivePath
    )

    if (-not (Test-Path -LiteralPath $HivePath)) {
        return $false
    }
    & reg load "HKU\$SID" $HivePath 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Dismount-UserHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $SID
    )

    # Force .NET to release any open registry handles before unloading.
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    & reg unload "HKU\$SID" 2>&1 | Out-Null
}

function Resolve-SIDToUsername {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string] $SID
    )

    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SID)
        return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $SID     # Fall back to the raw SID string if translation fails.
    }
}

#endregion

#region -- Main -------------------------------------------------------------------

Write-Host "Initializing WMI class '$WMIClassName'..." -ForegroundColor Cyan
Initialize-WMIClass -Namespace $WMINamespace -ClassName $WMIClassName

$allProfiles   = Get-AllUserProfiles
$loadedSIDs    = Get-LoadedUserSIDs
$hivesWeLoaded = [System.Collections.Generic.List[string]]::new()
$totalAddIns   = 0

foreach ($SingleProfile in $allProfiles) {
    $sid        = $SingleProfile.SID
    $hiveLoaded = $false

    # Mount the hive if it is not already present under HKEY_USERS.
    if ($sid -notin $loadedSIDs) {
        Write-Verbose "Mounting hive for SID: $sid  ($($SingleProfile.HivePath))"
        if (Mount-UserHive -SID $sid -HivePath $SingleProfile.HivePath) {
            $hivesWeLoaded.Add($sid)
            $hiveLoaded = $true
        } else {
            Write-Warning "Cannot mount registry hive for SID: $sid  — skipping."
            continue
        }
    }

    $username = Resolve-SIDToUsername -SID $sid
    foreach ($target in $OfficeAddInsTargets) {
        $addinsRegistryPath = "Registry::HKEY_USERS\$sid\$($target.SubPath)"

        if (Test-Path -LiteralPath $addinsRegistryPath) {
            $addinKeys = Get-ChildItem -LiteralPath $addinsRegistryPath -ErrorAction SilentlyContinue

            foreach ($addinKey in $addinKeys) {
                # PSChildName returns the key name exactly as stored in the registry bytes,
                # preserving the original casing (e.g. "Microsoft.Teams.AddinLoader" stays intact).
                $addinName = $addinKey.PSChildName

                Write-WMIInstance -Namespace $WMINamespace -ClassName $WMIClassName `
                    -UserSID $sid -Product $target.Product -AddInName $addinName -Username $username

                Write-Verbose "  Recorded: [$($target.Product)] '$addinName'  (user: $username)"
                $totalAddIns++
            }
        } else {
            Write-Verbose "No $($target.Product) AddIns path found for SID: $sid"
        }
    }

    # Unload any hive we mounted so we leave the system in a clean state.
    if ($hiveLoaded) {
        Write-Verbose "Dismounting hive for SID: $sid"
        Dismount-UserHive -SID $sid
    }
}

Write-Host "Done. $totalAddIns AddIn entr$(if ($totalAddIns -eq 1) { 'y' } else { 'ies' }) written to '$WMIClassName'." `
    -ForegroundColor Green

<# Quick confirmation — query the class we just populated.
Write-Host "`nWMI query result:" -ForegroundColor Cyan
Get-WmiObject -Namespace $WMINamespace -Class $WMIClassName |
    Sort-Object Username, Product, AddInName |
    Format-Table UserSID, Username, Product, AddInName -AutoSize
#>
#endregion
