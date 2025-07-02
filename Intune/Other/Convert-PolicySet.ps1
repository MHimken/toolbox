<#
THIS SCRIPT IS NOT DONE!
.SYNOPSIS
This script will take any given Policy Set and convert it to direct assignments
.DESCRIPTION
Policy sets have not received any update in quite some time, thus it can be savely assumed there won't be
any future development. Hence this script aims to make the move to more direct assignments easier. Keep in
mind, that the overview that policy sets provided will not be available anymore. You can either use the 
output of this script to see the assignments and put them in your documentation or use the Group Centric
Documentation script on my GitHub to figure out assignments.
.NOTES
    Version: 0.1
    Versionname: PolicySetsBeGone
    Intial creation date: 14.05.2025
    Last change date: 22.05.2025
    Latest changes: TODO: Put .MD here
    Shoutouts: 
#>
#USE CONNECT MGGRAPH FIRST
#CURRENTLY ISSUE: https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/3332
param(
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\ConvertPolicySet\",
    [System.IO.DirectoryInfo]$LogDirectory = "C:\ConvertPolicySet\",
    $CertificateThumbprint,
    $ClientID,
    $TenantId
)

if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId
}
function Get-ScriptPath {
    <#
    .SYNOPSIS
    Get the current script path.
    #>
    if ($PSScriptRoot) { 
        # Console or VS Code debug/run button/F5 temp console
        $ScriptRoot = $PSScriptRoot 
    } else {
        if ($psISE) { 
            Split-Path -Path $psISE.CurrentFile.FullPath
        } else {
            if ($profile -match 'VScode') { 
                # VS Code "Run Code Selection" button/F8 in integrated console
                $ScriptRoot = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
            } else { 
                Write-Output 'unknown directory to set path variable. exiting script.'
                exit
            } 
        } 
    }
    $Script:PathToScript = $ScriptRoot
}
function Initialize-Script {
    <#
    .SYNOPSIS
    Will initialize most of the required variables throughout this script.
    #>
    $LogPrefix = "CPS"
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    if (-not($Script:CurrentLocation)) {
        $Script:CurrentLocation = Get-Location
    }
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null } 
    if ((Get-Location).path -ne $WorkingDirectory) {
        Set-Location $WorkingDirectory
    }
    Get-ScriptPath
    if (-not($Script:LogFile)) {
        $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
        if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    }
    if ($PSVersionTable.psversion.major -lt 7) {
        Write-Log -Message 'Please follow the manual - PowerShell 7 is currently recommended to run this script.' -Component 'InitializeScript' -Type 2
    }
}
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of the script by Ryan Ephgrave.
        .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type
    )
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
        } elseif ($ToConsole) {
            switch ($type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}
function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $nextLink = ''
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}
function Get-PolicySetInfo {
    $PolicySets = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/policySets/"
    if ($PolicySets.'@odata.nextLink') {
        $PolicySets = Get-nextLinkData -OriginalObject $PolicySets
    }
    $PolicySetObjects = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($PolicySet in $PolicySets.value) {
        $PolicySetAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/policySets/$($PolicySet.id)/?`$expand=assignments,items"
        $PolicySetObject = [PSCustomObject]@{
            ID            = $PolicySet.id
            PolicySetName = $PolicySet.displayName
            Description   = $PolicySet.description
            LastModified  = $PolicySet.lastModifiedDateTime
            CreatedDate   = $PolicySet.createdDateTime
            Assignments   = @()
            Items         = @()
            DeleteFlag    = $true
        }
        #Find and list all assignments
        foreach ($PolicySetAssignment in $PolicySetAssignments.assignments ) {
            $DeletePolicySetAssignment = $true
            $GroupDisplayName = (Get-MgGroup -GroupId $PolicySetAssignments.assignments.target.groupid).DisplayName
            $GroupMemberCount = (Get-MgGroupMember -GroupId $PolicySetAssignments.assignments.target.groupid).count
            if ($GroupMemberCount -ge 1 ) {
                $DeletePolicySetAssignment = $false
                $PolicySetObject.DeleteFlag = $false
            } else {
                Write-Log -Message "Group $($GroupDisplayName) has no members" -Component 'GetPolicySet' -Type 2
            }
            <#
            #Evaluate Intune filters of the assignment (if any)
            if ($PolicySetAssignment.include) {
                $rule = '(device.deviceTrustType -in ["Hybrid Azure AD joined"])'
                $file = New-TemporaryFile
                Invoke-MgGraphRequest -Uri "beta/deviceManagement/evaluateAssignmentFilter" -Method POST -Body @{data = @{platform = "Windows10AndLater"; rule = $rule } } -OutputFilePath $file
                $data = Get-Content $file | ConvertFrom-Json -Depth 100
            }#>

            $PolicySetAssignmentInfo = [PSCustomObject]@{
                PolicySetAssignmentID     = $PolicySetAssignment.id
                GroupDisplayName          = $GroupDisplayName
                GroupMemberCount          = $GroupMemberCount
                Include                   = $PolicySetAssignment.include
                Exclude                   = $PolicySetAssignment.exclude
                DeletePolicySetAssignment = $DeletePolicySetAssignment
            }
            $PolicySetObject.Assignments += $PolicySetAssignmentInfo
        }
        #Find and list all items to assign to the groups directly later - only if the assignment is kept
        if ($PolicySetObject.DeleteFlag -eq $false) {
            foreach ($Item in $PolicySetAssignments.items) {
                $PolicySetItem = [PSCustomObject]@{
                    ItemID          = $Item.id
                    ItemDisplayName = $Item.displayName
                    ItemType        = $Item.type
                    ItemDescription = $Item.description
                }
                $PolicySetObject.Items += $PolicySetItem
            }
        }
        $PolicySetObjects.Add($PolicySetObject)
    }
}

#Start Coding!

Initialize-Script
Get-PolicySetInfo
Write-Log -Message "All done. Thanks for using one of my scripts!" -Component 'GetPolicySetInfo'