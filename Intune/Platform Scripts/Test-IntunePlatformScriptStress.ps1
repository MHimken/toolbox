<#
.SYNOPSIS
    Creates or removes unassigned Intune platform scripts for stress testing.
.DESCRIPTION
    Creates simple Intune platform scripts through Microsoft Graph and measures the platform-script
    limit against the real number of platform scripts in the tenant.

    The tenant is enumerated before creation starts, so an existing brownfield population is counted
    toward the limit. Creation stops when the target is reached or Microsoft Graph rejects a request.
    The tenant is enumerated again afterward, which reports the observed limit as a verified
    tenant-wide total rather than a count of newly created scripts.

    Generated scripts are not assigned to users, devices, or groups. Cleanup enumerates every
    page of platform scripts and removes only scripts whose display names start with NamePrefix.

    The script uses only Microsoft.Graph.Authentication, Connect-MgGraph, Get-MgContext, and
    Invoke-MgGraphRequest for Microsoft Graph access.
.PARAMETER Create
    Creates unassigned stress-test platform scripts.
.PARAMETER Cleanup
    Removes all platform scripts whose display names start with NamePrefix.
.PARAMETER Count
    The maximum number of platform scripts to add to the existing tenant population. The default is 10.
.PARAMETER TargetTotalCount
    The tenant-wide total number of platform scripts to reach. The script creates only the difference
    between the current tenant total and this value, which supports stress testing a brownfield tenant.
.PARAMETER NamePrefix
    The prefix used to identify stress-test platform scripts during creation and cleanup.
.PARAMETER ScriptContent
    The PowerShell content stored in each generated platform script.
.PARAMETER DelayMilliseconds
    The delay between creation requests. The default is zero milliseconds.
.PARAMETER TenantId
    The Microsoft Entra tenant ID used for certificate authentication.
.PARAMETER ClientId
    The application ID used for certificate authentication.
.PARAMETER CertificateThumbprint
    The certificate thumbprint used for certificate authentication.
.PARAMETER LogPath
    The folder used for the log file. The default is the current folder.
.PARAMETER LogFile
    The log file name. When omitted, a timestamped name is generated.
.PARAMETER ToConsole
    Writes log messages to the console instead of the log file.
.EXAMPLE
    .\Test-IntunePlatformScriptStress.ps1 -Create -Count 100 -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint '<CertificateThumbprint>' -ToConsole

    Adds up to 100 unassigned stress-test scripts to the existing tenant population. The output
    includes the tenant-wide count before and after creation.
.EXAMPLE
    .\Test-IntunePlatformScriptStress.ps1 -Create -TargetTotalCount 5000 -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint '<CertificateThumbprint>' -DelayMilliseconds 100 -ToConsole

    Enumerates the current tenant population and creates only enough unassigned scripts to reach
    a tenant-wide total of 5000. Creation stops if Microsoft Graph rejects a request first.
.EXAMPLE
    .\Test-IntunePlatformScriptStress.ps1 -Cleanup -NamePrefix 'IntunePlatformScriptStress-' -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint '<CertificateThumbprint>' -ToConsole

    Deletes all platform scripts whose display names start with the specified stress-test prefix.
    Scripts with other names remain unchanged.
.NOTES
Version: 0.4
Author: Martin Himken
Original script name: Test-IntunePlatformScriptStress.ps1
Initial creation date: 2026-10-06
Last change: 2026-10-06
Changes: Added examples for fixed-count creation, tenant-total targeting, and cleanup.
#>

[CmdletBinding(DefaultParameterSetName = 'Create', SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CreateTarget')]
    [switch]$Create,

    [Parameter(Mandatory = $true, ParameterSetName = 'Cleanup')]
    [switch]$Cleanup,

    [Parameter(ParameterSetName = 'Create')]
    [ValidateRange(1, 100000)]
    [int]$Count = 10,

    [Parameter(Mandatory = $true, ParameterSetName = 'CreateTarget')]
    [ValidateRange(1, 100000)]
    [int]$TargetTotalCount,

    [ValidateNotNullOrEmpty()]
    [string]$NamePrefix = 'IntunePlatformScriptStress-',

    [Parameter(ParameterSetName = 'Create')]
    [Parameter(ParameterSetName = 'CreateTarget')]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptContent = 'Write-Output "Intune platform script stress test"',

    [Parameter(ParameterSetName = 'Create')]
    [Parameter(ParameterSetName = 'CreateTarget')]
    [ValidateRange(0, 60000)]
    [int]$DelayMilliseconds = 0,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null,
    [switch]$ToConsole
)

$Pwsh7Path = Get-Command pwsh -ErrorAction SilentlyContinue
if (-not $Pwsh7Path) {
    Write-Error 'PowerShell 7 is required. Install PowerShell 7 and run the script again.'
    exit 1
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error 'This script must run in PowerShell 7. Start the script with pwsh.exe.'
    exit 1
}

function Write-Log {
    <#
    .DESCRIPTION
    This is a heavily modified version of the script by Ryan Ephgrave.
    .LINK
    https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')]
        [int]$Type
    )
    if ($Script:LogFile) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($Script:ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
        } elseif ($Script:ToConsole) {
            switch ($Type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}

function Initialize-Script {
    param(
        [switch]$UseTargetTotalCount
    )

    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'Test-IntunePlatformScriptStress'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''

    if (-not $LogFile) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }

    if (-not (Test-Path -LiteralPath $LogPath -PathType Container)) {
        New-Item -Path $LogPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if ($NamePrefix.Length -lt 8) {
        throw 'NamePrefix must contain at least eight characters to provide a safe cleanup boundary.'
    }

    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
    $Script:ToConsole = $ToConsole.IsPresent
    $Script:ConnectedByScript = $false
    $Script:UseTargetTotalCount = $UseTargetTotalCount.IsPresent
    $Script:PlatformScriptUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts'
}

function Confirm-MgGraphConnection {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $certificateValues = @($TenantId, $ClientId, $CertificateThumbprint)
    $specifiedCertificateValues = @($certificateValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count

    if ($specifiedCertificateValues -notin @(0, 3)) {
        throw 'TenantId, ClientId, and CertificateThumbprint must be provided together.'
    }

    if ($specifiedCertificateValues -eq 3) {
        Write-Log -Message "Connecting to Microsoft Graph tenant '$TenantId' with certificate authentication." -Component 'Graph' -Type 1
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
        $Script:ConnectedByScript = $true
    } elseif (-not (Get-MgContext)) {
        Write-Log -Message 'Connecting to Microsoft Graph with delegated authentication.' -Component 'Graph' -Type 1
        Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome -ErrorAction Stop
        $Script:ConnectedByScript = $true
    }

    $context = Get-MgContext
    if (-not $context) {
        throw 'A Microsoft Graph connection could not be established.'
    }

    Write-Log -Message "Connected to Microsoft Graph tenant '$($context.TenantId)' using '$($context.AuthType)' authentication." -Component 'Graph' -Type 1
}

function Get-IntunePlatformScriptInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $allScripts = [System.Collections.Generic.List[object]]::new()
    $matchingScripts = [System.Collections.Generic.List[object]]::new()
    $uri = "$($Script:PlatformScriptUri)?`$select=id,displayName&`$top=100"

    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
        foreach ($item in @($page.value)) {
            $allScripts.Add($item)
            if ($item.displayName -like "$Prefix*") {
                $matchingScripts.Add($item)
            }
        }
        $uri = [string]$page.'@odata.nextLink'
    }

    return [pscustomobject]@{
        TotalCount      = $allScripts.Count
        MatchingScripts = $matchingScripts
    }
}

function New-IntuneStressPlatformScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $requestBody = @{
        '@odata.type'         = '#microsoft.graph.deviceManagementScript'
        displayName           = $DisplayName
        description           = 'Unassigned stress-test script created by Test-IntunePlatformScriptStress.ps1.'
        scriptContent         = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))
        fileName              = "$DisplayName.ps1"
        runAsAccount          = 'system'
        runAs32Bit            = $false
        enforceSignatureCheck = $false
    }

    $createdScript = Invoke-MgGraphRequest -Method POST -Uri $Script:PlatformScriptUri -Body $requestBody -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if (-not $createdScript.id) {
        throw "Microsoft Graph did not return an ID for platform script '$DisplayName'."
    }

    return $createdScript
}

function Remove-IntuneStressPlatformScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    $uri = "$($Script:PlatformScriptUri)/$ScriptId"
    Invoke-MgGraphRequest -Method DELETE -Uri $uri -ErrorAction Stop | Out-Null
}

function Invoke-CreateStressScripts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $runId = "$(Get-Date -Format 'yyyyMMddTHHmmssfff')-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $createdScripts = [System.Collections.Generic.List[object]]::new()
    $failureMessage = $null
    $failedSequence = $null

    $baselineInventory = Get-IntunePlatformScriptInventory -Prefix $NamePrefix
    $baselineTotalCount = $baselineInventory.TotalCount
    Write-Log -Message "The tenant currently holds $baselineTotalCount platform script(s), of which $($baselineInventory.MatchingScripts.Count) match the prefix '$NamePrefix'." -Component 'Create' -Type 1

    if ($Script:UseTargetTotalCount) {
        $plannedCount = $TargetTotalCount - $baselineTotalCount
        if ($plannedCount -le 0) {
            Write-Log -Message "The tenant already holds $baselineTotalCount platform script(s), which reaches the target total of $TargetTotalCount. No scripts were created." -Component 'Create' -Type 2
            $plannedCount = 0
        } else {
            Write-Log -Message "Creating $plannedCount platform script(s) to reach the tenant-wide target total of $TargetTotalCount." -Component 'Create' -Type 1
        }
    } else {
        $plannedCount = $Count
        Write-Log -Message "Creating up to $plannedCount platform script(s) in addition to the existing $baselineTotalCount script(s)." -Component 'Create' -Type 1
    }

    for ($index = 1; $index -le $plannedCount; $index++) {
        $displayName = "$NamePrefix$runId-$($index.ToString('D6'))"
        $projectedTotalCount = $baselineTotalCount + $createdScripts.Count + 1

        if (-not $PSCmdlet.ShouldProcess($displayName, 'Create unassigned Intune platform script')) {
            continue
        }

        try {
            Write-Log -Message "Creating unassigned platform script '$displayName' for tenant-wide total $projectedTotalCount." -Component 'Create' -Type 1
            $createdScript = New-IntuneStressPlatformScript -DisplayName $displayName -Content $ScriptContent
            $createdScripts.Add($createdScript)
        } catch {
            $failedSequence = $index
            $failureMessage = $_.Exception.Message
            Write-Log -Message "Creation stopped while adding tenant-wide platform script number $projectedTotalCount. Microsoft Graph returned: $failureMessage" -Component 'Create' -Type 2
            break
        }

        if ($DelayMilliseconds -gt 0 -and $index -lt $plannedCount) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }

    $finalInventory = Get-IntunePlatformScriptInventory -Prefix $NamePrefix
    $observedLimit = $null
    if ($failureMessage) {
        $observedLimit = $finalInventory.TotalCount
    }

    $result = [pscustomobject]@{
        Action                = 'Create'
        NamePrefix            = $NamePrefix
        RunId                 = $runId
        CreationMode          = if ($Script:UseTargetTotalCount) { 'TargetTotal' } else { 'FixedCount' }
        BaselineTotalCount    = $baselineTotalCount
        BaselineMatchingCount = $baselineInventory.MatchingScripts.Count
        PlannedCount          = $plannedCount
        CreatedCount          = $createdScripts.Count
        FinalTotalCount       = $finalInventory.TotalCount
        FinalMatchingCount    = $finalInventory.MatchingScripts.Count
        ObservedLimit         = $observedLimit
        FailedSequence        = $failedSequence
        GraphFailureMessage   = $failureMessage
        Assigned              = $false
    }

    Write-Log -Message "Creation test completed. Baseline total: $baselineTotalCount. Planned: $plannedCount. Created: $($createdScripts.Count). Verified tenant total: $($finalInventory.TotalCount). Observed limit: $observedLimit." -Component 'Create' -Type 1
    return $result
}

function Invoke-CleanupStressScripts {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $baselineInventory = Get-IntunePlatformScriptInventory -Prefix $NamePrefix
    $scriptsToDelete = @($baselineInventory.MatchingScripts)
    $deletedCount = 0
    $failedScripts = [System.Collections.Generic.List[string]]::new()

    Write-Log -Message "The tenant currently holds $($baselineInventory.TotalCount) platform script(s), of which $($scriptsToDelete.Count) match the prefix '$NamePrefix'." -Component 'Cleanup' -Type 1

    foreach ($platformScript in $scriptsToDelete) {
        if (-not $PSCmdlet.ShouldProcess($platformScript.displayName, 'Delete Intune stress-test platform script')) {
            continue
        }

        try {
            Remove-IntuneStressPlatformScript -ScriptId $platformScript.id
            $deletedCount++
            Write-Log -Message "Deleted platform script '$($platformScript.displayName)' ($($platformScript.id))." -Component 'Cleanup' -Type 1
        } catch {
            $failedScripts.Add("$($platformScript.displayName): $($_.Exception.Message)")
            Write-Log -Message "Could not delete platform script '$($platformScript.displayName)': $($_.Exception.Message)" -Component 'Cleanup' -Type 3
        }
    }

    $finalInventory = Get-IntunePlatformScriptInventory -Prefix $NamePrefix

    $result = [pscustomobject]@{
        Action             = 'Cleanup'
        NamePrefix         = $NamePrefix
        BaselineTotalCount = $baselineInventory.TotalCount
        MatchedCount       = $scriptsToDelete.Count
        DeletedCount       = $deletedCount
        FinalTotalCount    = $finalInventory.TotalCount
        FinalMatchingCount = $finalInventory.MatchingScripts.Count
        FailedCount        = $failedScripts.Count
        FailureDetails     = @($failedScripts)
    }

    Write-Log -Message "Cleanup completed. Matched: $($scriptsToDelete.Count). Deleted: $deletedCount. Failed: $($failedScripts.Count). Verified tenant total: $($finalInventory.TotalCount)." -Component 'Cleanup' -Type 1
    return $result
}

function Invoke-IntunePlatformScriptStressTest {
    Confirm-MgGraphConnection

    if ($Create) {
        return Invoke-CreateStressScripts
    }

    return Invoke-CleanupStressScripts
}

Initialize-Script -UseTargetTotalCount:$PSBoundParameters.ContainsKey('TargetTotalCount')

try {
    $result = Invoke-IntunePlatformScriptStressTest
    $result

    if ($result.Action -eq 'Cleanup' -and $result.FailedCount -gt 0) {
        throw "Cleanup failed for $($result.FailedCount) platform script(s)."
    }
} catch {
    Write-Log -Message "The stress test stopped: $($_.Exception.Message)" -Component 'Runner' -Type 3
    Write-Error $_.Exception.Message
    exit 1
} finally {
    if ($Script:ConnectedByScript -and (Get-MgContext)) {
        Disconnect-MgGraph | Out-Null
    }
}
