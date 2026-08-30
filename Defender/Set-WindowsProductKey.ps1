<#
.SYNOPSIS
    Installs a Windows product key, activates Windows, and verifies the activation status.
.DESCRIPTION
    Designed for Defender Live Response. This script:
    * Validates the provided product key format before touching the system.
    * Installs the product key using slmgr /ipk.
    * Activates Windows using slmgr /ato.
    * Verifies the result via WMI (SoftwareLicensingProduct).

    No elevation check is performed — Defender Live Response already provides the required privileges.
    The product key is masked in all output (only the last segment is shown).
.PARAMETER ProductKey
    The Windows product key to install. Must be in the format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
.EXAMPLE
    .\Set-WindowsProductKey.ps1 -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-ABCDE"

    Installs and activates the given product key, then verifies activation status.
    Exit code 0 = success (activated and verified), Exit code 1 = failure.
.NOTES
    Version: 1.0
    Author: Martin Himken
    Original script name: Set-WindowsProductKey.ps1
    Initial creation date: 26.05.2026
    Last change: 26.05.2026
    Changes: Initial version
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$')]
    [string]$ProductKey
)

function Get-MaskedKey {
    <#
    .SYNOPSIS
        Returns the product key with all but the last segment masked.
    #>
    param ([string]$Key)
    $segments = $Key.Split('-')
    'XXXXX-XXXXX-XXXXX-XXXXX-{0}' -f $segments[-1]
}

function Invoke-SlmgrCommand {
    <#
    .SYNOPSIS
        Runs a slmgr.vbs command via cscript.exe and returns the exit code and output.
    .DESCRIPTION
        Output is captured via temp files to avoid encoding issues when reading cscript stdout.
    #>
    param (
        [string]$CscriptPath,
        [string]$SlmgrPath,
        [string[]]$Arguments
    )
    $stdOutFile = [System.IO.Path]::GetTempFileName()
    $stdErrFile = [System.IO.Path]::GetTempFileName()
    try {
        $fullArgs = @('//nologo', $SlmgrPath) + $Arguments
        $process = Start-Process -FilePath $CscriptPath -ArgumentList $fullArgs `
            -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile `
            -WindowStyle Hidden -Wait -PassThru
        $stdout = Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content -LiteralPath $stdErrFile -Raw -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ExitCode = $process.ExitCode
            Output   = if ($stdout) { $stdout.Trim() } else { '' }
            Error    = if ($stderr) { $stderr.Trim() } else { '' }
        }
    } finally {
        Remove-Item -LiteralPath $stdOutFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stdErrFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-ActivationStatus {
    <#
    .SYNOPSIS
        Returns the Windows activation status via WMI (SoftwareLicensingProduct).
    .DESCRIPTION
        Filters to the Windows OS product using ApplicationId
        '55c92734-d682-4d71-983e-d6ec3f16059f' and requires a non-empty PartialProductKey
        to exclude unused/placeholder entries. LicenseStatus 1 = Licensed (activated).
    #>
    $osProduct = Get-CimInstance -ClassName SoftwareLicensingProduct `
        -Filter "ApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey <> ''" `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $osProduct) {
        return [PSCustomObject]@{
            IsActivated = $false
            StatusCode  = -1
            Description = 'No Windows license entry found via WMI.'
        }
    }

    $statusMap = @{
        0 = 'Unlicensed'
        1 = 'Licensed'
        2 = 'Out-Of-Box Grace Period'
        3 = 'Out-Of-Tolerance Grace Period'
        4 = 'Non-Genuine Grace Period'
        5 = 'Notification'
        6 = 'Extended Grace Period'
    }
    $description = if ($statusMap.ContainsKey($osProduct.LicenseStatus)) {
        $statusMap[$osProduct.LicenseStatus]
    } else {
        "Unknown status code ($($osProduct.LicenseStatus))"
    }

    [PSCustomObject]@{
        IsActivated = ($osProduct.LicenseStatus -eq 1)
        StatusCode  = $osProduct.LicenseStatus
        Description = $description
    }
}

# ── Prerequisites ──────────────────────────────────────────────────────────────
$cscriptPath = Join-Path $env:SystemRoot 'System32\cscript.exe'
$slmgrPath   = Join-Path $env:SystemRoot 'System32\slmgr.vbs'

if (-not (Test-Path -LiteralPath $cscriptPath)) {
    Write-Output "FAIL  Prerequisites: cscript.exe not found at '$cscriptPath'."
    Exit 1
}
if (-not (Test-Path -LiteralPath $slmgrPath)) {
    Write-Output "FAIL  Prerequisites: slmgr.vbs not found at '$slmgrPath'."
    Exit 1
}

$maskedKey = Get-MaskedKey -Key $ProductKey
Write-Output "INFO  ProductKey  : $maskedKey"
Write-Output "INFO  cscript.exe : $cscriptPath"
Write-Output "INFO  slmgr.vbs   : $slmgrPath"
Write-Output ''

# ── Step 1: Install product key (slmgr /ipk) ──────────────────────────────────
Write-Output "STEP  [1/3] Installing product key..."
$ipkResult = Invoke-SlmgrCommand -CscriptPath $cscriptPath -SlmgrPath $slmgrPath -Arguments @('/ipk', $ProductKey)
if ($ipkResult.Output) { Write-Output "      $($ipkResult.Output)" }
if ($ipkResult.Error)  { Write-Output "      ERR $($ipkResult.Error)" }

if ($ipkResult.ExitCode -ne 0) {
    Write-Output "FAIL  [1/3] Product key installation failed (exit code $($ipkResult.ExitCode))."
    Exit 1
}
Write-Output "OK    [1/3] Product key installed."
Write-Output ''

# ── Step 2: Activate Windows (slmgr /ato) ─────────────────────────────────────
Write-Output "STEP  [2/3] Activating Windows..."
$atoResult = Invoke-SlmgrCommand -CscriptPath $cscriptPath -SlmgrPath $slmgrPath -Arguments @('/ato')
if ($atoResult.Output) { Write-Output "      $($atoResult.Output)" }
if ($atoResult.Error)  { Write-Output "      ERR $($atoResult.Error)" }

if ($atoResult.ExitCode -ne 0) {
    Write-Output "FAIL  [2/3] Activation attempt failed (exit code $($atoResult.ExitCode))."
    Exit 1
}
Write-Output "OK    [2/3] Activation command completed."
Write-Output ''

# ── Step 3: Verify activation status ──────────────────────────────────────────
Write-Output "STEP  [3/3] Verifying activation status (waiting 5 seconds for WMI to reflect change)..."
Start-Sleep -Seconds 5
$status = Get-ActivationStatus
Write-Output "      WMI LicenseStatus : $($status.StatusCode) - $($status.Description)"

if ($status.IsActivated) {
    Write-Output "OK    [3/3] Windows is activated."
    Write-Output ''
    Write-Output "RESULT  SUCCESS - Key $maskedKey installed and Windows activation verified."
    Exit 0
} else {
    Write-Output "FAIL  [3/3] Windows is not in Licensed state after activation."
    Write-Output ''
    Write-Output "RESULT  FAILURE - Activation command completed but license status is '$($status.Description)'."
    Exit 1
}
