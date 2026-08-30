<#
.SYNOPSIS
Escrows BitLocker recovery keys to Configuration Manager using CIM methods.

.DESCRIPTION
This script retrieves encrypted volumes from the local system and escrows their BitLocker recovery keys to the Configuration Manager infrastructure using CIM methods. When the Rotate switch is used, the script removes the existing escrowed key reference to force a new key rotation.

.PARAMETER LogPath
Path to the directory where log files will be stored. Defaults to the current folder.

.PARAMETER LogFile
Name of the log file. When omitted, the script generates a file name using the script name and a timestamp in ISO 8601 format.

.PARAMETER Rotate
If set, removes the existing escrowed key reference to force key rotation.

.NOTES
Version: 1.0
Author: Martin Himken
Original script name: Invoke-BitlockerEscrowKey.ps1
Initial creation date: 2026-08-17
Last change: 2026-08-17
Changes: Initial version with CmdletBinding, logging support, and CIM methods. PowerShell 7 requirement removed (uses only PS 5.1+ compatible features).
#>

[CmdletBinding()]
param (
    [string]$LogPath = (Get-Location).Path,
    [string]$LogFile = $null,
    [switch]$Rotate
)

function Write-Log {
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
    # Set a default log file name using ISO 8601 date-time with 24-hour timestamp.
    # Use a file-system-safe variant for Windows file names.
    $Script:DateTime = Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'
    $DefinedScriptName = 'InvokeBitlockerEscrowKey'
    $SanitizedScriptName = $DefinedScriptName -replace '\s+', ''
    if (-not($LogFile)) {
        $LogFile = "$($SanitizedScriptName)_$($Script:DateTime).log"
    }
    $Script:LogFile = Join-Path -Path $LogPath -ChildPath $LogFile
}

function Invoke-CCMBitlockerEscrowKey {
    [CmdletBinding()]
    param (
        [switch]$Rotate
    )

    $ErrorActionPreference = 'Stop'

    if ($Rotate) {
        Write-Log -Message "Removing HKLM:\SOFTWARE\Microsoft\CCM\BLM\Escrowed key (if exists) to force key rotation" -Component 'Invoke-CCMBitlockerEscrowKey' -Type 1
        Remove-Item 'HKLM:\SOFTWARE\Microsoft\CCM\BLM\Escrowed' -Recurse -ErrorAction SilentlyContinue
    }

    # Execute Package/Program
    try {
        Write-Log -Message "Retrieving drive letter(s) of encrypted volumes" -Component 'Invoke-CCMBitlockerEscrowKey' -Type 1
        $EncryptedDrives = Get-CimInstance -ClassName Win32_EncryptableVolume -Namespace 'root\cimv2\security\microsoftvolumeencryption' |
            Where-Object ProtectionStatus -EQ 1 |
            Select-Object -ExpandProperty DriveLetter

        # Loop through all encrypted drives & escrow the recovery key
        $results = foreach ($drive in $EncryptedDrives) {
            Write-Log -Message "Execute EscrowKey method for drive $drive" -Component 'Invoke-CCMBitlockerEscrowKey' -Type 1
            $escrowResult = Invoke-CimMethod -ClassName CCM_BLM_KeyEscrow -Namespace 'root\ccm\ClientSDK' -MethodName EscrowKey -Arguments @{ DriveLetter = $drive }
            [PSCustomObject]@{
                ReturnValue = $escrowResult.ReturnValue
                EscrowKey   = $escrowResult.KeyID
                DriveLetter = $drive
            }
        }
        return $results
    }
    catch {
        Write-Log -Message "Failed to escrow BitLocker keys: $_" -Component 'Invoke-CCMBitlockerEscrowKey' -Type 3
        throw
    }
}

# Initialize script at startup
Initialize-Script

Invoke-CCMBitlockerEscrowKey -Rotate:$Rotate -Verbose