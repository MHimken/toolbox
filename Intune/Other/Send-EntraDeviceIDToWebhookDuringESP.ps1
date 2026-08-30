<#
.SYNOPSIS
    Extracts the Entra device ID during ESP and posts it to a runbook webhook.
.DESCRIPTION
    This Intune script only runs during ESP. It reads the AutopilotPolicyCache registry value, parses the
    PolicyJsonCache JSON, extracts AadDeviceID, and posts the value to a configured webhook URL.
.LINK
    c:\Git\toolbox\toolbox\Intune\Runbooks\Add-EntraDeviceToGroupFromWebhook.ps1
.PARAMETER WebhookUri
    The runbook webhook URL that receives the EntraDeviceID string.
.NOTES
    Version: 1.0
    Versionname: Send-EntraDeviceIDToWebhookDuringESP
    Initial creation date: 06.08.2026
    Last change date: 06.08.2026
    Author: Martin Himken
#>
$WebhookUri = "<insert-runbook-webhook-uri-here>"

$ErrorActionPreference = "Stop"
Try {
    $HasProvisioningCompleted = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup" ).HasProvisioningCompleted -eq 4294967295
    if ($HasProvisioningCompleted) {
        exit 0; #Exiting cleanly is fine as we can assume we don't need to run the script again.
    }

    $PolicyCache = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache"
    $PolicyJsonCache = $PolicyCache.PolicyJsonCache
    if (-not($PolicyJsonCache)) {
        throw "PolicyJsonCache value not found."
    }

    $PolicyJson = $PolicyJsonCache | ConvertFrom-Json
    $EntraDeviceID = $PolicyJson.AadDeviceId
    if (-not($EntraDeviceID) -and $PolicyJson.CloudAssignedAadServerData) {
        try {
            $CloudAssignedAadServerData = $PolicyJson.CloudAssignedAadServerData | ConvertFrom-Json -Depth 50
            $EntraDeviceID = $CloudAssignedAadServerData.ZeroTouchConfig.CloudAssignedAadDeviceId
        } catch {
            $EntraDeviceID = $null
        }
    }
    if (-not($EntraDeviceID)) {
        throw "AadDeviceID not found in PolicyJsonCache."
    }
    try {
        [guid]::Parse($EntraDeviceID) | Out-Null
    } catch {
        throw "AadDeviceID '$EntraDeviceID' is not a valid GUID."
    }
    if ([string]::IsNullOrWhiteSpace($WebhookUri) -or $WebhookUri -eq "<insert-runbook-webhook-uri-here>") {
        throw "WebhookUri is not configured."
    }

    $RequestBody = @{
        EntraDeviceID = $EntraDeviceID
    } | ConvertTo-Json -Compress

    Invoke-RestMethod -Method Post -Uri $WebhookUri -ContentType "application/json" -Body $RequestBody | Out-Null
    exit 0
} catch {
    exit 2;
}