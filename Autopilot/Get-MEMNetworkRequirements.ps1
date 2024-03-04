<#
.SYNOPSIS
This is not finished!
.DESCRIPTION
.NOTES
    Version: 0.1
    Versionname: 
    Intial creation date: 19.02.2023
    Last change date:
    Latest changes: https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md
#>
[CmdletBinding()]
param(
    [switch]$Intune,
    [switch]$Autopilot,
    [switch]$WindowsActivation,
    [switch]$EntraID,
    [switch]$WindowsUpdate,
    [switch]$DeliveryOptimization,
    [switch]$NTP,
    [switch]$DNS,
    [switch]$DiagnosticsData,
    [switch]$NCSI,
    [switch]$WNS,
    [switch]$WindowsStore,
    [switch]$M365,
    [switch]$CRLs,
    [switch]$SelfDeploying,
    [switch]$Legacy,
    [switch]$Log, #to log or not to log
    [switch]$ToConsole
)
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
$Script:GUID = (New-Guid).Guid
$Script:MEMURLs = [System.Collections.ArrayList]::new()
$Script:M365URLs = [System.Collections.ArrayList]::new()
$Script:URLsToVerify = [System.Collections.ArrayList]::new()
function Get-M365Service {
    param(
        [switch]$M365,
        [switch]$MEM
    )
    $EndpointURL = "https://endpoints.office.com"
    #if (Test-HTTP -URL $EndpointURL) {
    if ($M365) {
        $M365URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?clientrequestid=$Script:GUID")
    }
    if ($MEM) {
        $MEMURLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?ServiceAreas=MEM`&`clientrequestid=$Script:GUID")
    }
    foreach ($Object in $MEMURLs) {
        #TODO: Handle Wildcard URLs
        $Ports = [array](($Object.tcpPorts).split(","))
        $URLObject = [PSCustomObject]@{
            id                     = $Object.id
            serviceArea            = $Object.serviceArea
            serviceAreaDisplayName = $Object.serviceAreaDisplayName
            url                    = ''
            tcpPort                = ''
            expressRoute           = $Object.expressroute
            category               = $Object.category
            required               = $Object.required
            notes                  = $Object.notes
        }
        foreach ($URL in $Object.urls) {
            $URLObject.url = $URL
            foreach ($Port in $Ports) {
                $URLObject.tcpPort = $Port
                $Script:MEMURLs.Add($URLObject)
            }
        }
    }
    #}
}
function Get-ScriptPath {
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

function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of Ryan Ephgrave's script
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
    $Time = Get-Date -Format 'HH:mm:ss.ffffff'
    $Date = Get-Date -Format 'MM-dd-yyyy'
    if (-not($Component)) { $Component = 'Runner' }
    if (-not($Type)) { $Type = 1 }
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
# Usage: CheckSSL <fully-qualified-domain-name>
function Confirm-SSL {
    #Source: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-monitor/log-analytics/ssl-connectivity-mma-windows-powershell
    #Modified by Martin Himken for the purpose of this script
    param(
        $FQDN, 
        $Port = 443)
    try {
        $TCPSocket = New-Object Net.Sockets.TcpClient($FQDN, $Port)
    } catch {
        Write-Warning "$($_.Exception.Message) / $FQDN"
        return $false
    }
    $TCPStream = $TCPSocket.GetStream()
    #""; "-- Target: $FQDN / " + $tcpSocket.Client.RemoteEndPoint.Address.IPAddressToString
    $SSLStream = New-Object -TypeName Net.Security.SslStream($TCPStream, $false)
    $SSLStream.AuthenticateAsClient($FQDN)  # If not valid, will display "remote certificate is invalid".
    $CertInfo = New-Object -TypeName Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
    $SSLStream | Select-Object | Format-List -Property SslProtocol, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus
    $CertInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
    $CertInfo.Extensions |  Where-Object -FilterScript { $_.Oid.FriendlyName -Like 'subject alt*' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
    $tcpSocket.Close()
    return $true 
}
function Test-HTTP {
    param(
        [System.Uri]$URL,
        [int]$Port
    )
    if (Test-DNS $URL) {

    }
}
function Test-DNS {
    #Verify answer isn't 0.0.0.0 or 127.0.0.1 or ::
    param(
        [System.Uri]$Target
    )
    Resolve-DnsName -Name $Target.Host
}
function Test-Port {
    
    param(
        [System.Uri]$Target,
        [int]$Port
    )
    (New-Object System.Net.Sockets.TcpClient -ArgumentList $Target, $Port).Connected
}
function Test-CRL {}

function Test-Intune {
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints#access-for-managed-devices
    #Last Checked 27.02.24
    #The inspection of SSL traffic is not supported on 'manage.microsoft.com', 'a.manage.microsoft.com', or 'dm.microsoft.com' endpoints.
    #Allow HTTP Partial response is required for Scripts & Win32 Apps endpoints.
    "*.azureedge.net", (443, 80)
    "manage.microsoft.com", (443, 80)

}
function Test-Autopilot {
    "https://ztd.dds.microsoft.com"
    "https://cs.dds.microsoft.com"
    "https://login.live.com"
}
function Test-WindowsActivation {}
function Test-EntraID {}
function Test-WindowsUpdate {}
function Test-DeliveryOptimization {}
function Test-NTP {
    "time.windows.com", "123"
}
function Test-DNS {}
function Test-DiagnosticsData {}
function Test-NCSI {
    "www.msftconnecttest.com"
}
function Test-WNS {

}
function Test-AppInstaller {
    "displaycatalog.md.mp.microsoft.com"
    "purchase.md.mp.microsoft.com"
    "licensing.mp.microsoft.com"
    "storeedgefd.dsx.mp.microsoft.com"
}
function Test-WindowsStore {
    #From https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints 
    "img-prod-cms-rt-microsoft-com.akamaized.net", 443 #Downloads images
    "img-s-msn-com.akamaized.net", 80 #No explanation
    "livetileedge.dsx.mp.microsoft.com", 443 #Content
    "storeedgefd.dsx.mp.microsoft.com", 80 #No explanation
    "*.wns.windows.com", 443 #Very important for other stuff! Windows Push Notifcation Service!
    "storecatalogrevocation.storequality.microsoft.com", (443, 80) #[...]used to revoke licenses for malicious apps in the Microsoft Store
    "manage.devcenter.microsoft.com", 443 #Analytics
    "displaycatalog.mp.microsoft.com", (443, 80) #[...]used to communicate with Microsoft Store
    "share.microsoft.com", 80 #No explanation

    #From the same source, but not listed under Store
    "*.dl.delivery.mp.microsoft.com", (443, 80) # Content
    "*.delivery.mp.microsoft.com", (443, 80) # Content
}
function Test-M365 {

}
function Test-CRLs {
    #I have no idea why these are more than just URLs
    #Source: https://support.microsoft.com/en-us/topic/windows-activation-or-validation-fails-with-error-code-0x8004fe33-a9afe65e-230b-c1ed-3414-39acd7fddf52
    "https://go.microsoft.com/"
    "http://go.microsoft.com/"
    "https://login.live.com"
    "https://activation.sls.microsoft.com/"
    "http://crl.microsoft.com/pki/crl/products/MicProSecSerCA_2007-12-04.crl"
    "https://validation.sls.microsoft.com/"
    "https://activation-v2.sls.microsoft.com/"
    "https://validation-v2.sls.microsoft.com/"
    "https://displaycatalog.mp.microsoft.com/"
    "https://licensing.mp.microsoft.com/"
    "https://purchase.mp.microsoft.com/"
    "https://displaycatalog.md.mp.microsoft.com/"
    "https://licensing.md.mp.microsoft.com/"
    "https://purchase.md.mp.microsoft.com/"
}
function Test-SelfDeploying {

}
function Test-Legacy {
    <#
    .NOTES
    Test-Hybrid Join?
    #>
}

#Start coding!
$CurrentLocation = Get-Location
$Location = Get-ScriptPath
Set-Location $Location
if (-not(Test-Path $Script:PathToScript)) { New-Item $Script:PathToScript -ItemType Directory -Force | Out-Null }
$LogPrefix = 'MEMNR'
$LogFile = Join-Path -Path $Script:PathToScript -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)

Get-M365Service -MEM
$Script:MEMURLs

Set-Location $CurrentLocation