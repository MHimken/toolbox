<#
.SYNOPSIS
This is not finished!
#TODO: Handle Wildcard URLs
.DESCRIPTION
.NOTES
    Version: 0.1
    Versionname: 
    Intial creation date: 19.02.2024
    Last change date: 01.05.2024
    Latest changes: https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md
#>
[CmdletBinding()]
param(
    [switch]$All,
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

function Build-Factory {
    param(
        $Inputs
    )
    foreach ($Input in $Inputs) {
        $Script:URLsToVerify.add([PSCustomObject]@{
                URI      = [string]$Input[0]
                Ports    = [int[]]$Input[1]
                Protocol = [string]$Input[2]
                GCC      = [bool]$Input[3]
            })
    }
}
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
        $Ports = [array](($(if($Object.tcpPorts){$Object.tcpPorts}elseif($Object.udpPorts){$Object.udpPorts}else{'443'})).split(",").trim())
        foreach ($URL in $Object.urls) {
            if($URL -match '\*'){
                $URL
            }
            foreach ($Port in $Ports) {
                $URLObject = [PSCustomObject]@{
                    id                     = $Object.id
                    serviceArea            = $Object.serviceArea
                    serviceAreaDisplayName = $Object.serviceAreaDisplayName
                    url                    = $URL
                    tcpPort                = $Port
                    expressRoute           = $Object.expressroute
                    category               = $Object.category
                    required               = $Object.required
                    notes                  = $Object.notes
                }
                $Script:MEMURLs.Add($URLObject)
            }
        }
    }
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
    #[System.Uri] Maybe needed?
    #Source: https://learn.microsoft.com/en-us/troubleshoot/azure/azure-monitor/log-analytics/ssl-connectivity-mma-windows-powershell
    #Modified by Martin Himken for the purpose of this script
    param(
        $FQDN, 
        $Port)
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
    
    #$SSLStream | Select-Object | Format-List -Property SslProtocol, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus
    #$CertInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
    #$CertInfo.Extensions |  Where-Object -FilterScript { $_.Oid.FriendlyName -Like 'subject alt*' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
    if (Test-Certificate -DNSName $FQDN -Cert $CertInfo) {
        Write-Log "Certificate for $FQDN successfully verified"
    }
    $tcpSocket.Close()
    return $true 

    <# from Connor aka dreary_ennui
$url = "https://www.microsoft.com"
$request = [System.Net.WebRequest]::Create($url)
$request.GetResponse() | Out-Null
$certDetails = $request.ServicePoint.Certificate

if (($certDetails.issuer -notlike "*Microsoft*") -or ($null -eq $certDetails.issuer)) {
    Write-Output "Probably SSL inspected"
}
}#>
}
function Test-HTTP {
    <#
    Extended = also verify different HTTP-Versions
    #>
    param(
        [System.Uri]$URL,
        [int]$Port,
        [switch]$extended
    )
    if (Test-DNS $URL) {
        $HTTPResult = Test-NetConnection -ComputerName $URL -CommonTCPPort HTTP -InformationLevel Quiet
        $HTTPSResult = Test-NetConnection -ComputerName $URL -Port 443 -InformationLevel Quiet
        #Wird so nicht funktionieren - 
        $HTTPiwr = Invoke-WebRequest -Uri 'https://'+$URL -SslProtocol Tls12 -ConnectionTimeoutSeconds 5 -Method Get 
        if ($HTTPResult -and $HTTPSResult) {
            return $true
        } else {
            return $false
        }
    }
}
function Test-DNS {
    #Verify answer isn't 0.0.0.0 or 127.0.0.1 or ::
    param(
        [string]$Target
    )
    $ResolvedARecords = Resolve-DnsName -Name $Target -Type A -ErrorAction SilentlyContinue
    if ($ResolvedARecords.count) {
        foreach ($ARecord in $ResolvedARecords) {
            if ($ARecord.IP4Address) {
                if ($ARecord.IP4Address -ne '0.0.0.0' -and $ARecord.IP4Address -ne '127.0.0.1' -and $ARecord.IP4Address -ne '::') {
                    return $true
                } elseif($ARecord.IP4Address -eq '0.0.0.0' -or $ARecord.IP4Address -eq '127.0.0.1' -or $ARecord.IP4Address -eq '::') {
                    Write-Log -Message "DNS sinkhole detected: Address $Target resolved to an invalid address" -Component 'DNS' -Type 2
                }
            }
        }
    }
    return $false
}
function Test-Port {
    
    param(
        [System.Uri]$Target,
        [int]$Port
    )
    (New-Object System.Net.Sockets.TcpClient -ArgumentList $Target, $Port).Connected
}
function Test-CRL {}
function Test-RemoteHelp {
    #Remote Help - Default + Required https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#remote-help
    #"*.support.services.microsoft.com", 443 #example see next line
    "remoteassistance.support.services.microsoft.com", 443
    "rdprelayv3eastusprod-0.support.services.microsoft.com", 443
    #"*.trouter.skype.com", 443 #See below
    "remoteassistanceprodacs.communication.azure.com", 443
    "edge.skype.com", 443
    "aadcdn.msftauth.net", 443
    "aadcdn.msauth.net", 443
    "alcdn.msauth.net", 443
    "wcpstatic.microsoft.com", 443
    #"*.aria.microsoft.com", 443 #example see next line
    "browser.pipe.aria.microsoft.com", 443
    #"*.events.data.microsoft.com", 443 #example see next line
    "v10.events.data.microsoft.com", 443
    #"*.monitor.azure.com", 443 #example see next line
    "js.monitor.azure.com", 443
    "edge.microsoft.com", 443
    #"*.trouter.communication.microsoft.com", 443 #example see next line
    "go.trouter.communication.microsoft.com", 443
    #"*.trouter.teams.microsoft.com", 443 #example see next line
    "trouter2-usce-1-a.trouter.teams.microsoft.com", 443
    "api.flightproxy.skype.com", 443
    "ecs.communication.microsoft.com", 443
    "remotehelp.microsoft.com", 443
    "trouter-azsc-usea-0-a.trouter.skype.com", 443
    #"*.webpubsub.azure.com", 443 #example see next line
    "AMSUA0101-RemoteAssistService-pubsub.webpubsub.azure.com", 443
    #GCC
    "remoteassistanceweb-gcc.usgov.communication.azure.us", 443
    "gcc.remotehelp.microsoft.com", 443, "", $true
    "gcc.relay.remotehelp.microsoft.com", 443, "GCC"
    #"*.gov.teams.microsoft.us", 443, "GCC" #example see next line
    "gov.teams.microsoft.us", 443, "GCC"
}
function Test-Autopilot {
    "https://ztd.dds.microsoft.com", 443 #According to Jason Sandys this is the port
    "https://cs.dds.microsoft.com", 443 #According to Jason Sandys this is the port
    "https://login.live.com", 443

    #Autopilot dependencies according to https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#autopilot-dependencies
    #Default+Required
    "*.download.windowsupdate.com", 443
    "*.windowsupdate.com", 443
    "*.dl.delivery.mp.microsoft.com", 443
    "*.prod.do.dsp.mp.microsoft.com", 443
    "emdl.ws.microsoft.com", 443
    "*.delivery.mp.microsoft.com", 443
    "*.update.microsoft.com", 443
    "tsfe.trafficshaping.dsp.mp.microsoft.com", 443
    "au.download.windowsupdate.com", 443
    "2.dl.delivery.mp.microsoft.com", 443
    "download.windowsupdate.com", 443
    "dl.delivery.mp.microsoft.com", 443
    "geo.prod.do.dsp.mp.microsoft.com", 443
    "catalog.update.microsoft.com", 443
    #"time.windows.com" #NTP test is seperate
    #"www.msftncsi.com" #Only Windows <10? https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network#ncsi-active-probes-and-the-network-status-alert
    "www.msftconnecttest.com", 443
    "clientconfig.passport.net", 443
    "windowsphone.com", 443
    "*.s-microsoft.com", 443
    "c.s-microsoft.com", 443
    "ekop.intel.com", 443
    "ekcert.spserv.microsoft.com", 443
    "ftpm.amd.com", 443
    "lgmsapeweu.blob.core.windows.net", 433
}
function Test-WNS {
    #WNS Default+Required https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#windows-push-notification-serviceswns-dependencies
    #"*.notify.windows.com", 443 #example see next line
    "sin.notify.windows.com", 443
    #"*.wns.windows.com", 443 #example see next line
    "sinwns1011421.wns.windows.com", 443
}
function Test-DeviceHealth {
    #Microsoft Azure Attestation (formerly Device Health)
    "intunemaape1.eus.attest.azure.net", 443
    "intunemaape2.eus2.attest.azure.net", 443
    "intunemaape3.cus.attest.azure.net", 443
    "intunemaape4.wus.attest.azure.net", 443
    "intunemaape5.scus.attest.azure.net", 443
    "intunemaape6.ncus.attest.azure.net", 443
    "intunemaape7.neu.attest.azure.net", 443
    "intunemaape8.neu.attest.azure.net", 443
    "intunemaape9.neu.attest.azure.net", 443
    "intunemaape10.weu.attest.azure.net", 443
    "intunemaape11.weu.attest.azure.net", 443
    "intunemaape12.weu.attest.azure.net", 443
    "intunemaape13.jpe.attest.azure.net", 443
    "intunemaape17.jpe.attest.azure.net", 443
    "intunemaape18.jpe.attest.azure.net", 443
    "intunemaape19.jpe.attest.azure.net", 443
}
function Test-DeliveryOptimization {
    ("*.do.dsp.mp.microsoft.com", (443))
    "*.dl.delivery.mp.microsoft.com", 443
    "*.emdl.ws.microsoft.com", 443
    "kv801.prod.do.dsp.mp.microsoft.com", 443
    "geo.prod.do.dsp.mp.microsoft.com", 443
    "emdl.ws.microsoft.com", 443
    "2.dl.delivery.mp.microsoft.com", 443
    "bg.v4.emdl.ws.microsoft.com", 443
}
function Test-Intune {
    param(
        [switch]$Enhanced
    )
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints#access-for-managed-devices
    #Last Checked 23.04.24
    #The inspection of SSL traffic is not supported on 'manage.microsoft.com', or 'dm.microsoft.com' endpoints.
    #Allow HTTP Partial response is required for Scripts & Win32 Apps endpoints.
    #Intune core service
    #Allow + Required
    #"*.azureedge.net", @(443, 80) #Doesn't allow authenticated proxy! 
    "manage.microsoft.com", @(443, 80)
    "EnterpriseEnrollment.manage.microsoft.com", @(443, 80)
    
    #Default + Required
    #"*.do.dsp.mp.microsoft.com", @(7680, 3544, 443, 80)  #example see next line
    "kv801.prod.do.dsp.mp.microsoft.com", @(7680, 3544, 443, 80)
    "geo.prod.do.dsp.mp.microsoft.com", @(7680, 3544, 443, 80)
    #"*.dl.delivery.mp.microsoft.com", @(7680, 3544, 443, 80) #example see next line
    "2.dl.delivery.mp.microsoft.com", @(7680, 3544, 443, 80)
    #"*.emdl.ws.microsoft.com", @(7680, 3544, 443, 80) #example see next line
    "emdl.ws.microsoft.com", @(7680, 3544, 443, 80)
    "bg.v4.emdl.ws.microsoft.com", @(7680, 3544, 443, 80)
    #Default+Required
    "swda01-mscdn.azureedge.net", 443
    "swda02-mscdn.azureedge.net", 443
    "swdb01-mscdn.azureedge.net", 443
    "swdb02-mscdn.azureedge.net", 443
    "swdc01-mscdn.azureedge.net", 443
    "swdc02-mscdn.azureedge.net", 443
    "swdd01-mscdn.azureedge.net", 443
    "swdd02-mscdn.azureedge.net", 443
    "swdin01-mscdn.azureedge.net", 443
    "swdin02-mscdn.azureedge.net", 443
    #Default
    "account.live.com", 443
    "login.live.com", 443
    if ($Enhanced) {
        Test-Autopilot
        Test-DeliveryOptimization
        Test-RemoteHelp
        Test-DeviceHealth
        Test-WNS
        Test-AuthenticatedProxy
        #Auth
        "login.microsoftonline.com", @(443, 80)
        "graph.windows.net", @(443, 80)
        <#
            "*.officeconfig.msocdn.com", @(443,80) #This URL only has Nameservers. Examples below
            "prod.officeconfig.msocdn.com", @(443,80) #This is not in the list, but should exist
        #>
        "config.office.com", 443
        "enterpriseregistration.windows.net", @(443, 80)
    }

}

function Test-Apple {
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#apple-dependencies
    "itunes.apple.com", 443
    "*.itunes.apple.com", 443
    "*.mzstatic.com", 443
    "*.phobos.apple.com", 443
    "phobos.itunes-apple.com.akadns.net", 443
    "5-courier.push.apple.com", 443
    "phobos.apple.com", 443
    "ocsp.apple.com", 443
    "ax.itunes.apple.com", 443
    "ax.itunes.apple.com.edgesuite.net", 443
    "s.mzstatic.com", 443
    "a1165.phobos.apple.com", 443
}
function Test-Android {
    ("intunecdnpeasd.azureedge.net", 443)
}
function Test-WindowsActivation {}
function Test-EntraID {}
function Test-WindowsUpdate {}

function Test-NTP {
    #probably w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    #would throw 0x800705B4 if the URL exists but isn't an NTP or 0x80072AF9 for not resolved
    #TODO: Add check if this server is the current
    #"time.windows.com", "123" #NTP and SNTP both use this
    $CurrentTimeServer = w32tm /query /source
    $Testresult = w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    if ($Testresult -like "*80072AF9*" -or $Testresult[3 - ($Testresult.count)] -like "*800705B4*") {
        "NOT COOL"
    } else { "SUCCESS" }
    if ($CurrentTimeServer -eq "time.windows.com") {
    }
}
function Test-DiagnosticsData {}
function Test-NCSI {
    "www.msftconnecttest.com"
}

function Test-AppInstaller {
    "displaycatalog.md.mp.microsoft.com"
    "purchase.md.mp.microsoft.com"
    "licensing.mp.microsoft.com"
    "storeedgefd.dsx.mp.microsoft.com"
}
function Test-MicrosoftStore {
    Test-WNS
    #From https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints 
    "img-prod-cms-rt-microsoft-com.akamaized.net", 443 #Downloads images
    "img-s-msn-com.akamaized.net", 80 #No explanation
    "livetileedge.dsx.mp.microsoft.com", 443 #Content
    "storeedgefd.dsx.mp.microsoft.com", 80 #No explanation
    #"*.wns.windows.com", 443 #Very important for other stuff! Windows Push Notifcation Service!
    "storecatalogrevocation.storequality.microsoft.com", (443, 80) #[...]used to revoke licenses for malicious apps in the Microsoft Store
    "manage.devcenter.microsoft.com", 443 #Analytics
    "displaycatalog.mp.microsoft.com", (443, 80) #[...]used to communicate with Microsoft Store
    "share.microsoft.com", 80 #No explanation

    #From the same source, but not listed under Store
    Test-DeliveryOptimization
    #"*.dl.delivery.mp.microsoft.com", (443, 80) # Content
    #"*.delivery.mp.microsoft.com", (443, 80) # Content

    #From https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#microsoft-store
    #Dupes filtered
    ("purchase.md.mp.microsoft.com", (443, 80))
    ("licensing.mp.microsoft.com", (443, 80))

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
function Test-AuthenticatedProxy {
    #These URLs don't allow authenticated proxies according to https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#access-for-managed-devices 
    #("*.azureedge.net", @(443, 80))
    ("graph.microsoft.com", @(443))
    ("manage.microsoft.com", @(443, 80))
    Test-DeviceHealth
}
function Test-SSLInspection {
    #These URLs don't allow SSL inspection
    "dm.microsoft.com", @(443, 80)
    "manage.microsoft.com", @(443, 80)
}

#Start coding!
$CurrentLocation = Get-Location
$Location = Get-ScriptPath
Set-Location $Location
if (-not(Test-Path $Script:PathToScript)) { New-Item $Script:PathToScript -ItemType Directory -Force | Out-Null }
$LogPrefix = 'MEMNR'
$LogFile = Join-Path -Path $Script:PathToScript -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)

Get-M365Service -MEM
if ($All) {
    Set-Variable $Intune, $Autopilot, $WindowsActivation, $EntraID, $WindowsUpdate, $DeliveryOptimization, $NTP, $DNS, $DiagnosticsData, $NCSI, $WNS, $WindowsStore, $M365, $CRLs, $SelfDeploying, $Legacy -Value $true
}
if ($Intune) {

}
#$Script:MEMURLs

Set-Location $CurrentLocation