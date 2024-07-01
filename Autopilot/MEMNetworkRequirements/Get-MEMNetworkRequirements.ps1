<#
.SYNOPSIS
This is not finished!
.DESCRIPTION
.NOTES
    Version: 0.5
    Versionname: 
    Intial creation date: 19.02.2024
    Last change date: 01.07.2024
    Latest changes: https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md
#>
[CmdletBinding()]
param(
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\MEMNR\",
    [System.IO.DirectoryInfo]$LogDirectory = "C:\MEMNR\",
    [string]$CSVFile = "Get-MEMNetworkRequirements.csv",
    [int]$MaxDelayInMS = 200,
    [bool]$BurstMode = $false, #Divide the delay by 50 and try different speeds. Give warning when more than 10 URLs are tested
    [bool]$UseMSJSON = $true, # make this a switch when finished
    [bool]$UseCustomCSV = $true, # make this a switch when finished
    [bool]$AllowBestEffort = $true, # make this a switch when finished
    [switch]$AllTargetTest,
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
    [bool]$CheckCertRevocation = $true, # make this a switch when finished
    [switch]$SelfDeploying,
    [switch]$Legacy,
    [switch]$NoLog,
    [string[]]$TestMethods,
    [bool]$ToConsole = $true
)
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
$Script:GUID = (New-Guid).Guid
$Script:M365ServiceURLs = [System.Collections.ArrayList]::new()
$Script:DNSCache = [System.Collections.ArrayList]::new()
$Script:TCPCache = [System.Collections.ArrayList]::new()
$Script:WildCardURLs = [System.Collections.ArrayList]::new()
$Script:URLsToVerify = [System.Collections.ArrayList]::new()
$Script:FinalResultList = [System.Collections.ArrayList]::new()
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
function Initialize-Script {
    $Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
    if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
    $LogPrefix = 'MEMNR'
    $Script:LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $Script:DateTime)
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null }
    $Script:CurrentLocation = Get-Location
    Set-Location $WorkingDirectory
    Get-ScriptPath
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
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red), 4 = Explicit Success (not CM!)
        [ValidateSet('1', '2', '3', '4')][int]$Type
    )
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($Type) -or $Type -eq 4) { $Type = 1 }
        if (-not($ToConsole)) {
            $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
            $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
        } elseif ($ToConsole) {
            switch ($type) {
                1 { Write-Host "T:$Type C:$Component M:$Message" }
                2 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Yellow -ForegroundColor Black }
                3 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Red -ForegroundColor White }
                4 { Write-Host "T:$Type C:$Component M:$Message" -BackgroundColor Green -ForegroundColor White ; $Type = 1; }
                default { Write-Host "T:$Type C:$Component M:$Message" }
            }
        }
    }
}
function Import-NetworkRequirementCSV {
    $Header = 'URL', 'Port', 'Protocol', 'ID'
    $Script:ManualURLs = [System.Collections.ArrayList]::new()
    $TempObjects = Import-Csv -Path (Join-Path -Path $Script:PathToScript -ChildPath $CSVFile) -Delimiter ',' -Header $Header
    foreach ($Object in $TempObjects) {
        $URLObject = [PSCustomObject]@{
            id       = $Object.ID
            #serviceArea            = $Object.serviceArea
            #serviceAreaDisplayName = $Object.serviceAreaDisplayName
            url      = $Object.url.replace('*.', '')
            Port     = $Object.port
            Protocol = $Object.protocol
            #expressRoute           = $Object.expressRoute
            #category               = $Object.category
            required = 'true'
            #notes                  = $Object.notes
        }
        $Script:ManualURLs.add($URLObject) | Out-Null
    }
}
function Get-URLsFromID {
    param(  
        [int]$ID,
        [int[]]$FilterPort
    )
    if ($Script:ManualURLs) {
        $Script:ManualURLs | Where-Object { $_.id -eq $ID -and $_.port -notin $FilterPort } | ForEach-Object { $Script:URLsToVerify.Add($_) | Out-Null }
    }
    if ($Script:M365ServiceURLs) {
        $Script:M365ServiceURLs | Where-Object { $_.id -eq $ID -and $_.port -notin $FilterPort } | ForEach-Object { $Script:URLsToVerify.Add($_) | Out-Null }
    }
    if (-not($Script:URLsToVerify)) {
        return $false
    }
    $DuplicateURLsToVerify = [System.Collections.ArrayList]::new()
    foreach ($IDsFound in $Script:URLsToVerify) {
        $RemoveMe = $Script:URLsToVerify | Where-Object { $_.id -eq $IDsFound.id -and $_.url -eq $IDsFound.url -and $_.port -eq $IDsFound.port -and $_.protocol -eq $IDsFound.protocol }
        if ($RemoveMe.count -gt 1) {
            $counter = 0
            foreach ($RemoveObject in $RemoveMe) {
                if ($counter -gt 0) {
                    $DuplicateURLsToVerify.add($RemoveObject) | Out-Null
                }
                $counter++
            }
        }
    }
    $DuplicateURLsToVerify | ForEach-Object { $Script:URLsToVerify.Remove($_) }

    #Cleanup of dupes
    return $true
}
function Build-Factory {
    param(
        [string[]]$TestMethods
    )
    if ($TestMethods -eq 'AllTests') {
        $TestMethods = 'DNS', 'Port', 'SSLInspection', 'HTTP'
    }
    foreach ($Input in $Inputs) {
        $Script:URLsToVerify.add([PSCustomObject]@{
                URI      = [string]$Input[0]
                Ports    = [int[]]$Input[1]
                Protocol = [string]$Input[2]
                GCC      = [bool]$Input[3]
            })
    }
}

function Find-WildcardURL {
    #ID 8888 = Best effort URLs
    Write-Log -Message 'Now searching for nearest match for Wildcards' -Component 'FindWildcardURL'
    foreach ($Object in $Script:WildCardURLs) {
        #Write-Log -Message "Searching for $($Object.url)" -Component 'FindWildcardURL' 
        if ($($Script:M365ServiceURLs | Where-Object { $_.url -like "*$($Object.url.replace('*.',''))*" })) {
            #if ($Object.url -in $Script:M365ServiceURLs.url) {
            #Write-Log -Message 'Found match in M365 service list - looking up next URL' -Component 'FindWildcardURL'
            continue
        }
        #Write-Log -Message 'We did not find a matching URL using best effort (no wildcard)' -Component 'FindWildcardURL'
        $URLObject = [PSCustomObject]@{
            id       = $Object.ID
            #serviceArea            = $Object.serviceArea
            #serviceAreaDisplayName = $Object.serviceAreaDisplayName
            url      = $Object.url.replace('*.', '')
            Port     = $Object.port
            Protocol = $Object.protocol
            #expressRoute           = $Object.expressRoute
            #category               = $Object.category
            required = $Object.required
            #notes                  = $Object.notes
        }
        
        $Script:M365ServiceURLs.Add($URLObject) | Out-Null
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
        $URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?clientrequestid=$Script:GUID")
    }
    if ($MEM) {
        $URLs = Invoke-RestMethod -Uri ("$EndpointURL/endpoints/WorldWide?ServiceAreas=MEM`&`clientrequestid=$Script:GUID")
    }
    foreach ($Object in $URLs) {
        $Ports = [array](($(if ($Object.tcpPorts) { $Object.tcpPorts }elseif ($Object.udpPorts) { $Object.udpPorts }else { '443' })).split(",").trim())
        $Protocol = $(if ($Object.tcpPorts) { 'TCP' } elseif ($Object.udpPorts) { 'UDP' } else { 'TCP' })
        foreach ($URL in $Object.urls) {
            foreach ($Port in $Ports) {
                $URLObject = [PSCustomObject]@{
                    id       = $Object.id
                    #serviceArea            = $Object.serviceArea
                    #serviceAreaDisplayName = $Object.serviceAreaDisplayName
                    url      = $URL
                    Port     = $Port
                    Protocol = $Protocol
                    #expressRoute           = $Object.expressroute
                    #category               = $Object.category
                    required = $Object.required
                    #notes                  = $Object.notes
                }
                if ($URL -match '\*') {
                    #Write-Log -Message "The URI $URL contains a wildcard - trying to find nearest match later" -Component 'GetM365Service'
                    if ($URL -in $Script:WildCardURLs.url) {
                        continue
                    }
                    $Script:WildCardURLs.add($URLObject) | Out-Null
                    continue
                }
                $Script:M365ServiceURLs.Add($URLObject) | Out-Null
            }
        }
    }
    if ($AllowBestEffort) {
        Write-Log -Message 'Best effort URLs are enabled - this will turn wildcards into regular URLs using a best effort method' -Component 'MEMNRMain'
        Find-WildcardURL
    }
}

# Usage: CheckSSL <fully-qualified-domain-name>
function Test-SSL {
    param(
        $Target, 
        $Port = 443
    )
    #try {
    #
    #} catch {
    #Write-Warning "$($_.Exception.Message) / $FQDN"
    #return $false
    #}
    $TCPSocket = New-Object Net.Sockets.TcpClient($Target, $Port)
    #$TCPStream = 
    $SSLStream = New-Object -TypeName Net.Security.SslStream($TCPSocket.GetStream(), $false)
    # $SSLStream.AuthenticateAsClient($FQDN)  # If not valid, will display "remote certificate is invalid".
    try {
        $SSLStream.AuthenticateAsClient(
            $Target, #targetHost
            $null, #clientCertificates (Collection)
            $true #checkCertificateRevocation
        )
    } catch [System.Security.Authentication.AuthenticationException] {
        #ToDo: Check other OS languages! We might have to switch to working with something else here
        switch -Wildcard ($Error[0].Exception.InnerException.Message) {
            "Cannot determine the frame size or a corrupted frame was received."{$AuthException = "FramSizeOrCorrupted"}
            "*TLS alert: 'HandshakeFailure'." { $AuthException = "HandshakeFailure" }
            "*validation procedure: RemoteCertificateNameMismatch" { $AuthException = "RemoteCertificateNameMismatch" }
            default { $AuthException = $Error[0].Exception.InnerException.Message.Split(':')[1].Trim() }
        }
    }
    #$CRLInfo = New-Object -TypeName Security.Cryptography.X509Certificates
    $CertInfo = New-Object -TypeName Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
    #$RevocationList = New-Object -TypeName Security.Cryptography.X509Certificates.
    #$SSLStream | Select-Object | Format-List -Property SslProtocol, CipherAlgorithm, HashAlgorithm, KeyExchangeAlgorithm, IsAuthenticated, IsEncrypted, IsSigned, CheckCertRevocationStatus
    #$CertInfo | Format-List -Property Subject, Issuer, FriendlyName, NotBefore, NotAfter, Thumbprint
    #$CertInfo.Extensions |  Where-Object -FilterScript { $_.Oid.FriendlyName -Like 'subject alt*' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
    if (Test-Certificate -DNSName $FQDN -Cert $CertInfo) {
        #Write-Log "Certificate for $FQDN successfully verified"
    }
    #$tcpSocket.Close()
    $Results = [PSCustomObject]@{
        SSLProtocol   = $SSLStream.SslProtocol
        Issuer        = $CertInfo.Issuer
        AuthException = $AuthException
    }
    return $Results
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
    $result = $true
    if ($Target -in $Script:DNSCache.CachedURL) {
        $CachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $Target } | Select-Object -Property result
        return $CachedResult.result
    }
    $ResolvedDNSRecords = Resolve-DnsName -Name $Target -ErrorAction SilentlyContinue
    if ($ResolvedDNSRecords.count) {
        foreach ($DNSARecord in $ResolvedDNSRecords.IP4Address) {
            if ($DNSARecord.IP4Address) {
                if ($DNSARecord -eq '0.0.0.0' -or $DNSARecord -eq '127.0.0.1') {
                    Write-Log -Message "DNS sinkhole detected: Address $Target resolved to an invalid address" -Component 'TestDNS' -Type 2
                    $result = $false
                    break
                }
            }
        }
        foreach ($DNSAAAARecord in $ResolvedDNSRecords.IP6Address) {
            if ($DNSAAAARecord -eq '::') {
                Write-Log -Message "DNS sinkhole detected: Address $Target resolved to an invalid address" -Component 'TestDNS' -Type 2
                $result = $false
                break
            }
        }
    } else {
        Write-Log -Message "No DNS record found for $Target" -Component 'TestDNS' -Type 3
        $result = $false
    }
    $DNSObject = [PSCustomObject]@{
        CachedURL = $Target
        Result    = $result
    }
    $Script:DNSCache.add($DNSObject) | Out-Null
    return $result
}
function Test-TCPPort {
    param(
        [string]$Target,
        [int]$Port,
        [int]$MaxWaitTime
    )
    if (-not($MaxWaitTime)) {
        $MaxWaitTime = 150
    }
    if ($Target -in $Script:DNSCache.CachedURL) {
        $DNSCachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $Target } | Select-Object -Property result -First 1
        if (-not($DNSCachedResult.result)) {
            return $false
        }
    }
    if (-not($BurstMode)) {
        if ($Target -in $Script:TCPCache.CachedURL -and $Port -in ($Script:TCPCache.Port | Where-Object { $_.CachedURL -eq $Target })) {
            $TCPCachedResult = $Script:TCPCache | Where-Object { $_.CachedURL -eq $Target } | Select-Object -Property result -First 1
            if (-not($TCPCachedResult.result)) {
                return $false
            }
        }
    }
    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
    $RunningClient = $TCPClient.ConnectAsync($Target, $Port)
    Start-Sleep -Milliseconds $MaxWaitTime
    $success = $false 
    if ($RunningClient.IsCompleted) {
        if ($RunningClient.Status -ne 'RanToCompletion') {
            Write-Log "TCP Port test failed with $($RunningClient.Status)" -Component 'TestTCPPort' -Type 2
            if ($RunningClient.Exception.InnerException) {
                Write-Log "$($RunningClient.Exception.InnerException.Message)" -Component 'TestTCPPort'
            }
        } else {
            $success = $true
        }
    } else {
        Write-Log 'TCP Port did not respond in a timely fashion' -Component 'TestTCPPort' -Type 2
    }
    $TCPClient.Close()
    $TCPClient.Dispose()
    if (-not($BurstMode)) {
        $TCPObject = [PSCustomObject]@{
            CachedURL = $Target
            Port      = $Port
            Result    = $result
        }
        $Script:TCPCache.add($TCPObject) | Out-Null
    }
    return $success
}
function Test-UDPPort {
    <#
    .SYNOPSIS
    This function is effectively not working correctly, because an UDP connection is stateless and we can't expect an answer from MS-Services
    The only service that will ever answer, because it has to, is a NTP server. There are other ways to test that though see Test-NTP
    HUGE thanks to https://github.com/proxb/PowerShell_Scripts/blob/master/Test-Port.ps1 and
    Jannik Reinhard for the idea to use NTP to test UDP https://github.com/JayRHa/Intune-Scripts/blob/main/Check-AutopilotPrerequisites/Check-AutopilotPrerequisites.ps1#L145
    #>
    param(
        [string]$Target,
        [int]$Port
    )
    $NTPData = New-Object byte[] 48
    $NTPData[0] = 27
    $udpobject = New-Object Net.Sockets.Udpclient([System.Net.Sockets.AddressFamily]::InterNetwork) 
    $udpobject.Client.Blocking = $False
    $udpobject.AllowNatTraversal($true)
    $Error.Clear()
    $udpobject.Connect($Target, $Port) | Out-Null
    if ($udpobject.client.Connected) {
        Write-Log -Message 'Sending UDP test message' -Component 'TestUDPPort'
        [void]$udpobject.Send($NTPData, $NTPData.Length)
        $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
        Start-Sleep -Milliseconds 100 #We have to wait slightly to send the data back
        $TestData = $udpobject.Receive([ref]$remoteendpoint)
    } else {
        Write-Log -Message 'No UDP "connection" established' -Component 'TestUDPPort'
        Write-Log -Message "$($Error[0].Exception.InnerException.Message)" -Component 'TestUDPPort' -Type 2
        return $false
    }
    $udpobject.Close()
    $udpobject.Dispose()
    if ($TestData) {
        $Seconds = [BitConverter]::ToUInt32( $TestData[43..40], 0 )
        ( [datetime]'1/1/1900' ).AddSeconds( $Seconds ).ToLocalTime()
    } else {
        Write-Log -Message 'Did not receive a response' -Component 'TestUDPPort' -Type 2
        return $false
    }
    return $true
}
function Test-TCPBurstMode {
    param(
        $WorkObject
    )
    $MinimumWaitTime = 50
    $AmountofTimes = [math]::floor([decimal]($MaxDelayInMS / $MinimumWaitTime))
    for ($i = 1; $i -lt $AmountofTimes + 1; $i++) {
        $MaxWaitTime = $($MinimumWaitTime * $i)
        $TCPResult = Test-TCPPort -Target $WorkObject.url -Port $WorkObject.port -MaxWaitTime $MaxWaitTime
        $WorkObject | Add-Member -MemberType NoteProperty -Name "TCP$MaxWaitTime" -Value $TCPResult
    }
}
function Test-CRL {}
function Test-RemoteHelp {
    <#
        #181
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
    
    #187
    #"*.webpubsub.azure.com", 443 #example see next line
    "AMSUA0101-RemoteAssistService-pubsub.webpubsub.azure.com", 443
    
    #GCC
    #188
    "remoteassistanceweb-gcc.usgov.communication.azure.us", 443
    "gcc.remotehelp.microsoft.com", 443,
    "gcc.relay.remotehelp.microsoft.com", 443
    #"*.gov.teams.microsoft.us", 443 #example see next line
    "gov.teams.microsoft.us", 443
    #>
    #ServiceIDs 181,187
    #ServiceIDs GCC 188
}
function Test-Autopilot {
    <#
    Sources:
    https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#windows-autopilot-deployment-service
    #Autopilot dependencies according to https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#autopilot-dependencies
    #"www.msftncsi.com" #Only Windows <10? https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network#ncsi-active-probes-and-the-network-status-alert
    #>
    #ServiceIDs 164,165,169,173,182,9999
    #9999 = Autopilot
    #Import
    $Autopilot = (182, 9999) | ForEach-Object { Get-URLsFromID $_ }
    foreach ($Object in $Autopilot) {
        Test-DNS $Object.url
    }
    <#
    Test-NTP #165
    Test-WNS #169
    Test-TPMAttestation #173
    Test-DeliveryOptimization #164
    Test-WNS #169
    #>

}
function Test-TPMAttestation {
    <#
    #https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#autopilot-self-deploying-mode-and-autopilot-pre-provisioning
    "ekop.intel.com", 443
    "ekcert.spserv.microsoft.com", 443
    "ftpm.amd.com", 443
    "TPMTESTURL.microsoftaik.azure.net", 443 #this will always resolve to at least SOME URL
    #>
    #ServiceIDs 164,9998
    #9998 = TPM Attestation
}
function Test-WNS {
    <#
    #WNS Default+Required https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#windows-push-notification-serviceswns-dependencies
    #"*.notify.windows.com", 443 #example see next line
    "sin.notify.windows.com", 443
    #"*.wns.windows.com", 443 #example see next line
    "sinwns1011421.wns.windows.com", 443
    #According to AP https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#autopilot-dependencies
    "clientconfig.passport.net", 443
    "windowsphone.com", 443
    "c.s-microsoft.com", 443
    #>
    #ServiceIDs 169,171
}
function Test-DeviceHealth {
    <#
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
    #>
    #ServiceIDs 186
}
function Test-DeliveryOptimization {
    <#param(
        $target,
        $port
    )
    #>
    <#
    https://remyhax.xyz/posts/do-harm/ - in depth article about how DO is communicating
    #("*.do.dsp.mp.microsoft.com", (443))
    "*.dl.delivery.mp.microsoft.com", 443
    #"*.emdl.ws.microsoft.com", 443
    "kv801.prod.do.dsp.mp.microsoft.com", 443
    "geo.prod.do.dsp.mp.microsoft.com", 443
    "emdl.ws.microsoft.com", 443
    "2.dl.delivery.mp.microsoft.com", 443
    "bg.v4.emdl.ws.microsoft.com", 443
    #>
    #ServiceIDs 172,164
    #Port 7680 is used to listen to other clients requests (on host)
    #Port 3544 UDP is needed for Download Mode 2 and 3 in _and_ outbound
    $result = $true
    Write-Log 'Documentation will specify port 7680 TCP. This is used to listen to other clients requests (from the host)' -Component 'TestDO'
    $Listening = Get-NetTCPConnection -LocalPort 7680
    if (-not($Listening)) {
        Write-Log 'TCP Port 7680 not being listed as listening checking service' -Component 'TestDO'
        if (-not(Get-Service -Name DoSvc)) {
            Write-Log 'DoSvc is not running! No delivery optimization possible' -Component 'TestDO' -Type 2
            $result = 'Warning'
        }
    }
    $DeliveryOptimization = (172, 164) | ForEach-Object { Get-URLsFromID -ID $_ -FilterPort 7680, 3544 }
    if (-not($DeliveryOptimization)) {
        Write-Log -Message 'No matching ID found for service area: Delivery Optimization' -Component 'TestDO' -Type 3
        return $false
    }
    foreach ($DOTarget in $Script:URLsToVerify) {
        $DNS = Test-DNS -Target $DOTarget.url
        $DOTarget | Add-Member -Name 'DNSResult' -MemberType NoteProperty -Value $DNS
        if ($DNS) {
            if ($BurstMode) {
                Test-TCPBurstMode $DOTarget
            } else {
                $TCP = Test-TCPPort -Target $DOTarget.url -Port $DOTarget.port
                if ($TCP) {
                    $SSLTest = Test-SSL -Target $DOTarget.url -Port $DOTarget.port
                    $DOTarget | Add-Member -Name 'SSLProtocol' -MemberType NoteProperty -Value $SSLTest.SSLProtocol
                    $DOTarget | Add-Member -Name 'Issuer' -MemberType NoteProperty -Value $SSLTest.Issuer
                    if ($SSLTest.AuthException) {
                        $DOTarget | Add-Member -Name 'AuthException' -MemberType NoteProperty -Value $SSLTest.AuthException
                    }
                }
                #Add more tests here if required! Most tests won't work with BURSTMODE ...??
            }
        } else {
            $TCP = $false
        }
        <#
        if ($DNS -xor $TCP) {
            $result = $false
            #Write-Log -Message "The FQDN $($DOTarget.url) was not detected successfully" -Component 'TestDO' -Type 3
        } else {
            #Write-Log -Message "$($DOTarget.url)" -Component 'TestDO' -Type 4
        }
        #>
        if (-not($BurstMode)) { $DOTarget | Add-Member -Name 'TCPResult' -MemberType NoteProperty -Value $TCP }
        $Script:FinalResultList.add($DOTarget) | Out-Null
    }
    return $result

    #TODO: CHECK THIS!
    #Last Check 24.06.24 - This should use a TCP connection, but if that's the case we'd need to find another client which we don't have.
    <#
        $DOMessage = ''
    $DOMessage += '0E 53 77 61 72 6D 20 70 72 6F 74 6F 63 6F 6C 00'.replace(' ', '')
    $DOMessage += '00 00 00 00 10 00 00 D9 A5 89 6D 90 26 67 C8 75'.replace(' ', '')
    $DOMessage += 'BC 5D 7C FE 87 32 36 F3 9C E5 A0 1E 11 F2 7B FE'.replace(' ', '')
    $DOMessage += '5F 18 FE B7 FE 23 F4 A0 5B EC F6 12 66 C0 41 BB'.replace(' ', '')
    $DOMessage += '0B C4 BA CF 17 AB 61 00 00 00 00               '.replace(' ', '')
    $DOMessage = [System.Convert]::FromHexString($DOMessage)
    #[System.BitConverter]::ToString($message).Replace('-')
    $udpobject = New-Object Net.Sockets.Udpclient([System.Net.Sockets.AddressFamily]::InterNetwork) 
    $udpobject.Client.Blocking = $False
    $udpobject.AllowNatTraversal($true)
    $Error.Clear()
    $udpobject.Connect($Target, $Port) | Out-Null
    if ($udpobject.client.Connected) {
        Write-Log -Message 'Sending UDP test message' -Component 'TestUDPPort'
        [void]$udpobject.Send($DOMessage, $DOMessage.Length)
        $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
        Start-Sleep -Milliseconds 100 #We have to wait slightly to send the data back
        $TestData = $udpobject.Receive([ref]$remoteendpoint)
    } else {
        Write-Log -Message 'No UDP "connection" established' -Component 'TestUDPPort'
        Write-Log -Message "$($Error[0].Exception.InnerException.Message)" -Component 'TestUDPPort' -Type 2
        return $false
    }
    $TestData
    $udpobject.Close()
    $udpobject.Dispose()
    #>
}
function Test-Intune {
    param(
        [switch]$Enhanced
    )
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints#access-for-managed-devices
    #Last Checked 11.06.24
    #ServiceIDs 97,172,163,164,9997
    #9997 = Defender
    <#
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
#>
    if ($Enhanced) {
        Test-Autopilot
        Test-RemoteHelp
        Test-DeviceHealth
        Test-AuthenticatedProxy
        <#
        #Auth
        "login.microsoftonline.com", @(443, 80)
        "graph.windows.net", @(443, 80)
        #    "*.officeconfig.msocdn.com", @(443,80) #This URL only has Nameservers. Examples below
        #    "prod.officeconfig.msocdn.com", @(443,80) #This is not in the list, but should exist
        "config.office.com", 443
        "enterpriseregistration.windows.net", @(443, 80)
    
    #>
    }
}
function Test-Apple {
    #ServiceIDs 178
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=north-america#apple-dependencies
    <#
    "itunes.apple.com", 443
    #"*.itunes.apple.com", 443
    #"*.mzstatic.com", 443
    #"*.phobos.apple.com", 443
    "phobos.itunes-apple.com.akadns.net", 443
    "5-courier.push.apple.com", 443
    "phobos.apple.com", 443
    "ocsp.apple.com", 443
    "ax.itunes.apple.com", 443
    "ax.itunes.apple.com.edgesuite.net", 443
    "s.mzstatic.com", 443
    "a1165.phobos.apple.com", 443
    #>
    Write-Log -Message 'Port 5223 is only used as a fallback for push notifications and only valid for push.apple.com addresses' -Component 'TestApple'
    Write-Log -Message 'Warning: Other URLs might be required, please also consult https://support.apple.com/de-de/101555' -Component 'TestApple' -Type 2
}
function Test-Android {
    #ServiceIDs 179
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#android-aosp-dependencies
    #
    <#
    "intunecdnpeasd.azureedge.net", 443
    #>
    Write-Log -Message 'Warning: Other URLs might be required, please also consult https://static.googleusercontent.com/media/www.android.com/en//static/2016/pdfs/enterprise/Android-Enterprise-Migration-Bluebook_2019.pdf' -Component 'TestAndroid' -Type 2
}
function Test-WindowsActivation {}
function Test-EntraID {}
function Test-WindowsUpdate {
    #ServiceIDs 164
    #https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting#device-cant-access-update-files
    <#
    "download.windowsupdate.com", 80
    "download.windowsupdate.com", 443
    "update.microsoft.com", 443
    "update.microsoft.com", 80
    #>
    Test-DeliveryOptimization
}
function Test-NTP {
    #ServiceIDs 165
    #probably w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    #would throw 0x800705B4 if the URL exists but isn't an NTP or 0x80072AF9 for not resolved
    #"time.windows.com", "123" #NTP and SNTP both use this
    Write-Log 'Microsofts JSON claims more URLs for Port 123, where in reality its only time.windows.com' -Component 'TestNTP' -Type 2
    $CurrentTimeServer = w32tm /query /source
    $TimeTest = w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    if ($TimeTest -like "*80072AF9*" -or $TimeTest[3 - ($TimeTest.count)] -like "*800705B4*") {
        return $false
    }
    if ($CurrentTimeServer -ne "time.windows.com") { 
        if ($Autopilot) {
            Write-Log 'time.windows.com is currently not the timeserver - this is a requirement for Autopilot' -Component 'TestNTP' -Type 3
        }
        return $false 
    }
    return $true
}
function Test-DiagnosticsData {}
function Test-NCSI {
    #ServiceIDs 165
    Write-Log 'MSFTConnectTest.com is listed under ID 165, which uses the wrong port' -Component 'TestNCSI'
    "www.msftconnecttest.com", 443
    "www.msftconnecttest.com", 80
}

function Test-AppInstaller {
    "displaycatalog.md.mp.microsoft.com"
    "purchase.md.mp.microsoft.com"
    "licensing.mp.microsoft.com"
    "storeedgefd.dsx.mp.microsoft.com"
}
function Test-MicrosoftStore {
    #ServiceIDs 9996
    #https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints 
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#microsoft-store
    <#
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
    "manage.devcenter.microsoft.com",443,80
        #From the same source, but not listed under Store
    #"*.dl.delivery.mp.microsoft.com", (443, 80) # Content
    #"*.delivery.mp.microsoft.com", (443, 80) # Content

    #From https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#microsoft-store
    #Dupes filtered
    ("purchase.md.mp.microsoft.com", (443, 80))
    ("licensing.mp.microsoft.com", (443, 80))
#>
    Get-URLsFromID 9996
    Test-WNS
    Test-DeliveryOptimization
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
Initialize-Script

#Test-UDPPort "noctua.local" -Port 55555
#Test-UDPPort "time.windows.com" -Port 123
#Test-UDPPort "time.windows.com" -Port 123
#Test-UDPPort "5-courier.push.apple.com" -Port 5223
#Test-UDPPort "asdiubfaoisdbfg.com" -Port 15415

if ($UseCustomCSV) {
    Import-NetworkRequirementCSV
}
if ($UseMSJSON) {
    Get-M365Service -MEM
}
if ($AllTargetTest) {
    Set-Variable $Intune, $Autopilot, $WindowsActivation, $EntraID, $WindowsUpdate, $DeliveryOptimization, $NTP, $DNS, $DiagnosticsData, $NCSI, $WNS, $WindowsStore, $M365, $CRLs, $SelfDeploying, $Legacy -Value $true
}
if ($AllTests) {
    $TestMethods = 'AllTests'
}
Test-DeliveryOptimization
#Test-SSL -Target untrusted-root.badssl.com -Port 443

#ToDo: Out-Gridview
# * 3 modes by default only show "true/false"
# * second mode shows a little more detail like certificate information
# * third mode shows all errors?
$Script:FinalResultList | Out-GridView
#Build-Factory $TestMethods #This should create the final URL list and prepare the selected tests

<#if($UseMSJSON -and $UseCustomCSV){
    Write-Log -Message 'Both Microsoft JSON and custom CSV specified - creating merged ressults. If a URL exists multiple times the CSV wins' -Component 'MEMNRMain'
}
#>
#Test-Autopilot
Set-Location $CurrentLocation