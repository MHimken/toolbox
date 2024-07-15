<#
.SYNOPSIS
This is not finished! This script is used to perform network requirements testing for various services.
.DESCRIPTION
Shoutouts: badssl.com and httpstat.us are amazing! WinAdmins Community - especially Chris.
The script allows you to test network connectivity and performance for different services by specifying the URLs, ports, and protocols to test. It supports testing for services like Intune, Autopilot, Windows Activation, EntraID, Windows Update, Delivery Optimization, NTP, DNS, Diagnostics Data, NCSI, WNS, Windows Store, M365, and CRLs.
.PARAMETER WorkingDirectory
Specifies the working directory where the script will be executed. The default value is "C:\MEMNR\".
.PARAMETER LogDirectory
Specifies the directory where log files will be stored. The default value is "C:\MEMNR\".
.PARAMETER CSVFile
Specifies the path to the CSV file containing the URLs, ports, and protocols to test. The default value is "Get-MEMNetworkRequirements.csv".
.PARAMETER MaxDelayInMS
Specifies the maximum delay in milliseconds for each network request. The default value is 300.
.PARAMETER BurstMode
Specifies whether to enable burst mode, which divides the delay by 50 and tries different speeds. Give a warning when more than 10 URLs are tested. The default value is $false.
.PARAMETER UseMSJSON
Specifies whether to use MSJSON for network requests. The default value is $true.
.PARAMETER UseCustomCSV
Specifies whether to use a custom CSV file for network requirements. The default value is $true.
.PARAMETER AllowBestEffort
Specifies whether to allow best effort testing for URLs that don't have an exact match. The default value is $true.
.PARAMETER AllTargetTest
Specifies whether to test all target services. This is a switch parameter.
.PARAMETER Intune
Specifies whether to test Intune service. This is a switch parameter.
.PARAMETER Autopilot
Specifies whether to test Autopilot service. This is a switch parameter.
.PARAMETER WindowsActivation
Specifies whether to test Windows Activation service. This is a switch parameter.
.PARAMETER EntraID
Specifies whether to test EntraID service. This is a switch parameter.
.PARAMETER WindowsUpdate
Specifies whether to test Windows Update service. This is a switch parameter.
.PARAMETER DeliveryOptimization
Specifies whether to test Delivery Optimization service. This is a switch parameter.
.PARAMETER NTP
Specifies whether to test NTP service. This is a switch parameter.
.PARAMETER DNS
Specifies whether to test DNS service. This is a switch parameter.
.PARAMETER DiagnosticsData
Specifies whether to test Diagnostics Data service. This is a switch parameter.
.PARAMETER NCSI
Specifies whether to test NCSI service. This is a switch parameter.
.PARAMETER WNS
Specifies whether to test WNS service. This is a switch parameter.
.PARAMETER WindowsStore
Specifies whether to test Windows Store service. This is a switch parameter.
.PARAMETER M365
Specifies whether to test M365 service. This is a switch parameter.
.PARAMETER CRLs
Specifies whether to test CRLs service. This is a switch parameter.
.PARAMETER CheckCertRevocation
Specifies whether to check certificate revocation for network requests. The default value is $true.
.PARAMETER SelfDeploying
Specifies whether to test self-deploying service. This is a switch parameter.
.PARAMETER Legacy
Specifies whether to test legacy service. This is a switch parameter.
.PARAMETER NoLog
Specifies whether to disable logging. This is a switch parameter.
.PARAMETER TestMethods
Specifies the test methods to use. The default value is an empty array.
.PARAMETER ToConsole
Specifies whether to output log messages to the console. The default value is $true.
.NOTES
    Version: 0.9
    Versionname: 
    Intial creation date: 19.02.2024
    Last change date: 13.07.2024
    Latest changes: https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md
#>
[CmdletBinding()]
param(
    [System.IO.DirectoryInfo]$WorkingDirectory = "C:\MEMNR\",
    [System.IO.DirectoryInfo]$LogDirectory = "C:\MEMNR\",
    [string]$CSVFile = "Get-MEMNetworkRequirements.csv",
    [int]$MaxDelayInMS = 300, #300 is recommended due to some Microsoft services being heavy load (like MS Update)
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
$Script:CRLURLsToCheck = [System.Collections.ArrayList]::new()
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
        [int[]]$IDs,
        [int[]]$FilterPort
    )
    if ($Script:URLsToVerify) {
        $script:URLsToVerify = [System.Collections.ArrayList]::new()
    }
    foreach ($ID in $IDs) {
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
    }
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
function Test-SSLInspectionByKnownCRLs {
    #Verify CRL against known good - this is an indicator for SSLInspection
    param(
        [string]$CRLURL
    )
    $SSLInspectionLikely = $true
    if (-not($Script:CRLURLsToCheck)) {
        if ($Script:ManualURLs) {
            $Script:ManualURLs | Where-Object { $_.id -in "125", "84" } | ForEach-Object { $Script:CRLURLsToCheck.add($_) | Out-Null }
        }
        if ($Script:M365ServiceURLs) {
            $Script:M365ServiceURLs | Where-Object { $_.id -in "125", "84" } | ForEach-Object { $Script:CRLURLsToCheck.add($_) | Out-Null }
        }
    }
    foreach ($URL in $Script:CRLURLsToCheck.url) {
        if ($CRLURL -like $("*" + $URL + "*")) {
            $SSLInspectionLikely = $false
        }
    }
    return $SSLInspectionLikely
}
function Test-SSL {
    param(
        $SSLTarget, 
        $SSLPort = 443
    )
    $TCPSocket = New-Object Net.Sockets.TcpClient($SSLTarget, $SSLPort)
    $SSLStream = New-Object -TypeName Net.Security.SslStream($TCPSocket.GetStream(), $false)
    try {
        $SSLStream.AuthenticateAsClient(
            $SSLTarget, #targetHost
            $null, #clientCertificates (Collection)
            $true #checkCertificateRevocation
        )
    } catch [System.Security.Authentication.AuthenticationException] {
        #THIS ONLY WORKS IN PS7!!
        if ($PSVersionTable.psversion.major -ge 7) {
            switch -Wildcard ($Error[0].Exception.InnerException.Message) {
                "Cannot determine the frame size or a corrupted frame was received." { $AuthException = "FrameSizeOrCorrupted" }
                "*TLS alert: 'HandshakeFailure'." { $AuthException = "HandshakeFailure" }
                "*validation procedure: RemoteCertificateNameMismatch" { $AuthException = "RemoteCertificateNameMismatch" }
                default { $AuthException = $Error[0].Exception.InnerException.Message.Split(':')[1].Trim() }
            } 
        } else {
            Write-Log -Message 'Cannot determine exact certificate failure, defaults to "failed"' -Component 'TestSSL' -Type 2
            $AuthException = "Failed"
        }
    } catch [System.Management.Automation.MethodInvocationException] {
        #TODO - Add a handler for random crashes of the tcp.socket
        Write-Log -Message 'The TCP socket closed unexpectedly. This could be random, repeat this test.' -Type 2 -Component 'TestSSL'
    }
    if ($SSLStream.IsAuthenticated) {
        $SSLTest = $true
        $CertInfo = New-Object -TypeName Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
        #$Test = New-Object -TypeName System.Net.Security.SslStreamCertificateContext.create($CertInfo)
        if ($CertInfo.Thumbprint) {
            Write-Log -Message "Grabbing CRL for $SSLTarget and verify against known-good" -Component 'TestSSL'
            $CRLURIarray = $CertInfo.Extensions |  Where-Object -FilterScript { $_.Oid.FriendlyName -Like 'CRL*' } | ForEach-Object -Process { $_.Oid.FriendlyName; $_.Format($true) }
            if ($CRLURIarray[1].split('[').count -eq 2) {
                #$CRLURI = $CRLURIarray.split('(')[2].split(')')[0]
                $CRLURI = $CRLURIarray[1].Split('http://')[1].split('/')[0]
                $SSLInspectionResult = Test-SSLInspectionByKnownCRLs -CRLURL $CRLURI
            } elseif ($CRLURIarray[1].split('[').count -gt 2) {
                $SSLInspectionResult = $CRLURIarray[1].split('=').split('[').trim() | Where-Object { $_.startswith("http://") } | ForEach-Object { Test-SSLInspectionByKnownCRLs -CRLURL $_.Split('http://')[1].split('/')[0] } | Where-Object { $_ -contains $true }
                if (-not($SSLInspectionResult)) { $SSLInspectionResult = $false }
            }
        }
    }
    $TCPSocket.Close()
    $TCPSocket.Dispose()
    if ($null -eq $SSLTest) {
        $SSLTest = $false
    }
    $Result = [PSCustomObject]@{
        SSLTest         = $SSLTest
        SSLProtocol     = $SSLStream.SslProtocol
        Issuer          = $CertInfo.Issuer
        AuthException   = $AuthException
        SSLInterception = $SSLInspectionResult
    }
    return $Result
}
function Test-HTTP {
    param(
        [string]$HTTPURL,
        [int]$HTTPPort
    )
    switch ($HTTPPort) {
        "80" { $URIStart = "http://" }
        "443" { $URIStart = "https://" }
        default { $URIStart = "https://" }
    }
    try {
        #We could use -SkipHttpErrorCheck in PS7...
        if ($PSVersionTable.psversion.major -ge 7) {
            $HTTPiwr = Invoke-WebRequest -Uri $($URIStart + $HTTPURL) -ConnectionTimeoutSeconds $(($MaxDelayInMS / 100)) -Method Get -SkipHttpErrorCheck
        } else {
            $HTTPiwr = Invoke-WebRequest -Uri $($URIStart + $HTTPURL) -ConnectionTimeoutSeconds $(($MaxDelayInMS / 100)) -Method Get 
        }
        return $HTTPiwr.StatusCode
    } catch {
        #This is only reached if PS5 is used
        $Statuscode = $error[0].Exception.Response.StatusCode.value__
        if ($Statuscode) {
            return $Statuscode
        }
        return $false
    }
}
function Test-DNS {
    #Verify answer isn't 0.0.0.0 or 127.0.0.1 or ::
    param(
        [string]$DNSTarget
    )
    $DNSresult = $true
    if ($DNSTarget -in $Script:DNSCache.CachedURL) {
        $CachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $DNSTarget } | Select-Object -Property result
        return $CachedResult.result
    }
    $ResolvedDNSRecords = Resolve-DnsName -Name $DNSTarget -ErrorAction SilentlyContinue
    if ($ResolvedDNSRecords.count) {
        foreach ($DNSARecord in $ResolvedDNSRecords.IP4Address) {
            if ($DNSARecord.IP4Address) {
                if ($DNSARecord -eq '0.0.0.0' -or $DNSARecord -eq '127.0.0.1') {
                    Write-Log -Message "DNS sinkhole detected: Address $DNSTarget resolved to an invalid address" -Component 'TestDNS' -Type 2
                    $DNSresult = $false
                    break
                }
            }
        }
        foreach ($DNSAAAARecord in $ResolvedDNSRecords.IP6Address) {
            if ($DNSAAAARecord -eq '::') {
                Write-Log -Message "DNS sinkhole detected: Address $DNSTarget resolved to an invalid address" -Component 'TestDNS' -Type 2
                $DNSresult = $false
                break
            }
        }
    } else {
        Write-Log -Message "No DNS record found for $DNSTarget" -Component 'TestDNS' -Type 3
        $DNSresult = $false
    }
    $DNSObject = [PSCustomObject]@{
        CachedURL = $DNSTarget
        Result    = $DNSresult
    }
    $Script:DNSCache.add($DNSObject) | Out-Null
    return $DNSresult
}
function Test-TCPPort {
    param(
        [string]$TCPTarget,
        [int]$TCPPort,
        [int]$MaxWaitTime
    )
    if (-not($MaxWaitTime)) {
        $MaxWaitTime = 150
    }
    if ($TCPTarget -in $Script:DNSCache.CachedURL) {
        $DNSCachedResult = $Script:DNSCache | Where-Object { $_.CachedURL -eq $TCPTarget } | Select-Object -Property result -First 1
        if (-not($DNSCachedResult.result)) {
            return $false
        }
    }
    if (-not($BurstMode)) {
        if ($TCPTarget -in $Script:TCPCache.CachedURL -and $TCPPort -in ($Script:TCPCache.Port | Where-Object { $_.CachedURL -eq $TCPTarget })) {
            $TCPCachedResult = $Script:TCPCache | Where-Object { $_.CachedURL -eq $TCPTarget } | Select-Object -Property result -First 1
            if (-not($TCPCachedResult.result)) {
                return $false
            }
        }
    }
    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
    $RunningClient = $TCPClient.ConnectAsync($TCPTarget, $TCPPort)
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
            CachedURL = $TCPTarget
            Port      = $TCPPort
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
function Test-Network {
    #ToDo: Make each check based upon a switch that is default = on
    param(
        [PSCustomObject]$TestObject
    )
    $TestObject | Add-Member -Name 'DNSResult' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'TCPResult' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'HTTPStatusCode' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLTest' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLProtocol' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'Issuer' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'AuthException' -MemberType NoteProperty -Value ""
    $TestObject | Add-Member -Name 'SSLInterception' -MemberType NoteProperty -Value ""
    $DNS = Test-DNS -DNSTarget $TestObject.url
    $TestObject.DNSResult = $DNS
    if ($DNS) {
        if ($BurstMode) {
            Test-TCPBurstMode -TCPTarget $TestObject.url
        } else {
            $TCP = Test-TCPPort -TCPTarget $TestObject.url -TCPPort $TestObject.port
            $TestObject.TCPResult = $TCP
            if ($TCP) {
                #Test HTTP(s) Connections
                $HTTPStatuscode = Test-HTTP -HTTPURL $TestObject.url -HTTPPort $TestObject.port
                if ($null -ne $HTTPStatuscode) {
                    $TestObject.HTTPStatusCode = $HTTPStatuscode
                } else { 
                    $TestObject.HTTPStatusCode = $false 
                }
                #Test TLS and verify everything around the cert including traffic interception
                $SSLTest = Test-SSL -SSLTarget $TestObject.url -SSLPort $TestObject.port
                $TestObject.SSlTest = $SSLTest.SSLTest

                if ($SSLTest.SSLTest) {
                    $TestObject.SSLProtocol = $SSLTest.SSLProtocol
                    $TestObject.Issuer = $SSLTest.Issuer
                    if ($SSLTest.AuthException) {
                        $TestObject.AuthException = $SSLTest.AuthException
                    }
                    if ($null -ne $SSLTest.SSLInterception) {
                        $TestObject.SSLInterception = $SSLTest.SSLInterception
                    }                   
                }
            }
        }
    }
    $Script:FinalResultList.add($TestObject) | Out-Null
}
function Test-RemoteHelp {
    <#
        #181
    #Remote Help - Default + Required https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#remote-help
    #ServiceIDs 181,187,189
    #ServiceIDs GCC 188
    #>

}

function Test-TPMAttestation {
    #ServiceIDs 173,9998
    #https://learn.microsoft.com/en-us/autopilot/requirements?tabs=networking#autopilot-self-deploying-mode-and-autopilot-pre-provisioning
    $ServiceIDs = 173, 9998
    $ServiceArea = "TPM"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $TPM = Get-URLsFromID -IDs $ServiceIDs
    if (-not($TPM)) {
        Write-Log -Message 'No matching ID found for service area: Windows (Push) Notification Services' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($TPMTarget in $Script:URLsToVerify) {
        Test-Network $TPMTarget
    }
    return $true
}
function Test-WNS {
    #ServiceIDs 169,171
    #https://learn.microsoft.com/en-us/mem/intune/fundamentals/intune-endpoints?tabs=europe#windows-push-notification-serviceswns-dependencies
    $ServiceIDs = 169, 171
    $ServiceArea = "WNS"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $WNS = Get-URLsFromID -IDs $ServiceIDs
    if (-not($WNS)) {
        Write-Log -Message 'No matching ID found for service area: Windows (Push) Notification Services' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($WNSTarget in $Script:URLsToVerify) {
        Test-Network $WNSTarget
    }
    return $true
}
function Test-DeviceHealth {
    <#
    Microsoft Azure Attestation (formerly Device Health)
    ServiceIDs 186
    #>
}

function Test-DeliveryOptimization {
    $ServiceIDs = 164
    $ServiceArea = "DO"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    Write-Log 'Filtered Port TCP 7680: Documentation will specify port 7680 TCP. This is used to listen to other clients requests (from the host)' -Component 'TestDO'
    Write-Log 'Filtered Port UDP 3544: Documentation will specify port 3544 UDP in/outbound as required - this is required for P2P connections' -Component 'TestDO'
    Write-Log 'Verify TCP Port 7680 is being listened on' -Component 'TestDO'
    $Listening = Get-NetTCPConnection -LocalPort 7680 -ErrorAction SilentlyContinue
    if (-not($Listening)) {
        Write-Log 'TCP Port 7680 not being listed as listening checking service' -Component 'TestDO'
        if (-not(Get-Service -Name DoSvc)) {
            Write-Log 'DoSvc is not running! Delivery optimization not possible' -Component 'TestDO' -Type 3
            return $false
        }
    }
    $DeliveryOptimization = Get-URLsFromID -IDs $ServiceIDs -FilterPort 7680, 3544
    if (-not($DeliveryOptimization)) {
        Write-Log -Message 'No matching ID found for service area: Delivery Optimization' -Component 'TestDO' -Type 3
        return $false
    }
    foreach ($DOTarget in $Script:URLsToVerify) {
        Test-Network $DOTarget
    }
    return $true
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
    $Autopilot = Get-URLsFromID -IDs $ServiceIDs
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
    #TODO: Build logic for these tests :)
    $WNSTest = Test-WNS
    $DOTest = Test-DeliveryOptimization
    $NTPTest = Test-NTP
    $TPMAttTest = Test-TPMAttestation
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
    $ServiceIDs = 164
    $ServiceArea = "WU"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $WindowsUpdate = Get-URLsFromID -IDs $ServiceIDs
    if (-not($WindowsUpdate)) {
        Write-Log -Message 'No matching ID found for service area: Windows Update' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($WUTarget in $Script:URLsToVerify) {
        Test-Network $WUTarget
    }
    return $true
}
function Test-NTP {
    #ServiceIDs 165
    #probably w32tm /stripchart /computer:time.windows.com /dataonly /samples:3
    #would throw 0x800705B4 if the URL exists but isn't an NTP or 0x80072AF9 for not resolved
    #"time.windows.com", "123" #NTP and SNTP both use this
    Write-Log 'Microsofts JSON claims more URLs for Port 123, where in reality its only time.windows.com' -Component 'TestNTP' -Type 2
    $CurrentTimeServer = w32tm /query /source
    #ToDo: Maybe also check the ACTUAL timeserver?
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
    $ServiceIDs = 9996
    $ServiceArea = "MS"
    Write-Log "Testing Service Area $ServiceArea" -Component "Test$ServiceArea"
    $MicrosoftStore = Get-URLsFromID -IDs $ServiceIDs
    if (-not($MicrosoftStore)) {
        Write-Log -Message 'No matching ID found for service area: Windows Update' -Component "Test$ServiceArea" -Type 3
        return $false
    }
    foreach ($MSTarget in $Script:URLsToVerify) {
        Test-Network $MSTarget
    }
    $WNSTest = Test-WNS
    $DOTest = Test-DeliveryOptimization
    if (-not($WNSTest -and $DOTest)) {
        return $false
    }
    return $true
    
}
function Test-M365 {

}
function Test-CRL {
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
#Test-WNS
Test-MicrosoftStore
#Test-DeliveryOptimization
#Test-WindowsUpdate
#Test-TPMAttestation

#ToDo: Out-Gridview
# * 3 modes by default only show "true/false"
# * second mode shows a little more detail like certificate information
# * third mode shows all errors?
$Script:FinalResultList | Out-GridView -Title 'Intune Network test results' -Wait   
#Build-Factory $TestMethods #This should create the final URL list and prepare the selected tests

<#if($UseMSJSON -and $UseCustomCSV){
    Write-Log -Message 'Both Microsoft JSON and custom CSV specified - creating merged ressults. If a URL exists multiple times the CSV wins' -Component 'MEMNRMain'
}
#>
#Test-Autopilot
Set-Location $CurrentLocation