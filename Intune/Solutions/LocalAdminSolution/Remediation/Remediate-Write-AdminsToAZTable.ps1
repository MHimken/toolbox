<#
.SYNOPSIS
    Collects the local Administrators group membership and writes the result to Azure Tables.
.DESCRIPTION
    This remediation targets domain joined, Microsoft Entra joined, and hybrid joined devices. It enumerates the
    localized built-in Administrators group, collects direct users and groups, resolves direct
    domain group members when domain connectivity is available, and writes a typed snapshot into
    three Azure Tables using SID-backed keys. Previously reported members that are no longer found
    are retained in the main table with Removed set to 1.
.NOTES
    Version: 2.5
    Author: Martin Himken
    Original script name: Remediate-Write-AdminsToAZTable.ps1
    Initial creation date: 2026-08-30
    Last change: 2026-09-02
    Changes: Suppresses unchanged lookup writes and submits newer name candidates for reconciliation.
.LINK
    ..\changelog.md
#>

$DomainName = '' #This can be set to a specific domain name to override the detected domain name for domain joined devices. If left empty, the detected domain name will be used.
$sasToken = '<sas-token>'
$MaxRetries = 3
$RetryDelaySeconds = 5
$storageAccountName = '<storage-account-name>'
$MainTable = 'LocalAdminCollection'
$AdminUserNames = 'AdminUserNames'
$AdminGroups = 'AdminGroups'

$ErrorActionPreference = 'Stop'

$script:UserLookup = @{}
$script:GroupLookup = @{}
$script:UserEntities = New-Object System.Collections.ArrayList
$script:GroupEntities = New-Object System.Collections.ArrayList
$script:MainEntities = New-Object System.Collections.ArrayList
$script:MainRowCounter = 1
$script:LookupRowsCreated = 0
$script:LookupCandidatesUpdated = 0
$script:LookupRowsSkipped = 0
$script:ObservationTimestamp = [datetime]::UtcNow

function Get-JoinState {
    $joinInfoPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDomainJoined = $false
    $detectedDomainName = ''

    if ($null -ne $computerSystem) {
        $isDomainJoined = [bool]$computerSystem.PartOfDomain
        $detectedDomainName = [string]$computerSystem.Domain
    }

    $isEntraJoined = (Get-ChildItem -LiteralPath $joinInfoPath -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
    $joinType = 0

    if ($isDomainJoined -and $isEntraJoined) {
        $joinType = 2
    } elseif ((-not $isDomainJoined) -and $isEntraJoined) {
        $joinType = 1
    } elseif ($isDomainJoined) {
        $joinType = 3
    }

    $effectiveDomainName = $detectedDomainName
    if (-not [string]::IsNullOrWhiteSpace($DomainName)) {
        $effectiveDomainName = $DomainName
    }

    [pscustomobject]@{
        IsDomainJoined      = $isDomainJoined
        IsEntraJoined       = $isEntraJoined
        EntraOrHybrid       = $joinType
        DeviceDomainName    = $detectedDomainName
        EffectiveDomainName = $effectiveDomainName
    }
}

function Get-LocalizedAdministratorsGroup {
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $translatedAccount = $administratorsSid.Translate([System.Security.Principal.NTAccount]).Value
    $localGroupName = $translatedAccount.Split('\')[-1]

    New-Object psobject -Property @{
        Name = $localGroupName
        Sid  = $administratorsSid.Value
        Path = 'WinNT://./{0},group' -f $localGroupName
    }
}

function Get-AdsPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$AdsObject,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    try {
        return $AdsObject.GetType().InvokeMember($PropertyName, 'GetProperty', $null, $AdsObject, $null)
    } catch {
        return $null
    }
}

function Get-LeafAccountName {
    param(
        [Parameter(Mandatory = $false)]
        [string]$AccountName
    )

    if ([string]::IsNullOrWhiteSpace($AccountName)) {
        return ''
    }

    if ($AccountName.Contains('\')) {
        return $AccountName.Split('\')[-1]
    }

    if ($AccountName.Contains('/')) {
        return $AccountName.Split('/')[-1]
    }

    return $AccountName
}

function Get-AuthorityName {
    param(
        [Parameter(Mandatory = $false)]
        [string]$AdsPath
    )

    if ([string]::IsNullOrWhiteSpace($AdsPath)) {
        return ''
    }

    $trimmedPath = $AdsPath -replace '^WinNT://', ''
    $pathParts = $trimmedPath.Split('/')
    if ($pathParts.Count -ge 2) {
        return $pathParts[0]
    }

    return ''
}

function Convert-ObjectSidToString {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SidValue,
        [Parameter(Mandatory = $false)]
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry,
        [Parameter(Mandatory = $false)]
        [string]$Authority,
        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    if ($null -ne $SidValue) {
        try {
            $sidText = [string]$SidValue
            if ($sidText -match '^S-\d-(?:\d+-)+\d+$') {
                return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sidText).Value
            }

            $sidBytes = [byte[]]@($SidValue)
            if ($sidBytes.Count -gt 0) {
                return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @($sidBytes, 0)).Value
            }
        } catch {
        }
    }

    if ($null -ne $DirectoryEntry) {
        try {
            $sidValue = $DirectoryEntry.Properties['objectSid'].Value
            if ($sidValue -is [byte[]]) {
                return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @($sidValue, 0)).Value
            }
        } catch {
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Authority) -and -not [string]::IsNullOrWhiteSpace($Name)) {
        try {
            return (New-Object System.Security.Principal.NTAccount -ArgumentList @($Authority, $Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
        }
    }

    return $null
}

function Get-MemberSource {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Member,
        [Parameter(Mandatory = $true)]
        [psobject]$JoinState
    )

    if ($Member.Sid -match '^S-1-12-1-') {
        return 'E'
    }

    if ($Member.Authority -ieq $env:COMPUTERNAME -or $Member.Authority -eq '.') {
        return 'L'
    }

    if ($Member.Authority -ieq 'AzureAD') {
        return 'E'
    }

    if ($Member.Authority -ieq 'BUILTIN' -or $Member.Authority -ieq 'NT AUTHORITY') {
        return 'L'
    }

    if ($JoinState.IsDomainJoined -and -not [string]::IsNullOrWhiteSpace($JoinState.EffectiveDomainName)) {
        return 'A'
    }

    return 'A'
}

function Get-EntraPrincipalName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $false)]
        [string]$FallbackName
    )

    $fallback = Get-LeafAccountName -AccountName $FallbackName
    if ([string]::IsNullOrWhiteSpace($fallback) -or
        $fallback -match '^S-\d-(?:\d+-)+\d+$' -or
        $fallback.Length -gt 128 -or
        $fallback -match '[/\\#?]' -or
        $fallback -match '[\x00-\x1F\x7F-\x9F]') {
        $fallback = $Sid
    }

    if ($Sid -notmatch '^S-1-12-1-') {
        return $fallback
    }

    $identityCachePath = 'HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\{0}\IdentityCache' -f $Sid
    try {
        $identityCache = Get-ItemProperty -LiteralPath $identityCachePath -ErrorAction Stop
        $displayName = [string]$identityCache.DisplayName
        if (-not [string]::IsNullOrWhiteSpace($displayName) -and
            $displayName -ne $Sid -and
            $displayName.Length -le 128 -and
            $displayName -notmatch '[/\\#?]' -and
            $displayName -notmatch '[\x00-\x1F\x7F-\x9F]') {
            return $displayName
        }

        $identityName = Get-LeafAccountName -AccountName ([string]$identityCache.IdentityName)
        if (-not [string]::IsNullOrWhiteSpace($identityName) -and
            $identityName -ne $Sid -and
            $identityName.Length -le 128 -and
            $identityName -notmatch '[/\\#?]' -and
            $identityName -notmatch '[\x00-\x1F\x7F-\x9F]') {
            return $identityName
        }
    } catch {
    }

    return $fallback
}

function Get-ComputerSid {
    $localAccount = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop |
        Where-Object { $_.SID -match '^S-1-5-21-(?:\d+-){3}\d+$' } |
        Select-Object -First 1

    if ($null -eq $localAccount) {
        throw 'The computer SID could not be determined from a local account.'
    }

    $computerSid = [string]$localAccount.SID -replace '-\d+$', ''
    try {
        $null = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $computerSid
    } catch {
        throw "The derived computer SID '$computerSid' is invalid."
    }

    return $computerSid
}

function Get-LocalUserDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $false)]
        [string]$FallbackName
    )

    $details = [pscustomobject]@{
        SamAccountName   = Get-LeafAccountName -AccountName $FallbackName
        UserPrincipalName = 'N/A'
        PasswordLastSet  = $null
    }

    try {
        $localUser = Get-LocalUser -SID $Sid -ErrorAction Stop
        $details.SamAccountName = [string]$localUser.Name
        $details.PasswordLastSet = $localUser.PasswordLastSet
    } catch {
    }

    return $details
}

function Get-LocalAdministratorsMembers {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupPath,
        [Parameter(Mandatory = $true)]
        [psobject]$JoinState
    )

    $administratorsGroup = New-Object System.DirectoryServices.DirectoryEntry($GroupPath)
    $results = New-Object System.Collections.ArrayList

    foreach ($member in $administratorsGroup.Invoke('Members')) {
        $memberAdsPath = [string](Get-AdsPropertyValue -AdsObject $member -PropertyName 'ADsPath')
        $memberName = [string](Get-AdsPropertyValue -AdsObject $member -PropertyName 'Name')
        $memberClass = [string](Get-AdsPropertyValue -AdsObject $member -PropertyName 'Class')
        $authorityName = Get-AuthorityName -AdsPath $memberAdsPath
        $directoryEntry = $null

        try {
            $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $memberAdsPath
        } catch {
        }

        $memberSidValue = Get-AdsPropertyValue -AdsObject $member -PropertyName 'ObjectSID'
        $resolvedSid = Convert-ObjectSidToString -SidValue $memberSidValue -DirectoryEntry $directoryEntry -Authority $authorityName -Name $memberName
        if ([string]::IsNullOrWhiteSpace($resolvedSid)) {
            $sidFromName = Get-LeafAccountName -AccountName $memberName
            if ($sidFromName -match '^S-\d-(?:\d+-)+\d+$') {
                $resolvedSid = Convert-ObjectSidToString -SidValue $sidFromName
            }
        }
        $accountName = $memberName
        if (-not [string]::IsNullOrWhiteSpace($authorityName)) {
            $accountName = '{0}\{1}' -f $authorityName, $memberName
        }

        if ([string]::IsNullOrWhiteSpace($resolvedSid)) {
            throw "The SID could not be resolved for Administrators member '$accountName' with class '$memberClass' and path '$memberAdsPath'."
        }

        [void]$results.Add([pscustomobject]@{
            Name        = $memberName
            AccountName = $accountName
            Sid         = $resolvedSid
            Class       = $memberClass
            AdsPath     = $memberAdsPath
            Authority   = $authorityName
            Source      = $null
        })
    }

    foreach ($result in $results) {
        $result.Source = Get-MemberSource -Member $result -JoinState $JoinState
    }

    return @($results)
}

function Test-DomainConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$JoinState
    )

    if (-not $JoinState.IsDomainJoined) {
        return $false
    }

    try {
        if (Test-ComputerSecureChannel -ErrorAction Stop) {
            return $true
        }
    } catch {
    }

    if ([string]::IsNullOrWhiteSpace($JoinState.EffectiveDomainName)) {
        return $false
    }

    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/RootDSE' -f $JoinState.EffectiveDomainName)
        $null = $rootDse.Properties['defaultNamingContext'][0]
        return $true
    } catch {
        return $false
    }
}

function Convert-SidToLdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
    $sidBytes = New-Object byte[] $sidObject.BinaryLength
    $sidObject.GetBinaryForm($sidBytes, 0)

    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $sidBytes) {
        [void]$builder.AppendFormat('\{0:X2}', $byte)
    }

    return $builder.ToString()
}

function Get-DomainUserDetails {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $true)]
        [psobject]$JoinState,
        [Parameter(Mandatory = $false)]
        [string]$FallbackName
    )

    $details = [pscustomobject]@{
        SamAccountName    = Get-LeafAccountName -AccountName $FallbackName
        UserPrincipalName = 'N/A'
        PasswordLastSet   = $null
    }

    if (-not (Test-DomainConnectivity -JoinState $JoinState)) {
        return $details
    }

    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/RootDSE' -f $JoinState.EffectiveDomainName)
        $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/{1}' -f $JoinState.EffectiveDomainName, $defaultNamingContext)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.PropertiesToLoad.Add('samaccountname') | Out-Null
        $searcher.PropertiesToLoad.Add('userprincipalname') | Out-Null
        $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(objectSid={0}))' -f (Convert-SidToLdapFilterValue -Sid $Sid)
        $result = $searcher.FindOne()
        if ($null -ne $result) {
            $details.SamAccountName = [string]$result.Properties['samaccountname'][0]
            $details.UserPrincipalName = [string]$result.Properties['userprincipalname'][0]
        }
    } catch {
    }

    return $details
}

function Get-SearchResultSid {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.SearchResult]$SearchResult
    )

    if ($SearchResult.Properties.Contains('objectsid')) {
        $sidBytes = $SearchResult.Properties['objectsid'][0]
        if ($sidBytes -is [byte[]]) {
            return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @($sidBytes, 0)).Value
        }
    }

    return $null
}

function Resolve-DomainGroupMembers {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$GroupMember,
        [Parameter(Mandatory = $true)]
        [psobject]$JoinState,
        [Parameter(Mandatory = $true)]
        [int]$RetryCount,
        [Parameter(Mandatory = $true)]
        [int]$RetryDelay
    )

    $resolution = [pscustomobject]@{
        ResolvedMembers = @()
        Status          = 'Skipped'
    }

    if ($GroupMember.Source -ne 'A') {
        return $resolution
    }

    if (-not (Test-DomainConnectivity -JoinState $JoinState)) {
        $resolution.Status = 'DomainUnavailable'
        return $resolution
    }

    if ([string]::IsNullOrWhiteSpace($GroupMember.Sid)) {
        $resolution.Status = 'MissingSid'
        return $resolution
    }

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $rootDse = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList ('LDAP://{0}/RootDSE' -f $JoinState.EffectiveDomainName)
            $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'][0]
            if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
                throw 'defaultNamingContext could not be determined.'
            }

            $searchRootPath = 'LDAP://{0}/{1}' -f $JoinState.EffectiveDomainName, $defaultNamingContext
            $searchRoot = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $searchRootPath
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.Add('member') | Out-Null
            $searcher.PropertiesToLoad.Add('samaccountname') | Out-Null
            $searcher.PropertiesToLoad.Add('objectsid') | Out-Null
            $searcher.PropertiesToLoad.Add('objectclass') | Out-Null
            $searcher.PropertiesToLoad.Add('name') | Out-Null
            $searcher.PropertiesToLoad.Add('userprincipalname') | Out-Null
            $searcher.Filter = '(&(objectCategory=group)(objectSid={0}))' -f (Convert-SidToLdapFilterValue -Sid $GroupMember.Sid)

            $groupResult = $searcher.FindOne()
            if ($null -eq $groupResult) {
                $resolution.Status = 'GroupNotFound'
                return $resolution
            }

            $resolvedMembers = New-Object System.Collections.ArrayList
            $memberDns = @($groupResult.Properties['member'])
            foreach ($memberDn in $memberDns) {
                try {
                    $memberEntryPath = 'LDAP://{0}/{1}' -f $JoinState.EffectiveDomainName, [string]$memberDn
                    $memberEntry = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $memberEntryPath
                    $null = $memberEntry.RefreshCache(@('sAMAccountName', 'userPrincipalName', 'objectSid', 'objectClass', 'name'))
                    $memberSid = $null
                    if ($memberEntry.Properties['objectSid'].Value -is [byte[]]) {
                        $memberSid = (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList @($memberEntry.Properties['objectSid'].Value, 0)).Value
                    }

                    $objectClassValues = @($memberEntry.Properties['objectClass'])
                    $objectClass = ''
                    if ($objectClassValues.Count -gt 0) {
                        $objectClass = [string]$objectClassValues[$objectClassValues.Count - 1]
                    }

                    $samAccountName = [string]$memberEntry.Properties['sAMAccountName'].Value
                    if ([string]::IsNullOrWhiteSpace($samAccountName)) {
                        $samAccountName = [string]$memberEntry.Properties['name'].Value
                    }

                    $resolvedAccountName = ''
                    if (-not [string]::IsNullOrWhiteSpace($samAccountName)) {
                        $resolvedAccountName = '{0}\{1}' -f $JoinState.EffectiveDomainName, $samAccountName
                    }

                    $userPrincipalName = [string]$memberEntry.Properties['userPrincipalName'].Value

                    [void]$resolvedMembers.Add([pscustomobject]@{
                        Name              = $samAccountName
                        Sid               = $memberSid
                        Class             = $objectClass
                        Source            = 'A'
                        AccountName       = $resolvedAccountName
                        SamAccountName    = $samAccountName
                        UserPrincipalName = $userPrincipalName
                    })
                } catch {
                }
            }

            $resolution.ResolvedMembers = @($resolvedMembers)
            $resolution.Status = 'Resolved'
            return $resolution
        } catch {
            if ($attempt -lt $RetryCount) {
                Start-Sleep -Seconds $RetryDelay
            } else {
                $resolution.Status = 'Failed'
                return $resolution
            }
        }
    }

    return $resolution
}

function Convert-TableValue {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ''
    }

    return $Value
}

function Get-UnicodeCodePointCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $count = 0
    for ($index = 0; $index -lt $Value.Length; $index++) {
        if ([char]::IsHighSurrogate($Value[$index])) {
            if (($index + 1 -ge $Value.Length) -or -not [char]::IsLowSurrogate($Value[$index + 1])) {
                throw 'Value contains an invalid Unicode surrogate sequence.'
            }

            $index++
        } elseif ([char]::IsLowSurrogate($Value[$index])) {
            throw 'Value contains an invalid Unicode surrogate sequence.'
        }

        $count++
    }

    return $count
}

function Get-RequiredTableValue {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName,
        [Parameter(Mandatory = $true)]
        [int]$MaximumLength,
        [Parameter(Mandatory = $false)]
        [switch]$UseNotAvailable,
        [Parameter(Mandatory = $false)]
        [switch]$CountUnicodeCodePoints
    )

    $result = $Value
    if ([string]::IsNullOrWhiteSpace($result)) {
        if ($UseNotAvailable) {
            $result = 'N/A'
        } else {
            throw "$PropertyName is required."
        }
    }

    $resultLength = if ($CountUnicodeCodePoints) { Get-UnicodeCodePointCount -Value $result } else { $result.Length }
    if ($resultLength -gt $MaximumLength) {
        throw "$PropertyName exceeds the maximum length of $MaximumLength characters."
    }

    return $result
}

function ConvertTo-AzureDateTime {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Value
    )

    return $Value.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Assert-ValidSourceCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    if ($Source -notin @('L', 'E', 'A')) {
        throw "LocalOrEntraOrAD must be L, E, or A. Received '$Source'."
    }
}

function Assert-ValidTableKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($Value -match '[/\\#?]' -or $Value -match '[\x00-\x1F\x7F-\x9F]') {
        throw "$PropertyName contains a character that Azure Table Storage does not allow in key fields."
    }
}

function Add-AdminUser {
    param(
        [Parameter(Mandatory = $false)]
        [string]$SamAccountName,
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $userId = Get-RequiredTableValue -Value $Sid -PropertyName 'UserID' -MaximumLength 256
    $resolvedSamAccountName = if ($SamAccountName -eq 'N/A') { 'N-A' } else { Get-LeafAccountName -AccountName $SamAccountName }
    if ([string]::IsNullOrWhiteSpace($resolvedSamAccountName)) {
        $resolvedSamAccountName = 'N-A'
    }
    $userName = Get-RequiredTableValue -Value $resolvedSamAccountName -PropertyName 'SamAccountName' -MaximumLength 20
    $upn = Get-RequiredTableValue -Value $UserPrincipalName -PropertyName 'UserPrincipalName' -MaximumLength 1024 -UseNotAvailable
    Assert-ValidSourceCode -Source $Source
    Assert-ValidTableKey -Value $userId -PropertyName 'UserID'
    Assert-ValidTableKey -Value $userName -PropertyName 'SamAccountName'
    $lookupKey = '{0}|{1}' -f $userId, $userName

    if ($script:UserLookup.ContainsKey($lookupKey)) {
        return $userId
    }

    $entity = [ordered]@{
        PartitionKey                   = $userId
        RowKey                         = $userName
        UserPrincipalName              = $upn
        LocalOrEntraOrAD               = $Source
        'ObservedAt@odata.type'         = 'Edm.DateTime'
        ObservedAt                     = ConvertTo-AzureDateTime -Value $script:ObservationTimestamp
        ResolutionState                = if ($Source -eq 'E') { 'EntraPending' } elseif ($userName -eq 'N-A' -or $userName -match '^S-\d-(?:\d+-)+\d+$') { 'DomainUnavailable' } else { 'Resolved' }
    }

    $record = [pscustomobject]$entity
    [void]$script:UserEntities.Add($record)
    $script:UserLookup[$lookupKey] = $record
    return $userId
}

function Add-AdminGroup {
    param(
        [Parameter(Mandatory = $false)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [string]$Sid,
        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $groupId = Get-RequiredTableValue -Value $Sid -PropertyName 'GroupID' -MaximumLength 256
    $groupNameValue = if ($GroupName -eq 'N/A') { 'N-A' } else { Get-LeafAccountName -AccountName $GroupName }
    if ([string]::IsNullOrWhiteSpace($groupNameValue)) {
        $groupNameValue = 'N-A'
    }
    $resolvedGroupName = Get-RequiredTableValue -Value $groupNameValue -PropertyName 'GroupName' -MaximumLength 128
    Assert-ValidSourceCode -Source $Source
    Assert-ValidTableKey -Value $groupId -PropertyName 'GroupID'
    Assert-ValidTableKey -Value $resolvedGroupName -PropertyName 'GroupName'
    $lookupKey = '{0}|{1}' -f $groupId, $resolvedGroupName

    if ($script:GroupLookup.ContainsKey($lookupKey)) {
        return $groupId
    }

    $entity = [ordered]@{
        PartitionKey                   = $groupId
        RowKey                         = $resolvedGroupName
        LocalOrEntraOrAD               = $Source
        'ObservedAt@odata.type'         = 'Edm.DateTime'
        ObservedAt                     = ConvertTo-AzureDateTime -Value $script:ObservationTimestamp
        ResolutionState                = if ($Source -eq 'E') { 'EntraPending' } elseif ($resolvedGroupName -match '^S-\d-(?:\d+-)+\d+$') { 'DomainUnavailable' } else { 'Resolved' }
    }

    $record = [pscustomobject]$entity
    [void]$script:GroupEntities.Add($record)
    $script:GroupLookup[$lookupKey] = $record
    return $groupId
}

function Add-MainTableRow {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'This value is a password-change timestamp, not a password.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerSid,
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [int]$EntraOrHybrid,
        [Parameter(Mandatory = $true)]
        [datetime]$Timestamp,
        [Parameter(Mandatory = $true)]
        [string]$AdminGroupName,
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group')]
        [string]$PrincipalType,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Direct', 'Transitive')]
        [string]$MembershipType,
        [Parameter(Mandatory = $false)]
        [string]$AssignedThroughGroupId,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LocalAccountCredentialChangedAt,
        [Parameter(Mandatory = $false)]
        [ValidateSet(0, 1)]
        [int]$Removed = 0,
        [Parameter(Mandatory = $false)]
        [int]$EntryNumber = 0
    )

    $computerId = Get-RequiredTableValue -Value $ComputerSid -PropertyName 'ComputerID' -MaximumLength 256
    $resolvedComputerName = Get-RequiredTableValue -Value $ComputerName -PropertyName 'Computername' -MaximumLength 63 -CountUnicodeCodePoints
    $resolvedAdminGroupName = Get-RequiredTableValue -Value $AdminGroupName -PropertyName 'LocalAdminGroupName' -MaximumLength 128
    Assert-ValidTableKey -Value $computerId -PropertyName 'ComputerID'
    if (($EntraOrHybrid -lt 1) -or ($EntraOrHybrid -gt 3)) {
        throw 'EntraOrHybrid must be 1, 2, or 3.'
    }

    $resolvedPrincipalId = Get-RequiredTableValue -Value $PrincipalId -PropertyName 'PrincipalID' -MaximumLength 256
    if ($resolvedPrincipalId -notmatch '^S-\d-(?:\d+-)+\d+$') {
        throw 'PrincipalID must be a valid SID.'
    }

    if ($MembershipType -eq 'Direct' -and -not [string]::IsNullOrWhiteSpace($AssignedThroughGroupId)) {
        throw 'AssignedThroughGroupID must not be set for direct membership.'
    }

    if ($MembershipType -eq 'Transitive' -and [string]::IsNullOrWhiteSpace($AssignedThroughGroupId)) {
        throw 'AssignedThroughGroupID must be set for transitive membership.'
    }

    if ($EntryNumber -le 0) {
        $EntryNumber = $script:MainRowCounter
        $script:MainRowCounter++
    }

    $entity = [ordered]@{
        PartitionKey                        = $computerId
        RowKey                              = [string]$EntryNumber
        Computername                        = $resolvedComputerName
        EntraOrHybrid                       = [string]$EntraOrHybrid
        'LastReportTimeStamp@odata.type'    = 'Edm.DateTime'
        LastReportTimeStamp                 = ConvertTo-AzureDateTime -Value $Timestamp
        LocalAdminGroupName                 = $resolvedAdminGroupName
        PrincipalID                        = $resolvedPrincipalId
        PrincipalType                      = $PrincipalType
        MembershipType                     = $MembershipType
        Removed                             = $Removed
    }

    if ($MembershipType -eq 'Transitive') {
        $resolvedAssignedThroughGroupId = Get-RequiredTableValue -Value $AssignedThroughGroupId -PropertyName 'AssignedThroughGroupID' -MaximumLength 256
        if ($resolvedAssignedThroughGroupId -notmatch '^S-\d-(?:\d+-)+\d+$') {
            throw 'AssignedThroughGroupID must be a valid SID.'
        }

        $entity.AssignedThroughGroupID = $resolvedAssignedThroughGroupId
    }

    if ($LocalAccountCredentialChangedAt -is [datetime]) {
        $entity['LocalAccountLastPasswordChange@odata.type'] = 'Edm.DateTime'
        $entity.LocalAccountLastPasswordChange = ConvertTo-AzureDateTime -Value $LocalAccountCredentialChangedAt
    }

    [void]$script:MainEntities.Add([pscustomobject]$entity)
}

function Get-TrimmedSasToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq '<sas-token>') {
        throw 'sasToken is not configured.'
    }

    return $Token.TrimStart('?')
}

function Get-StorageHeaders {
    return @{
        'Accept'            = 'application/json;odata=nometadata'
        'Content-Type'      = 'application/json'
        'DataServiceVersion' = '3.0;NetFx'
        'MaxDataServiceVersion' = '3.0;NetFx'
        'x-ms-version'      = '2023-11-03'
    }
}

function Get-TableUri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    return 'https://{0}.table.core.windows.net/{1}?{2}' -f $storageAccountName, $TableName, $Token
}

function Test-StorageAccountResolution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccount
    )

    $storageHost = '{0}.table.core.windows.net' -f $StorageAccount

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($storageHost)
        return ($addresses | Measure-Object).Count -gt 0
    } catch {
        return $false
    }
}

function Get-EntityUri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$PartitionKey,
        [Parameter(Mandatory = $true)]
        [string]$RowKey,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $escapedPartitionKey = [System.Uri]::EscapeDataString($PartitionKey.Replace("'", "''"))
    $escapedRowKey = [System.Uri]::EscapeDataString($RowKey.Replace("'", "''"))
    return "https://{0}.table.core.windows.net/{1}(PartitionKey='{2}',RowKey='{3}')?{4}" -f $storageAccountName, $TableName, $escapedPartitionKey, $escapedRowKey, $Token
}

function Get-HttpErrorResponseBody {
    param(
        [Parameter(Mandatory = $false)]
        [System.Net.WebResponse]$Response
    )

    if ($null -eq $Response) {
        return ''
    }

    $reader = $null
    try {
        $responseStream = $Response.GetResponseStream()
        if ($null -eq $responseStream) {
            return ''
        }

        $reader = New-Object System.IO.StreamReader($responseStream)
        return $reader.ReadToEnd().Trim()
    } catch {
        return ''
    } finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Get-TablePartitionEntities {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$PartitionKey,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $escapedPartitionKey = $PartitionKey.Replace("'", "''")
    $encodedFilter = [System.Uri]::EscapeDataString("PartitionKey eq '$escapedPartitionKey'")
    $uri = "https://{0}.table.core.windows.net/{1}()?`$filter={2}&{3}" -f $storageAccountName, $TableName, $encodedFilter, $Token
    $entities = New-Object System.Collections.ArrayList

    do {
        $response = Invoke-WebRequest -Uri $uri -Method Get -Headers (Get-StorageHeaders) -UseBasicParsing -ErrorAction Stop
        $payload = $response.Content | ConvertFrom-Json
        foreach ($entity in @($payload.value)) {
            [void]$entities.Add($entity)
        }

        $nextPartitionKey = [string]$response.Headers['x-ms-continuation-NextPartitionKey']
        $nextRowKey = [string]$response.Headers['x-ms-continuation-NextRowKey']
        if (-not [string]::IsNullOrWhiteSpace($nextPartitionKey)) {
            $uri = "https://{0}.table.core.windows.net/{1}()?`$filter={2}&NextPartitionKey={3}&NextRowKey={4}&{5}" -f $storageAccountName, $TableName, $encodedFilter, [System.Uri]::EscapeDataString($nextPartitionKey), [System.Uri]::EscapeDataString($nextRowKey), $Token
        } else {
            $uri = $null
        }
    } while ($null -ne $uri)

    return @($entities)
}

function ConvertTo-LookupDateTime {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    $parsed = [datetime]::MinValue
    if ($null -ne $Value -and [datetime]::TryParse(
            [string]$Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal,
            [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }

    return [datetime]::MinValue
}

function Get-LookupObservationTime {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entity,
        [Parameter(Mandatory = $false)]
        [switch]$Candidate
    )

    if ($Candidate) {
        return ConvertTo-LookupDateTime -Value $Entity.CandidateObservedAt
    }

    $observedAt = ConvertTo-LookupDateTime -Value $Entity.ObservedAt
    if ($observedAt -ne [datetime]::MinValue) {
        return $observedAt
    }

    return ConvertTo-LookupDateTime -Value $Entity.Timestamp
}

function Select-CanonicalLookupEntity {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entities
    )

    if ($Entities.Count -eq 0) {
        return $null
    }

    return @($Entities | Sort-Object -Property @(
        @{ Expression = { if ([string]$_.ResolutionState -eq 'Resolved') { 1 } else { 0 } }; Descending = $true },
        @{ Expression = { Get-LookupObservationTime -Entity $_ }; Descending = $true },
        @{ Expression = { [string]$_.RowKey }; Descending = $true }
    ))[0]
}

function Test-LookupValuesEqual {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group')]
        [string]$LookupType,
        [Parameter(Mandatory = $true)]
        [psobject]$Left,
        [Parameter(Mandatory = $true)]
        [psobject]$Right,
        [Parameter(Mandatory = $false)]
        [switch]$RightIsCandidate
    )

    if ($LookupType -eq 'Group') {
        $rightName = if ($RightIsCandidate) { [string]$Right.CandidateGroupName } else { [string]$Right.RowKey }
        return [string]::Equals([string]$Left.RowKey, $rightName, [System.StringComparison]::OrdinalIgnoreCase)
    }

    $rightName = if ($RightIsCandidate) { [string]$Right.CandidateSamAccountName } else { [string]$Right.RowKey }
    $rightUpn = if ($RightIsCandidate) { [string]$Right.CandidateUserPrincipalName } else { [string]$Right.UserPrincipalName }
    return [string]::Equals([string]$Left.RowKey, $rightName, [System.StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals([string]$Left.UserPrincipalName, $rightUpn, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-ExactTableEntity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [string]$PartitionKey,
        [Parameter(Mandatory = $true)]
        [string]$RowKey,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $uri = Get-EntityUri -TableName $TableName -PartitionKey $PartitionKey -RowKey $RowKey -Token $Token
    $response = Invoke-WebRequest -Uri $uri -Method Get -Headers (Get-StorageHeaders) -UseBasicParsing -ErrorAction Stop
    [pscustomobject]@{
        Entity = $response.Content | ConvertFrom-Json
        ETag   = [string]$response.Headers['ETag']
    }
}

function Set-LookupCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group')]
        [string]$LookupType,
        [Parameter(Mandatory = $true)]
        [psobject]$ObservedEntity,
        [Parameter(Mandatory = $true)]
        [psobject]$CanonicalEntity,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $current = Get-ExactTableEntity -TableName $TableName -PartitionKey ([string]$CanonicalEntity.PartitionKey) -RowKey ([string]$CanonicalEntity.RowKey) -Token $Token
        } catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { $null }
            if ($attempt -eq 2 -and $statusCode -eq 404) {
                $script:LookupRowsSkipped++
                return
            }
            throw
        }
        if (Test-LookupValuesEqual -LookupType $LookupType -Left $ObservedEntity -Right $current.Entity) {
            $script:LookupRowsSkipped++
            return
        }

        $candidateTime = Get-LookupObservationTime -Entity $current.Entity -Candidate
        if ((Test-LookupValuesEqual -LookupType $LookupType -Left $ObservedEntity -Right $current.Entity -RightIsCandidate) -or
            $script:ObservationTimestamp -le (Get-LookupObservationTime -Entity $current.Entity) -or
            $script:ObservationTimestamp -le $candidateTime) {
            $script:LookupRowsSkipped++
            return
        }

        $candidate = [ordered]@{
            PartitionKey                    = [string]$current.Entity.PartitionKey
            RowKey                          = [string]$current.Entity.RowKey
            'CandidateObservedAt@odata.type' = 'Edm.DateTime'
            CandidateObservedAt             = ConvertTo-AzureDateTime -Value $script:ObservationTimestamp
        }
        if ($LookupType -eq 'Group') {
            $candidate.CandidateGroupName = [string]$ObservedEntity.RowKey
        } else {
            $candidate.CandidateSamAccountName = [string]$ObservedEntity.RowKey
            $candidate.CandidateUserPrincipalName = [string]$ObservedEntity.UserPrincipalName
        }

        $headers = Get-StorageHeaders
        $headers['If-Match'] = if ([string]::IsNullOrWhiteSpace($current.ETag)) { '*' } else { $current.ETag }
        $uri = Get-EntityUri -TableName $TableName -PartitionKey $candidate.PartitionKey -RowKey $candidate.RowKey -Token $Token
        $body = [System.Text.Encoding]::UTF8.GetBytes(($candidate | ConvertTo-Json -Depth 4 -Compress))
        try {
            Invoke-RestMethod -Uri $uri -Method Merge -Headers $headers -Body $body -ErrorAction Stop | Out-Null
            $script:LookupCandidatesUpdated++
            return
        } catch {
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { $null }
            if ($statusCode -ne 412 -or $attempt -eq 2) {
                throw
            }
        }
    }
}

function Write-LookupEntitySet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group')]
        [string]$LookupType,
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Entities,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    foreach ($entity in $Entities) {
        $existing = @(Get-TablePartitionEntities -TableName $TableName -PartitionKey ([string]$entity.PartitionKey) -Token $Token)
        if ($existing.Count -eq 0) {
            Set-TableEntity -TableName $TableName -Entity $entity -Token $Token
            $script:LookupRowsCreated++
            continue
        }

        $canonical = Select-CanonicalLookupEntity -Entities $existing
        if ([string]$entity.LocalOrEntraOrAD -eq 'E' -or
            [string]$entity.ResolutionState -eq 'DomainUnavailable' -or
            (Test-LookupValuesEqual -LookupType $LookupType -Left $entity -Right $canonical)) {
            $script:LookupRowsSkipped++
            continue
        }

        Set-LookupCandidate -TableName $TableName -LookupType $LookupType -ObservedEntity $entity -CanonicalEntity $canonical -Token $Token
    }
}

function Get-MainEntityIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entity
    )

    $principalId = [string]$Entity.PrincipalID
    $principalType = [string]$Entity.PrincipalType
    $membershipType = [string]$Entity.MembershipType
    if ([string]::IsNullOrWhiteSpace($principalId) -or $principalType -notin @('User', 'Group')) {
        return $null
    }

    if ($membershipType -eq 'Direct') {
        return '{0}|{1}|Direct' -f $principalType, $principalId
    }

    $assignedThroughGroupId = [string]$Entity.AssignedThroughGroupID
    if ($membershipType -eq 'Transitive' -and -not [string]::IsNullOrWhiteSpace($assignedThroughGroupId)) {
        return '{0}|{1}|{2}' -f $principalType, $principalId, $assignedThroughGroupId
    }

    return $null
}

function Merge-MainEntitySnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$ExistingEntities,
        [Parameter(Mandatory = $true)]
        [datetime]$Timestamp
    )

    $existingByIdentity = @{}
    $maximumEntryNumber = 0
    foreach ($existingEntity in $ExistingEntities) {
        $entryNumber = 0
        if ([int]::TryParse([string]$existingEntity.RowKey, [ref]$entryNumber) -and $entryNumber -gt $maximumEntryNumber) {
            $maximumEntryNumber = $entryNumber
        }

        $identity = Get-MainEntityIdentity -Entity $existingEntity
        if ($null -ne $identity -and -not $existingByIdentity.ContainsKey($identity)) {
            $existingByIdentity[$identity] = $existingEntity
        }
    }

    $reconciled = New-Object System.Collections.ArrayList
    $activeIdentities = @{}
    foreach ($currentEntity in $script:MainEntities) {
        $identity = Get-MainEntityIdentity -Entity $currentEntity
        if ($null -eq $identity -or $activeIdentities.ContainsKey($identity)) {
            continue
        }

        $activeIdentities[$identity] = $true
        if ($existingByIdentity.ContainsKey($identity)) {
            $currentEntity.RowKey = [string]$existingByIdentity[$identity].RowKey
        } else {
            $maximumEntryNumber++
            $currentEntity.RowKey = [string]$maximumEntryNumber
        }

        $currentEntity.Removed = 0
        [void]$reconciled.Add($currentEntity)
    }

    foreach ($identity in $existingByIdentity.Keys) {
        if ($activeIdentities.ContainsKey($identity)) {
            continue
        }

        $existingEntity = $existingByIdentity[$identity]
        $removedEntity = [ordered]@{
            PartitionKey                     = [string]$existingEntity.PartitionKey
            RowKey                           = [string]$existingEntity.RowKey
            Computername                     = [string]$existingEntity.Computername
            EntraOrHybrid                    = [string]$existingEntity.EntraOrHybrid
            'LastReportTimeStamp@odata.type' = 'Edm.DateTime'
            LastReportTimeStamp              = ConvertTo-AzureDateTime -Value $Timestamp
            LocalAdminGroupName              = [string]$existingEntity.LocalAdminGroupName
            Removed                          = 1
        }

        $removedEntity.PrincipalID = [string]$existingEntity.PrincipalID
        $removedEntity.PrincipalType = [string]$existingEntity.PrincipalType
        $removedEntity.MembershipType = [string]$existingEntity.MembershipType
        if ([string]$existingEntity.MembershipType -eq 'Transitive') {
            $removedEntity.AssignedThroughGroupID = [string]$existingEntity.AssignedThroughGroupID
        }

        if (-not [string]::IsNullOrWhiteSpace([string]$existingEntity.LocalAccountLastPasswordChange)) {
            $removedEntity['LocalAccountLastPasswordChange@odata.type'] = 'Edm.DateTime'
            $removedEntity.LocalAccountLastPasswordChange = ConvertTo-AzureDateTime -Value ([datetime]$existingEntity.LocalAccountLastPasswordChange)
        }

        [void]$reconciled.Add([pscustomobject]$removedEntity)
    }

    $script:MainEntities.Clear()
    foreach ($entity in $reconciled) {
        [void]$script:MainEntities.Add($entity)
    }
}

function Set-TableEntity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [psobject]$Entity,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    Assert-TableEntity -TableName $TableName -Entity $Entity
    $headers = Get-StorageHeaders
    $entityUri = Get-EntityUri -TableName $TableName -PartitionKey $Entity.PartitionKey -RowKey $Entity.RowKey -Token $Token
    $jsonPayload = $Entity | ConvertTo-Json -Depth 4 -Compress
    $requestBody = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)

    try {
        Invoke-RestMethod -Uri $entityUri -Method Put -Headers $headers -Body $requestBody -ErrorAction Stop | Out-Null
    } catch {
        $statusCode = $null
        $responseBody = [string]$_.ErrorDetails.Message
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
            if ([string]::IsNullOrWhiteSpace($responseBody)) {
                $responseBody = Get-HttpErrorResponseBody -Response $_.Exception.Response
            }
        }

        if ($statusCode -eq 404) {
            throw "Azure table '$TableName' was not found. Create the table first or grant table create permission to the SAS token."
        }

        if ($statusCode -eq 403) {
            throw "Azure table '$TableName' rejected the upsert request with 403. The SAS token does not have the required add/update permissions for this table."
        }

        $entityIdentity = '{0}/{1}' -f [string]$Entity.PartitionKey, [string]$Entity.RowKey
        $errorDetail = if ([string]::IsNullOrWhiteSpace($responseBody)) { $_.Exception.Message } else { $responseBody }
        throw "Azure table '$TableName' rejected entity '$entityIdentity' with HTTP $statusCode. $errorDetail"
    }
}

function Assert-TableEntity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [psobject]$Entity
    )

    $partitionKey = Get-RequiredTableValue -Value ([string]$Entity.PartitionKey) -PropertyName 'PartitionKey' -MaximumLength 1024
    $rowKey = Get-RequiredTableValue -Value ([string]$Entity.RowKey) -PropertyName 'RowKey' -MaximumLength 1024
    Assert-ValidTableKey -Value $partitionKey -PropertyName 'PartitionKey'
    Assert-ValidTableKey -Value $rowKey -PropertyName 'RowKey'

    if ($TableName -eq $MainTable) {
        $null = Get-RequiredTableValue -Value ([string]$Entity.Computername) -PropertyName 'Computername' -MaximumLength 63 -CountUnicodeCodePoints
        $null = Get-RequiredTableValue -Value ([string]$Entity.LocalAdminGroupName) -PropertyName 'LocalAdminGroupName' -MaximumLength 128
        if ([string]$Entity.EntraOrHybrid -notmatch '^[123]$') {
            throw 'EntraOrHybrid must contain one of the values 1, 2, or 3.'
        }

        $entryNumber = 0
        if (-not [int]::TryParse($rowKey, [ref]$entryNumber) -or $entryNumber -le 0) {
            throw 'EntryNumber must be a positive Int32 serialized as RowKey text.'
        }

        if ([string]$Entity.'LastReportTimeStamp@odata.type' -ne 'Edm.DateTime') {
            throw 'LastReportTimeStamp must have the Edm.DateTime annotation.'
        }

        if ([int]$Entity.Removed -notin @(0, 1)) {
            throw 'Removed must be the Int32 value 0 or 1.'
        }

        $principalId = Get-RequiredTableValue -Value ([string]$Entity.PrincipalID) -PropertyName 'PrincipalID' -MaximumLength 256
        if ($principalId -notmatch '^S-\d-(?:\d+-)+\d+$') {
            throw 'PrincipalID must be a valid SID.'
        }

        $principalType = [string]$Entity.PrincipalType
        if ($principalType -notin @('User', 'Group')) {
            throw 'PrincipalType must contain User or Group.'
        }

        $membershipType = [string]$Entity.MembershipType
        $assignedThroughGroupId = [string]$Entity.AssignedThroughGroupID
        if ($membershipType -eq 'Direct' -and -not [string]::IsNullOrWhiteSpace($assignedThroughGroupId)) {
            throw 'AssignedThroughGroupID must not be set for direct membership.'
        }

        if ($membershipType -eq 'Transitive') {
            $assignedThroughGroupId = Get-RequiredTableValue -Value $assignedThroughGroupId -PropertyName 'AssignedThroughGroupID' -MaximumLength 256
            if ($assignedThroughGroupId -notmatch '^S-\d-(?:\d+-)+\d+$') {
                throw 'AssignedThroughGroupID must be a valid SID.'
            }
        } elseif ($membershipType -ne 'Direct') {
            throw 'MembershipType must contain Direct or Transitive.'
        }

        if ($Entity.PSObject.Properties.Name -contains 'LocalAccountLastPasswordChange') {
            if ([string]$Entity.'LocalAccountLastPasswordChange@odata.type' -ne 'Edm.DateTime') {
                throw 'LocalAccountLastPasswordChange must have the Edm.DateTime annotation.'
            }
        }
    } elseif ($TableName -eq $AdminGroups) {
        $null = Get-RequiredTableValue -Value $partitionKey -PropertyName 'GroupID' -MaximumLength 256
        $null = Get-RequiredTableValue -Value $rowKey -PropertyName 'GroupName' -MaximumLength 128
        Assert-ValidSourceCode -Source ([string]$Entity.LocalOrEntraOrAD)
        if ([string]$Entity.ResolutionState -notin @('Resolved', 'EntraPending', 'DomainUnavailable')) {
            throw 'ResolutionState must contain Resolved, EntraPending, or DomainUnavailable.'
        }
    } elseif ($TableName -eq $AdminUserNames) {
        $null = Get-RequiredTableValue -Value $partitionKey -PropertyName 'UserID' -MaximumLength 256
        $null = Get-RequiredTableValue -Value $rowKey -PropertyName 'SamAccountName' -MaximumLength 20
        $null = Get-RequiredTableValue -Value ([string]$Entity.UserPrincipalName) -PropertyName 'UserPrincipalName' -MaximumLength 1024
        Assert-ValidSourceCode -Source ([string]$Entity.LocalOrEntraOrAD)
        if ([string]$Entity.ResolutionState -notin @('Resolved', 'EntraPending', 'DomainUnavailable')) {
            throw 'ResolutionState must contain Resolved, EntraPending, or DomainUnavailable.'
        }
    } else {
        throw "No schema validator is defined for table '$TableName'."
    }
}

function Write-EntitySet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TableName,
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Entities,
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    foreach ($entity in $Entities) {
        Set-TableEntity -TableName $TableName -Entity $entity -Token $Token
    }
}

try {
    $joinState = Get-JoinState

    if ($joinState.EntraOrHybrid -eq 0) {
        Write-Output 'COMPLIANT: Device is neither domain joined, hybrid joined, nor Microsoft Entra joined only.'
        exit 0
    }

    if ([string]::IsNullOrWhiteSpace($storageAccountName) -or $storageAccountName -eq '<storage-account-name>') {
        throw 'storageAccountName is not configured.'
    }

    if (-not (Test-StorageAccountResolution -StorageAccount $storageAccountName)) {
        throw ('The storage account URL {0}.table.core.windows.net could not be resolved.' -f $storageAccountName)
    }

    $sanitizedSasToken = Get-TrimmedSasToken -Token $sasToken

    $administratorsGroup = Get-LocalizedAdministratorsGroup
    $computerSid = Get-ComputerSid
    $timestamp = $script:ObservationTimestamp
    $existingMainEntities = @(Get-TablePartitionEntities -TableName $MainTable -PartitionKey $computerSid -Token $sanitizedSasToken)
    $localMembers = @(Get-LocalAdministratorsMembers -GroupPath $administratorsGroup.Path -JoinState $joinState)

    foreach ($member in $localMembers) {
        $isGroup = $member.Class -ieq 'Group'
        $displayName = $member.AccountName

        if ($isGroup) {
            $groupName = if ($member.Source -eq 'E') { Get-EntraPrincipalName -Sid $member.Sid -FallbackName $displayName } else { $displayName }
            $groupId = Add-AdminGroup -GroupName $groupName -Sid $member.Sid -Source $member.Source
            Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -PrincipalId $groupId -PrincipalType Group -MembershipType Direct

            $groupResolution = Resolve-DomainGroupMembers -GroupMember $member -JoinState $joinState -RetryCount $MaxRetries -RetryDelay $RetryDelaySeconds
            foreach ($resolvedMember in $groupResolution.ResolvedMembers) {
                if ($resolvedMember.Class -ieq 'group') {
                    $resolvedGroupId = Add-AdminGroup -GroupName $resolvedMember.AccountName -Sid $resolvedMember.Sid -Source $resolvedMember.Source
                    Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -PrincipalId $resolvedGroupId -PrincipalType Group -MembershipType Transitive -AssignedThroughGroupId $groupId
                } else {
                    $resolvedUserId = Add-AdminUser -SamAccountName $resolvedMember.SamAccountName -UserPrincipalName $resolvedMember.UserPrincipalName -Sid $resolvedMember.Sid -Source $resolvedMember.Source
                    Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -PrincipalId $resolvedUserId -PrincipalType User -MembershipType Transitive -AssignedThroughGroupId $groupId
                }
            }

            continue
        }

        $userDetails = if ($member.Source -eq 'L') {
            Get-LocalUserDetails -Sid $member.Sid -FallbackName $member.AccountName
        } elseif ($member.Source -eq 'A') {
            Get-DomainUserDetails -Sid $member.Sid -JoinState $joinState -FallbackName $member.AccountName
        } else {
            $entraName = Get-LeafAccountName -AccountName $member.AccountName
            [pscustomobject]@{
                SamAccountName    = 'N/A'
                UserPrincipalName = if ($entraName -match '@') { $entraName } else { 'N/A' }
                PasswordLastSet   = $null
            }
        }

        $userId = Add-AdminUser -SamAccountName $userDetails.SamAccountName -UserPrincipalName $userDetails.UserPrincipalName -Sid $member.Sid -Source $member.Source
        Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -PrincipalId $userId -PrincipalType User -MembershipType Direct -LocalAccountCredentialChangedAt $userDetails.PasswordLastSet
    }

    Merge-MainEntitySnapshot -ExistingEntities $existingMainEntities -Timestamp $timestamp

    Write-LookupEntitySet -TableName $AdminUserNames -LookupType User -Entities $script:UserEntities -Token $sanitizedSasToken
    Write-LookupEntitySet -TableName $AdminGroups -LookupType Group -Entities $script:GroupEntities -Token $sanitizedSasToken
    Write-EntitySet -TableName $MainTable -Entities $script:MainEntities -Token $sanitizedSasToken

    Write-Output ('COMPLIANT: Uploaded {0} main rows; created {1} lookup rows, updated {2} candidates, and skipped {3} unchanged lookup rows.' -f $script:MainEntities.Count, $script:LookupRowsCreated, $script:LookupCandidatesUpdated, $script:LookupRowsSkipped)
    exit 0
} catch {
    Write-Output "ERROR: Remediation failed. $($_.Exception.Message)"
    exit 1
}