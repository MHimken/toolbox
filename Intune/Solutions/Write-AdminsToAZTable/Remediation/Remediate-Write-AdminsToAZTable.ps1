<#
.SYNOPSIS
    Collects the local Administrators group membership and writes the result to Azure Tables.
.DESCRIPTION
    This remediation targets domain joined, Microsoft Entra joined, and hybrid joined devices. It enumerates the
    localized built-in Administrators group, collects direct users and groups, resolves direct
    domain group members when domain connectivity is available, and writes a typed snapshot into
    three Azure Tables using SID-backed keys. Previously reported members that are no longer found
    are retained in the main table with Removed set to 1.
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
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry,
        [Parameter(Mandatory = $false)]
        [string]$Authority,
        [Parameter(Mandatory = $false)]
        [string]$Name
    )

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

        $resolvedSid = Convert-ObjectSidToString -DirectoryEntry $directoryEntry -Authority $authorityName -Name $memberName
        $accountName = $memberName
        if (-not [string]::IsNullOrWhiteSpace($authorityName)) {
            $accountName = '{0}\{1}' -f $authorityName, $memberName
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
        [switch]$UseNotAvailable
    )

    $result = $Value
    if ([string]::IsNullOrWhiteSpace($result)) {
        if ($UseNotAvailable) {
            $result = 'N/A'
        } else {
            throw "$PropertyName is required."
        }
    }

    if ($result.Length -gt $MaximumLength) {
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
        PartitionKey        = $userId
        RowKey              = $userName
        UserPrincipalName   = $upn
        LocalOrEntraOrAD    = $Source
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
        PartitionKey     = $groupId
        RowKey           = $resolvedGroupName
        LocalOrEntraOrAD = $Source
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
        [Parameter(Mandatory = $false)]
        [string]$GroupId,
        [Parameter(Mandatory = $false)]
        [string]$UserId,
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
    $resolvedComputerName = Get-RequiredTableValue -Value $ComputerName -PropertyName 'Computername' -MaximumLength 15
    $resolvedAdminGroupName = Get-RequiredTableValue -Value $AdminGroupName -PropertyName 'LocalAdminGroupName' -MaximumLength 128
    Assert-ValidTableKey -Value $computerId -PropertyName 'ComputerID'
    if (($EntraOrHybrid -lt 1) -or ($EntraOrHybrid -gt 3)) {
        throw 'EntraOrHybrid must be 1, 2, or 3.'
    }

    if ([string]::IsNullOrWhiteSpace($GroupId) -eq [string]::IsNullOrWhiteSpace($UserId)) {
        throw 'Exactly one of GroupID or UserID must be set.'
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
        Removed                             = $Removed
    }

    if (-not [string]::IsNullOrWhiteSpace($GroupId)) {
        $entity.GroupID = Get-RequiredTableValue -Value $GroupId -PropertyName 'GroupID' -MaximumLength 256
    } else {
        $entity.UserID = Get-RequiredTableValue -Value $UserId -PropertyName 'UserID' -MaximumLength 256
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

function Get-MainEntityIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Entity
    )

    if (-not [string]::IsNullOrWhiteSpace([string]$Entity.GroupID)) {
        return 'G|{0}' -f [string]$Entity.GroupID
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Entity.UserID)) {
        return 'U|{0}' -f [string]$Entity.UserID
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

        if ($identity.StartsWith('G|')) {
            $removedEntity.GroupID = [string]$existingEntity.GroupID
        } else {
            $removedEntity.UserID = [string]$existingEntity.UserID
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

    try {
        Invoke-RestMethod -Uri $entityUri -Method Put -Headers $headers -Body $jsonPayload -ErrorAction Stop | Out-Null
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        }

        if ($statusCode -eq 404) {
            throw "Azure table '$TableName' was not found. Create the table first or grant table create permission to the SAS token."
        }

        if ($statusCode -eq 403) {
            throw "Azure table '$TableName' rejected the upsert request with 403. The SAS token does not have the required add/update permissions for this table."
        }

        throw
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
        $null = Get-RequiredTableValue -Value ([string]$Entity.Computername) -PropertyName 'Computername' -MaximumLength 15
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

        $groupId = [string]$Entity.GroupID
        $userId = [string]$Entity.UserID
        if ([string]::IsNullOrWhiteSpace($groupId) -eq [string]::IsNullOrWhiteSpace($userId)) {
            throw 'Exactly one of GroupID or UserID must be set.'
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
    } elseif ($TableName -eq $AdminUserNames) {
        $null = Get-RequiredTableValue -Value $partitionKey -PropertyName 'UserID' -MaximumLength 256
        $null = Get-RequiredTableValue -Value $rowKey -PropertyName 'SamAccountName' -MaximumLength 20
        $null = Get-RequiredTableValue -Value ([string]$Entity.UserPrincipalName) -PropertyName 'UserPrincipalName' -MaximumLength 1024
        Assert-ValidSourceCode -Source ([string]$Entity.LocalOrEntraOrAD)
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
    $timestamp = [datetime]::UtcNow
    $existingMainEntities = @(Get-TablePartitionEntities -TableName $MainTable -PartitionKey $computerSid -Token $sanitizedSasToken)
    $localMembers = @(Get-LocalAdministratorsMembers -GroupPath $administratorsGroup.Path -JoinState $joinState)

    foreach ($member in $localMembers) {
        $isGroup = $member.Class -ieq 'Group'
        $displayName = $member.AccountName

        if ($isGroup) {
            $groupId = Add-AdminGroup -GroupName $displayName -Sid $member.Sid -Source $member.Source
            Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -GroupId $groupId

            $groupResolution = Resolve-DomainGroupMembers -GroupMember $member -JoinState $joinState -RetryCount $MaxRetries -RetryDelay $RetryDelaySeconds
            foreach ($resolvedMember in $groupResolution.ResolvedMembers) {
                if ($resolvedMember.Class -ieq 'group') {
                    $resolvedGroupId = Add-AdminGroup -GroupName $resolvedMember.AccountName -Sid $resolvedMember.Sid -Source $resolvedMember.Source
                    Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -GroupId $resolvedGroupId
                } else {
                    $resolvedUserId = Add-AdminUser -SamAccountName $resolvedMember.SamAccountName -UserPrincipalName $resolvedMember.UserPrincipalName -Sid $resolvedMember.Sid -Source $resolvedMember.Source
                    Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -UserId $resolvedUserId
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
        Add-MainTableRow -ComputerSid $computerSid -ComputerName $env:COMPUTERNAME -EntraOrHybrid $joinState.EntraOrHybrid -Timestamp $timestamp -AdminGroupName $administratorsGroup.Name -UserId $userId -LocalAccountCredentialChangedAt $userDetails.PasswordLastSet
    }

    Merge-MainEntitySnapshot -ExistingEntities $existingMainEntities -Timestamp $timestamp

    Write-EntitySet -TableName $AdminUserNames -Entities $script:UserEntities -Token $sanitizedSasToken
    Write-EntitySet -TableName $AdminGroups -Entities $script:GroupEntities -Token $sanitizedSasToken
    Write-EntitySet -TableName $MainTable -Entities $script:MainEntities -Token $sanitizedSasToken

    Write-Output ('COMPLIANT: Uploaded {0} main rows, {1} user rows, and {2} group rows.' -f $script:MainEntities.Count, $script:UserEntities.Count, $script:GroupEntities.Count)
    exit 0
} catch {
    Write-Output "ERROR: Remediation failed. $($_.Exception.Message)"
    exit 1
}