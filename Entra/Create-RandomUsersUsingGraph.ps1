<#
.SYNOPSIS
    This script creates a lot of new random users in Entra using Graph API
.DESCRIPTION
    This script creates a specified number of random users in Entra using the Microsoft Graph API.
.PARAMETER NumberOfUsers
    The number of random users to create.
.NOTES
    Version: 1.0
    Versionname: Create-RandomUsersUsingGraph
    Initial creation date: 29.07.2025
    Last change date: 04.08.2025
    Latest changes: Initial Version
    Author: Martin Himken
#>
param (
    [int]$NumberOfUsers = 1000, # Default is 100 users
    [string]$UPN = "intune.best", # Replace with your actual domain
    [string]$WorkingDirectory = "C:\Temp\RandomUserGenerator",#ToDo: Change the default!
    [string]$LogDirectory = "C:\Temp\RandomUserGenerator\Logs",#ToDo: Change the default!
    [string]$LogPrefix = "RUUG", # Random User User Generator
    [string]$CertificateThumbprint = "",
    [string]$ClientID = "",
    [string]$TenantId = "",
    [string]$TenantAPIToUse = "/beta", # Change to /v1.0 if you want to use the stable API version
    [boolean]$CreateMode = $false, # Set to $false if you want to delete users instead of creating them
    [boolean]$DeleteMode = $true # Set to $true if you want to delete users
)
$ThrottleLimit = 10 # DO NOT INCREASE unless you know what you are doing! This is the maximum number of concurrent batch requests.
if (-not(Get-MgContext)) {
    Connect-MgGraph -CertificateThumbprint $CertificateThumbprint -ClientId $ClientID -TenantId $TenantId 
    if (-not(Get-MgContext)) {
        exit
    } else {
        Write-Log -Message "Successfully connected to Microsoft Graph." -Component 'RUUG'
    }
}
function Get-ScriptPath {
    <#
    .SYNOPSIS
    Get the current script path.
    #>
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
    <#
    .SYNOPSIS
    Will initialize most of the required variables throughout this script.
    #>
    $Script:DateTime = Get-Date -Format yyyyMMdd_HHmmss
    if (-not($Script:CurrentLocation)) {
        $Script:CurrentLocation = Get-Location
    }
    if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null } 
    if ((Get-Location).path -ne $WorkingDirectory) {
        Set-Location $WorkingDirectory
    }
    Get-ScriptPath
    if (-not($Script:LogFile)) {
        if (-not($LogPrefix)) {
            $Script:LogPrefix = 'RUUG'#Random User User Generator
        } else {
            $Script:LogPrefix = $LogPrefix
        }
        $Script:LogFile = Join-Path -Path $Script:LogDirectory -ChildPath ('{0}_{1}.log' -f $Script:LogPrefix, $Script:DateTime)
        if (-not(Test-Path $Script:LogDirectory)) { New-Item $Script:LogDirectory -ItemType Directory -Force | Out-Null }
    }
    #Make sure not jobs from the last run are still running
    Get-Job -Name "$($Script:LogPrefix)-*" | Remove-Job -Force
    #Initialize variables
    $Script:Users = [System.Collections.ArrayList]::new()
    $Script:NameDatabase = Invoke-RestMethod "https://random-word-api.herokuapp.com/word?number=5000&length=8&lang=de"
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    #$Script:BatchRequestsAnalyze = [System.Collections.ArrayList]::new()
    $Script:BatchRequests = [System.Collections.ArrayList]::new()
    #$Script:BatchRetryRequests = [System.Collections.ArrayList]::new()
    if ($DeleteMode) {
        $Script:UsersToDelete = [System.Collections.ArrayList]::new()
    }
}
function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to the log file and optionally to the console.
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
        [ValidateSet('1', '2', '3')][int]$Type,
        [Switch]$Finish,
        [Switch]$ToConsole
    )
    if ($null -eq $Script:LogMessageBuffer) {
        $Script:LogMessageBuffer = [System.Collections.ArrayList]::new()
    }
    if (-not($NoLog)) {
        $Time = Get-Date -Format 'HH:mm:ss.ffffff'
        $Date = Get-Date -Format 'MM-dd-yyyy'
        if (-not($Component)) { $Component = 'Runner' }
        if (-not($ToConsole)) {
            if ($Message) {
                $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
                $Script:LogMessageBuffer.Add($LogMessage) | Out-Null
            }
            if ($Script:LogMessageBuffer.count -ge 10 -or $Finish) {
                $Script:LogMessageBuffer | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
                $Script:LogMessageBuffer.Clear() | Out-Null
            }
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
function New-Password {
    <#
    .SYNOPSIS
    Generates a random password.
    #>
    $length = 20
    $RandomString = -join (((65..90) + (97..122) + (48..57) + 33 + (35..47) + (58..64) + (91..95) + (123..126)) | Get-Random -Count $length | ForEach-Object { [char]$_ })
    return $RandomString
}
function New-UserList {
    <#
    .SYNOPSIS
        Creates a list of random users.
    #>
    for ($i = 0; $i -lt $NumberOfUsers; $i++) {
        $FirstName = $Script:NameDatabase | Get-Random | ForEach-Object{if($_ -match '[äöü]'){$_ -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue'}else{$_}}
        $LastName = $Script:NameDatabase | Get-Random | ForEach-Object{if($_ -match '[äöü]'){$_ -replace 'ä', 'ae' -replace 'ö', 'oe' -replace 'ü', 'ue'}else{$_}}
        $UserPrincipalName = "$($FirstName.ToLower()).$($LastName.ToLower())@$UPN"
        $RandomUser = [PSCustomObject]@{
            accountEnabled    = $true
            displayName       = "$FirstName $LastName"
            mailNickname      = "$($FirstName.ToLower())$($LastName.ToLower())"
            userPrincipalName = $UserPrincipalName
            passwordProfile   = @{
                forceChangePasswordNextSignIn = "false"
                password                      = New-Password
            }
            officeLocation    = "RandomOffice$i"
        }
        $Script:Users.Add($RandomUser) | Out-Null
    }
}
function Get-nextLinkData {
    param(
        $OriginalObject
    )
    $nextLink = $OriginalObject.'@odata.nextLink'
    $Results = $OriginalObject
    while ($nextLink) {
        $Request = Invoke-MgGraphRequest -Uri $nextLink
        $Results.value += $Request.value
        $nextLink = ''
        $nextLink = $Request.'@odata.nextLink'
    }
    return $Results
}
function Search-UsersToDelete {
    <#
    .SYNOPSIS
        Searches for users to delete based on a specific criteria.
    #>
    $Headers = @{
        'ConsistencyLevel' = 'eventual'
    }
    $Script:UsersToDelete = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/?`$count=true&`$select=id&`$filter=startswith(officeLocation,'RandomOffice')" -Headers $Headers -ErrorAction Stop
    if ($Script:UsersToDelete.'@odata.nextLink') {
        $Script:UsersToDelete = Get-nextLinkData -OriginalObject $Script:UsersToDelete
    }
}
function Add-BatchRequestObjectToQueue {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body
    )
    $ID = $Script:BatchRequests.count
    $BatchObject = [PSCustomObject]@{
        id      = $ID
        method  = $Method
        URL     = $URL
        headers = $Headers
    }
    if ($Body) {
        #A body is only required for POST, PATCH, and PUT requests
        $BatchObject | Add-Member -MemberType NoteProperty -Name 'body' -Value $null -Force
        $BatchObject.body = $Body
    }
    $Script:BatchRequests.add($BatchObject) | Out-Null
}
function Invoke-BatchRequest {
    param(
        [string]$Method,
        [string]$URL,
        $Headers,
        $Body,
        [switch]$Finalize
    )
    if ($Method -and $URL) {
        Add-BatchRequestObjectToQueue -Method $method -URL $URL -Headers $Headers -Body $Body
    }
    if ($Script:BatchRequests.count -eq 20 -or $Finalize) {
        $BatchRequestBody = [PSCustomObject]@{ requests = $Script:BatchRequests }
        $JSONRequests = $BatchRequestBody | ConvertTo-Json -Depth 10
        #$Results = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $JSONRequests -ContentType 'application/json' -ErrorAction Stop
        $PrepareJob = [PSCustomObject]@{
            ID                = $Script:BatchRequestsQueue.Count
            Name              = "BatchRequest-$($Script:BatchRequestsQueue.Count)"
            ArgumentToProvide = @($JSONRequests)
        }
        $Script:BatchRequestsQueue.Add($PrepareJob) | Out-Null
        $Script:BatchRequests = [System.Collections.ArrayList]::new()
    }
    return $Results
}
function Write-CreateUserBatchRequests {
    <#
    .SYNOPSIS
        Writes the batch requests to the queue.
    #>
    foreach ($User in $Script:Users) {
        $Method = 'POST'
        $URL = "/users/"
        $Headers = @{
            'Content-Type' = 'application/json'
        }
        $Body = $User
        Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers -Body $Body
    }
    if ($Script:BatchRequests.count -gt 0) {
        Invoke-BatchRequest -Finalize
    }
}
function Write-DeleteUserBatchRequests {
    <#
    .SYNOPSIS
        Writes the batch requests to delete users to the queue.
    #>
    foreach ($User in $Script:UsersToDelete.value) {
        $Method = 'DELETE'
        $URL = "/users/$($User.id)"
        $Headers = @{
            'Content-Type' = 'application/json'
        }
        Invoke-BatchRequest -Method $Method -URL $URL -Headers $Headers
    }
    if ($Script:BatchRequests.count -gt 0) {
        Invoke-BatchRequest -Finalize
    }
}
function Submit-BatchRequests {
    <#
    .SYNOPSIS
        Processes the batch requests in the queue.
    #>
    foreach ($BatchRequest in $Script:BatchRequestsQueue) {
        Start-ThreadJob -Name "$($Script:LogPrefix)-$($BatchRequest.Name)" -ThrottleLimit $ThrottleLimit -ScriptBlock {
            param($ArgumentToProvide, $TenantAPIToUse)
            #Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500) # Random delay to avoid throttling
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com$TenantAPIToUse/`$batch" -Body $ArgumentToProvide -ContentType 'application/json' -ErrorAction Stop
        } -ArgumentList $BatchRequest.ArgumentToProvide, $TenantAPIToUse | Out-Null
    }
    Write-Log -Message "Batch requests submitted." -Component 'SubmitBatch'
}
function Confirm-BatchRequests {
    <#
    .SYNOPSIS
        Confirms the batch requests and processes the results.
    #>
    Write-Log -Message "Analyzing batch requests..." -Component 'ConfirmBatch'
    #Save the current batch requests to retry them later if needed
    $Script:RetryRequests = $Script:BatchRequestsQueue | ForEach-Object{$_}
    #Clear the current batch requests queue to prepare for the retry batch
    $Script:BatchRequestsQueue = [System.Collections.ArrayList]::new()
    #Get the wait time from the batch requests if any requests were throttled
    $Script:MinimumWaitTimeFromBatchRequests = 0
    $Jobs = Get-Job | Where-Object { $_.name -like "$($Script:LogPrefix)-BatchRequest-*" }
    foreach ($Job in $Jobs) {
        $BatchID = $Job.Name -replace "$($Script:LogPrefix)-BatchRequest-", ''
        $Job.Output.responses | ForEach-Object {
            $RetryRequestFullJSON = ConvertFrom-Json -InputObject ([string]$Script:RetryRequests[$BatchID].ArgumentToProvide) -AsHashtable
            $SingleRetryRequest = $RetryRequestFullJSON.requests[$_.id]
            $UserName = if ($SingleRetryRequest.body.displayName) { $SingleRetryRequest.body.displayName } else { "N/A" }
            if ($_.status -eq 200 -or $_.status -eq 201 -or $_.status -eq 204) {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID completed successfully." -Component 'ConfirmBatch'
            } elseif ($_.status -eq 429) {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID was throttled." -Component 'ConfirmBatch' -Type 2
                if ($_.headers.'Retry-After') {
                    $RetryAfter = [int]$_.headers.'Retry-After'
                    if ($RetryAfter -gt $Script:MinimumWaitTimeFromBatchRequests) {
                        $Script:MinimumWaitTimeFromBatchRequests = $RetryAfter
                    }
                }
                #ToDo: This is a problem, because creating is different from deleting users and we might be missing information the second time
                # Maybe we need to create a queue for each retry batch?
                # Instead use Write-CreateUserBatchRequests and Write-DeleteUserBatchRequests to feed the queue!
                Invoke-BatchRequest -Method $SingleRetryRequest.method -URL $SingleRetryRequest.URL -Headers $SingleRetryRequest.headers -Body $SingleRetryRequest.body
            } else {
                Write-Log -Message "Request $($_.id) for $UserName in batch $BatchID failed with status $($_.status) and provided the following error:`n $($_.body.error.message)" -Component 'ConfirmBatch' -Type 3
            }
            Clear-Variable -Name SingleRetryRequest,RetryRequestFullJSON -ErrorAction SilentlyContinue
        }
        Remove-Job -Id $Job.Id -Force
    }
}
#Start coding!
Initialize-Script
Write-Log -Message "Welcome to RUUG the random user generator!" -Component 'RUUG' -Finish #Finish here will generate the log file
if ($CreateMode) {
    New-UserList
    Write-CreateUserBatchRequests
}
if ($DeleteMode) {
    Write-Log -Message "Searching for users to delete..." -Component 'RUUG'
    Write-Log -Message "Keep in mind that with deletions the batch responses will not contain user information." -Component 'RUUG'
    Search-UsersToDelete
    if($Script:UsersToDelete){
        Write-Log -Message "Found $($Script:UsersToDelete.value.Count) users to delete." -Component 'RUUG' -Finish
        Write-DeleteUserBatchRequests
    }
}
    
Submit-BatchRequests
while ((Get-Job | Where-Object { $_.name -like "$($Script:LogPrefix)-BatchRequest-*" }).state -ne 'Completed') {
    Start-Sleep -Seconds 1
}
Write-Log -Message "All batch requests have been submitted and processed." -Component 'RUUG'
Do {
    Confirm-BatchRequests
    if ($Script:BatchRequestsQueue.Count -eq 0) {
        Write-Log -Message "No more batch requests to process." -Component 'RUUG'
        break
    }
    Write-Log -message "Some requests were throttled and need to be retried." -Component 'RUUG' -Type 2
    Write-Log -Message "Waiting for $($Script:MinimumWaitTimeFromBatchRequests) seconds before processing the next batch requests." -Component 'RUUG' -Finish
    Start-Sleep -Seconds $Script:MinimumWaitTimeFromBatchRequests
    Write-Log -Message 'Processing '
    Submit-BatchRequests
} while ($Script:BatchRequestsQueue.Count -gt 0)

#Finalize the script
Write-Log -Message "Thank you for using this script!" -Component 'RUUG'
Get-Job | Remove-Job -Force
if ($Script:LogMessageBuffer) {
    $Script:LogMessageBuffer | Out-File -Append -Encoding UTF8 -FilePath $Script:LogFile
    $Script:LogMessageBuffer.Clear() | Out-Null
}
Set-Location $Script:CurrentLocation
#Disconnect-MgGraph