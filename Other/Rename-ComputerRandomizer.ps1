<#
.SYNOPSIS
Randomize the computername and reboot. This script is not done yet!
.DESCRIPTION
Randomize the computername and reboot - keep in mind, that this was tested on an Entra-Joined device.
####################################################
DO NOT TRY THIS ON AN ACTIVE DIRECTORY JOINED DEVICE
####################################################
.PARAMETER CurseLevel
Use an int to describe how curse you 

.NOTES
Initial Creation date: 30.11.24
Last Update: 05.12.24
Version: 1.0
#>
[CmdletBinding()]
param(
    $CurseLevel
)
#Rules of the game
#https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/naming-conventions-for-computer-domain-site-ou#computer-names
#Disallowed names are _suggestions_ - you can absolutely name your computer "BATCH"
$Script:DisallowedNames = @("ANONYMOUS", "BATCH", "BUILTIN", "DIALUP", "DOMAIN", "ENTERPRISE", "INTERACTIVE", "INTERNET", "LOCAL", "NETWORK", "NULL", "PROXY", "RESTRICTED", "SELF", "SERVER", "SERVICE", "SYSTEM", "USERS", "WORLD")
#While not state explictily a " " (whitespace) or "." (dot) or $ (dollar) aren't allowed either
$Script:DisallowedCharacters = @("\", "/", ":", "*", "?", "`"", "<", ">", "|", " ", ".", "$")
#WARNING: I can't guarantee what these will do - I DID test them very briefly
$Script:CursedNames = @("INTERACTIVE", "SELF", "SYSTEM", "LOCALHOST", "PRINTER", "NUL", "CON", "PRN", "AUX", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "💩")
$Script:DoNotUse = @("AzureAD", "BUILTIN")
$MaximumLength = 15
function New-ComputerNameObject {
    param(
        $Level
    )
    switch ($Level) {
        "1" { $Script:NewComputerName = (New-Guid).Guid.Substring(0, 15) }
        "2" {$Script:NewComputerName = Get-SecureRandom -Minimum 1 -Maximum 15 -Shuffle}
        "666" {}#Create Emojis + hard to type stuff to hammer the point down
        "999" {}#Use an explicitely disallowed/cursed name
        Default { $Script:NewComputerName = (New-Guid).Guid.Substring(0, 15) }
    }

}

function Confirm-ComputerNameIsValid {
    param(
        $ComputerName
    )
    $IsNumbersOnly = [int]::TryParse($Script:NewComputerName, [ref]$null)
}

New-ComputerNameObject -Level $CurseLevel
if (Confirm-ComputerNameIsValid) {
    Rename-Computer -NewName ($Script:NewComputerName) -Restart -Force
} else {}