<#
.SYNOPSIS
Randomize the computername and reboot. This script is not done yet!
.DESCRIPTION
Randomize the computername and reboot - keep in mind, that this was tested on an Entra-Joined device.
####################################################
DO NOT TRY THIS ON AN ACTIVE DIRECTORY JOINED DEVICE
####################################################
.PARAMETER CurseLevel
Use an int to describe how cursed you want your computer name to be. 1 and 2 will avoid any explictely forbidden characters or names
1 Takes a part of a GUID for the new name - very tame
2 Will use random strings and letters - very tame
#########
I can't guarantee what will break if you use these!
#########
666 These are very cursed, but they don't seem to break anything (yet)
999 These will definitely break things. I don't recommend you use these ever.
.NOTES
Initial Creation date: 30.11.24
Last Update: 10.12.24
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
function New-RandomString{

    [char](Get-SecureRandom -Minimum 1 -Maximum 1250)
}
function New-ComputerNameObject {
    param(
        $Level
    )
    switch ($Level) {
        "1" { $Script:NewComputerName = (New-Guid).Guid.Substring(0, $MaximumLength) }
        "2" {$Script:NewComputerName = New-RandomString}
        "666" {$Script:NewComputerName =$Script:CursedNames[(Get-SecureRandom -Minimum 0 -Maximum $Script:CursedNames.count)]}#Create Emojis + hard to type stuff to hammer the point down
        "999" {$Script:NewComputerName = $Script:DoNotUse[(Get-SecureRandom -Minimum 0 -Maximum $Script:DoNotUse.count)]}#Use an explicitely disallowed/cursed name
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