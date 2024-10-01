param(
    $TargetPath ="HKCU:\Software\Microsoft\Global Secure Access Client"
)
function CreateIfNotExists
{
    param($Path)
    if (-NOT (Test-Path $Path))
    {
        New-Item -Path $Path -Force | Out-Null
    }
}
CreateIfNotExists $TargetPath
Set-ItemProperty -Path $TargetPath -Name "HideSignOutButton" -Type DWord -Value "0x0"
Set-ItemProperty -Path $TargetPath -Name "HideDisablePrivateAccessButton" -Type DWord -Value "0x0"