<#
.SYNOPSIS
    This script sets the user's default background wallpaper.
.DESCRIPTION
    This script either downloads a wallpaper from a specified URL to the specified working directory, or uses a local file, and then sets it as the desktop background.
.PARAMETER WallpaperPath
    Provide the URL or local path to the wallpaper image. If a URL is provided, the script will first download the image to a specified directory before setting it as the wallpaper.
    "$($WorkingDir.FullName)\windows-server-2025-3840x2400-15385.jpg"
    "https://somedomain.com/images/wallpapers/windows-server-2025-3840x2400-15385.jpg"
    If you use a URL, you need to specify a file type at the end of the URL. Otherwise, specify a supported file type in the 'SupportedFileType' parameter.
    If you specify a local file, it will be used immediately, bypassing the download to the working directory.
.PARAMETER WorkingDir
    This is the directory where the wallpaper image will be downloaded if a URL is provided. If the directory does not exist, it will be created.
.PARAMETER SupportedFiletype
    If the wallpaper URL does not end in a supported file type, an error will be generated. If your URL does not contain a supported file type, please specify the file type here. 
    Ensure that it matches the file types specified in $FileTypes.
.EXAMPLE
    Set-BackgroundWallpaperAsUser.ps1 -WallpaperPath "https://somedomain.com/images/wallpapers/windows-server-2025-3840x2400-15385.jpg" -SupportedFiletype ".jpg"
    This example demonstrates how to set the wallpaper to a specified image URL and download it.
.EXAMPLE
    Set-BackgroundWallpaperAsUser.ps1 -WallpaperPath "C:\Users\Public\Pictures\wallpaper.jpg"
    This example demonstrates how to set a wallpaper from a local file without downloading it.
.NOTES
    Run this script in **USER MODE**
    This script is Johannes approved and tested for Windows.
    Version: 1.0
    Versionname: Initial 
    Intial creation date: 18.07.2025
    Last change date: 18.07.2025
#>
[CmdletBinding()]
param(
    [String]$WallpaperPath = "https://SOMEDOMAIN.com/images/wallpapers/windows-server-2025-3840x2400-15385.jpg",
    [System.IO.DirectoryInfo]$WorkingDir = "C:\ProgramData\Wallpaper",
    [String]$SupportedFiletype
)
if (-not(Test-Path $WorkingDir )) { 
    New-Item $WorkingDir -ItemType Directory -Force | Out-Null 
    $WorkingDirACL = Get-Acl $WorkingDir
    $SIDToConvert = New-Object System.Security.Principal.SecurityIdentifier ("S-1-5-11")
    $ConvertedSIDName = $SIDToConvert.Translate( [System.Security.Principal.NTAccount])
    $Name = $ConvertedSIDName.Value
    $InheritanceFlag = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $NewAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ("$Name","FullControl",$InheritanceFlag,$PropagationFlag,"Allow")
    $WorkingDirACL.SetAccessRule($NewAccessRule)
    Set-Acl -Path $WorkingDir -AclObject $WorkingDirACL
}

if ($WorkingDir -and (Test-Path $WorkingDir)) {
    $CurrentDir = Get-Location
    Set-Location $WorkingDir
}
if ($WallpaperPath) {
    Remove-Item -Path $WallpaperPath -Force -ErrorAction SilentlyContinue
    Write-Information "Removed old wallpaper file if it existed: $WallpaperPath"
}
$FileTypes = ".jpg", ".jpeg", ".bmp", ".dib", ".png", ".jfif", ".jpe", ".gif", ".tif", ".tiff", ".wdp", ".heic", ".heif", ".heics", ".heifs", ".hif", ".avci", ".avcs", ".avif", ".avifs", ".jxr", ".jxl" 

#Start coding!
if ($WallpaperPath -match "https://") {
    if (-not($SupportedFiletype)) {
        $SupportedFiletype = $FileTypes | ForEach-Object { If ($WallpaperPath -match $_ ) { $_ } }
    } 
    if ($SupportedFiletype) {
        Write-Information "Online wallpaper detected - downloading file"
        $WallpaperPathDownload = $($WorkingDir.FullName + "\Wallpaper$SupportedFiletype")
        if (Test-Path $WallpaperPathDownload) {
            Write-Information "Removing old wallpaper file: $WallpaperPathDownload"
            Try {
                Remove-Item -Path $WallpaperPathDownload -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Error "Failed to remove old wallpaper file: $WallpaperPathDownload"
            }
        } else {
            Write-Information "No old wallpaper file found to remove: $WallpaperPathDownload"
        }
        Try {
            Invoke-WebRequest -Uri $WallpaperPath -OutFile $WallpaperPathDownload -ErrorAction Stop
            Write-Information "Downloaded wallpaper to: $WallpaperPathDownload"
        } catch {
            Write-Error "Failed to download wallpaper from URL: $WallpaperPath. Error: $($_.Exception.Message)"
            Write-Information "Using default Windows wallpaper instead."
            $WallpaperPathDownload = "C:\Windows\Web\Wallpaper\Windows\img0.jpg" #Default Windows wallpaper
        }
        $WallpaperPath = $WallpaperPathDownload
    }
}

# Verify file exists
if ($WallpaperPath -and (Test-Path $WallpaperPath)) {
    Write-Information "File verified"
} else {
    #Try getting any supported picture type from the current folder - will selected newest file if multiple exist
    $PotentialFiles = Get-ChildItem | Where-Object { $_.Extension -in $FileTypes } | Sort-Object -Property LastWriteTime -Descending
    if (-not($PotentialFiles)) {
        Write-Error "The specified wallpaper file was not found: $WallpaperPath"
        Exit 1
    }
    $WallpaperPath = $PotentialFiles[0].FullName
}
[System.IO.FileInfo]$WallpaperPath = $WallpaperPath
# Set background via COM object, which is esentially the same as if the user would do it. 
Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
 
public class Wallpaper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
 
$SPI_SETDESKWALLPAPER = 20
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDWININICHANGE = 0x02
 
[Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $($WallpaperPath.FullName), $SPIF_UPDATEINIFILE -bor $SPIF_SENDWININICHANGE) | Out-Null

Write-Output "Default background wallpaper successfully set."
Set-Location $CurrentDir