<#
.SYNOPSIS
    This script retrieves the current geographical location of the user and sets the system timezone accordingly.
.DESCRIPTION
    The script uses the GeoCoordinateWatcher class to obtain the user's current latitude and longitude.
    It then calls the Azure Maps API to get the timezone information for those coordinates and sets the system timezone.
#>
$SubscriptionKey = "YOURKEYHERE"
Add-Type -AssemblyName System.Device 
$GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher 
$GeoWatcher.Start()
while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
    Start-Sleep -Milliseconds 100 
}  
if ($GeoWatcher.Permission -eq 'Denied'){
    #Write-Error 'Access Denied for Location Information' #Fail silently!
} else {
    $LocationCoordinates = $GeoWatcher.Position.Location | Select-Object Latitude,Longitude
}
$GeoWatcher.Stop() 
$TimeZones = (ConvertFrom-Json (Invoke-WebRequest -Uri "https://atlas.microsoft.com/timezone/byCoordinates/json?subscription-key=$($SubscriptionKey)&api-version=1.0&options=all&query=$([Math]::Floor($LocationCoordinates.Latitude)),$([Math]::Floor($LocationCoordinates.Longitude))").content).timezones
Set-Timezone $TimeZones.names.Standard