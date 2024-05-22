if ($null -eq $($MgContext)) {
    Connect-MgGraph -TenantId '<TENANTID>' -Scopes DeviceManagementServiceConfig.ReadWrite.All,DeviceManagementConfiguration.ReadWrite.All
}
$GroupTag = 'Windows | AP default'
$graphApiVersion = 'beta'
$Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
$APDevices = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/$graphApiVersion/$Resource/" -Method GET
$body = "{
    `"groupTag`":`"$GroupTag`"
    }"
ForEach($Device in $APDevices.value){
    Invoke-MgGraphRequest -ContentType "application/json" -Uri "https://graph.microsoft.com/$graphApiVersion/$Resource/$($Device.id)/UpdateDeviceProperties" -Method POST -Body $body -OutputType PSObject
}
