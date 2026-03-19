$Adapters = Get-NetAdapter | Get-NetAdapterPowerManagement | Where-Object { $null -ne $_.AllowComputerToTurnOffDevice -and $_.AllowComputerToTurnOffDevice -ne 'Unsupported' -and $_.AllowComputerToTurnOffDevice -ne 'Disabled' }

If ($Adapters) {
    # There should only be one, but looping just in case.
    try {
        foreach ($Adapter in $Adapters) {
            $Adapter.AllowComputerToTurnOffDevice = 'Disabled'
            $Adapter | Set-NetAdapterPowerManagement
        }
    } catch {
        Write-Output "An error occurred while trying to disable power management for the network adapter(s). Please review the error message below and try again."
        Write-Output $_.Exception.Message
    }
}