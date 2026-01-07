<#
This script is not done!
tracerpt "C:\ProgramData\USOShared\Logs\User\UpdateUx.ba5df953-91f0-4437-bc04-7d9703af9c7c.1.etl" -o C:\temp\sleep.xml -of XML 
or
tracerpt "C:\ProgramData\USOShared\Logs\User\UpdateUx.0aacc72c-1594-4376-8671-15f50419cf61.1.etl" -o C:\temp\sleep.xml -of XML -LR
#>
[xml]$import = Get-Content C:\temp\sleep.xml -Raw
foreach ($EventData in $import.Events.Event) {
    $EventObject = [PSCustomObject]@{
        EventName = $EventData.EventData.Data.
        Type      = $EventData.Type
    }
}