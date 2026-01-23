<#
This script is not done!
tracerpt "C:\ProgramData\USOShared\Logs\User\UpdateUx.ba5df953-91f0-4437-bc04-7d9703af9c7c.1.etl" -o C:\temp\sleep.xml -of XML 
or
tracerpt "C:\ProgramData\USOShared\Logs\User\UpdateUx.0aacc72c-1594-4376-8671-15f50419cf61.1.etl" -o C:\temp\sleep.xml -of XML -LR
#>
[xml]$import = Get-Content C:\temp\notification.xml -Raw
# ToDo: Sort by the timestamp of the events
function ConvertFrom-FileTimeToLocalDateTime {
    param (
        [Parameter(Mandatory = $true)]
        [long]$FileTime
    )
    return ((Get-Date 1/1/1601).AddDays($FileTime / 864000000000)).ToLocalTime()
}
#Create Initialize-Script function here
$NotificationEvents = $import.Events.Event
$EventsWithUpdateTitles = $NotificationEvents | Where-Object { $_.EventData.Data.Name -eq "UpdateTitle" }
$Script:Updates =  [System.Collections.ArrayList]::new()

#Put this foreach into a function
foreach ($UpdateInEvent in $EventsWithUpdateTitles) {
    $UpdateTitle = ($UpdateInEvent.EventData.Data | Where-Object{$_.name -eq "UpdateTitle"}).'#text'
    if($Script:Updates.title -notcontains $UpdateTitle) {
        #IDs seem to end with :1 or :200 etc - from the current log this might indicate optional vs required?
        #Split the GUID and the :number
        [string]$Type = ($UpdateInEvent.EventData.Data | Where-Object{$_.name -eq "UpdateId"}).'#text'.Split(":")[1]
        [string]$GUID = ($UpdateInEvent.EventData.Data | Where-Object{$_.name -eq "UpdateId"}).'#text'.Split(":")[0]
        $Script:Updates.Add([PSCustomObject]@{
            Title = $UpdateTitle
            Id    = $GUID
            Type  = $Type
        }) | Out-Null
    }
}
# Tie events together using the UpdateId should work.
<#
    The following event runs just after UpdateAttentionRequiredReason_NeedUserAgreementForPolicy
	<RenderingInfo Culture="de-DE">
		<Task>AvailableUpdatesCount</Task>
	</RenderingInfo>
    This event tells us how many updates are available - can't easily link to the updates though
    The following event runs just after the AvailableUpdatesCount
    <RenderingInfo Culture="de-DE">
		<Task>CompletedUpdatesCount</Task>
	</RenderingInfo>
    This event tells us how many updates are completed - can't easily link to the updates though

    The following will tell us generally which updates are available - not sure what "Seeker" means here, probably the update agent?
    <EventData>
		<Data Name="message">Seeker Updates Status</Data>
		<Data Name="numberOfSeekerFeatureUpdates">0</Data>
		<Data Name="numberOfSeekerQualityUpdates">0</Data>
		<Data Name="numberOfSeekerOthersUpdates">0</Data>
		<Data Name="numberOfSeekerDriverUpdates">2</Data>
		<Data Name="numberOfApprovedSeekerFeatureUpdates">       0</Data>
		<Data Name="numberOfApprovedSeekerQualityUpdates">       0</Data>
	</EventData>
#>
# What is SustainabilityMessageDisplayed ?
<#
	<RenderingInfo Culture="de-DE">
		<Task>Update progress</Task>
	</RenderingInfo>
    this has a
    <Data Name="Progress">       0</Data>
    and is using the UpdateId and should tell us about the installation progress of an update
#>
<# put this foreach into a function
TODO: Map UpdateStatus and AttentionRequiredReason codes to human readable text
	<EventData>
		<Data Name="UpdateId">ef55c4d3-2f7b-4b92-90ee-8f305ce02f35:200</Data>
		<Data Name="UpdateStatus">UpdateStatusInstallBlocked</Data>
		<Data Name="AttentionRequiredReason">UpdateAttentionRequiredReason_NeedUserAgreementForPolicy</Data>
	</EventData>

    More examples of UpdateStatus:
    	<EventData>
		<Data Name="UpdateId">ef55c4d3-2f7b-4b92-90ee-8f305ce02f35:200</Data>
		<Data Name="UpdateStatus">UpdateStatusInstalling</Data>
		<Data Name="AttentionRequiredReason">UpdateAttentionRequiredReason_None</Data>
	</EventData>
    #>
<#TODO UpdateApproved is hidden in 
	<RenderingInfo Culture="de-DE">
		<Task>UpdateApproved</Task>
	</RenderingInfo>
    but mentions the UpdateId so we can probably link them in one object using the timestamps
#>
$Script:Updates


<#$BootTime = ConvertFrom-FileTimeToLocalDateTime -FileTime $EventDataHashTable["BootTime"]
$StartTime = ConvertFrom-FileTimeToLocalDateTime -FileTime $EventDataHashTable["StartTime"]
$EndTime = ConvertFrom-FileTimeToLocalDateTime -FileTime $EventDataHashTable["EndTime"]
$UsoApiSplitJson = $EventDataHashTable["UsoApiSplitJson"] | ConvertFrom-Json
foreach ($EventData in $import.Events.Event) {
    $EventObject = [PSCustomObject]@{
        EventName = $EventData.EventData.Data.
        Type      = $EventData.Type
    }
}#>