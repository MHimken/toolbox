# Runbook

## Add-InfoToEntraDeviceExtensions

### Purpose of Add-InfoToEntraDeviceExtensions

This runbook automatically adds information from the primary user to the Entra device using its extension attributes. It will also add information from the matching Intune device if it is enrolled. As far as I'm aware, the idea comes from Adam Gross. I just wanted to automate the process so that it could be run regularly.

### What do I need to do to make Add-InfoToEntraDeviceExtensions work?

You need a global admin to set up the correct graph rights (as that can't be delegated at the time of writing). Those rights need to be added to the service principal an automation account. You also need to set up a "Managed Identity" - I [used this blog](https://thesysadminchannel.com/graph-api-using-a-managed-identity-in-an-automation-runbook/) by Paul Contreras to do that.

Required scopes: Device.ReadWrite.All ,  DeviceManagementManagedDevices.Read.All , User.Read.All , GroupMember.Read.All , Group.Read.All

## Add-ExcludeTagToEntraDeviceFromGroup

### Purpose of Add-ExcludeTagToEntraDeviceFromGroup

This runbook automatically adds an "Exclude" tag to Entra devices that are members of a specific group. This is useful for excluding devices from certain policies or configurations in Intune.

### What do I need to do to make Add-ExcludeTagToEntraDeviceFromGroup work?

You need a global admin to set up the correct graph rights (as that can't be delegated at the time of writing). Those rights need to be added to the service principal an automation account. You also need to set up a "Managed Identity" - I [used this blog](https://thesysadminchannel.com/graph-api-using-a-managed-identity-in-an-automation-runbook/) by Paul Contreras to do that.

Required scopes: Device.ReadWrite.All, GroupMember.Read.All, Group.Read.All
