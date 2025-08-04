# Add primary user info to device

## What does this runbook do?

This runbook automatically adds information from the primary user to the Entra device using its extension attributes. It will also add information from the matching Intune device if it is enrolled. As far as I know, the idea comes from Adam Gross. I just wanted to automate the process so that it could be run regularly.

## What do I need to do?

You need a global admin to set up the correct graph rights (as that can't be delegated at the time of writing). Those rights need to be added to the service principal an automation account.

Required scopes: Device.ReadWrite.All, User.Read.All, DeviceManagementManagedDevices.Read.All
