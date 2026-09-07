targetScope = 'resourceGroup'

@description('Azure region used for all resources.')
param location string = resourceGroup().location

@description('Globally unique Storage account name.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Azure Automation account name.')
@minLength(6)
@maxLength(50)
param automationAccountName string

@description('Origins allowed to query Azure Table Storage from the live HTML report. Leave empty to disable CORS.')
param allowedCorsOrigins array = []

@description('Tags applied to resources that support tags.')
param tags object = {}

var storageTableDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: true
    defaultToOAuthAuthentication: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    cors: {
      corsRules: empty(allowedCorsOrigins) ? [] : [
        {
          allowedHeaders: [
            'x-ms-version'
          ]
          allowedMethods: [
            'GET'
          ]
          allowedOrigins: allowedCorsOrigins
          exposedHeaders: [
            'x-ms-continuation-NextPartitionKey'
            'x-ms-continuation-NextRowKey'
          ]
          maxAgeInSeconds: 3600
        }
      ]
    }
  }
}

// Endpoint SAS access is used for this table. The reconciliation identity has no access to device snapshots.
resource localAdminCollection 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'LocalAdminCollection'
}

resource adminUserNames 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'AdminUserNames'
}

resource adminGroups 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'AdminGroups'
}

resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: automationAccountName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    disableLocalAuth: true
    publicNetworkAccess: true
    sku: {
      name: 'Basic'
    }
  }
}

resource userLookupContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(adminUserNames.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: adminUserNames
  properties: {
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource groupLookupContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(adminGroups.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: adminGroups
  properties: {
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

output automationAccountName string = automationAccount.name
output automationManagedIdentityPrincipalId string = automationAccount.identity.principalId
output storageAccountName string = storageAccount.name
output tableEndpoint string = storageAccount.properties.primaryEndpoints.table
