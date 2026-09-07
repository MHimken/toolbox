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
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource dailyAggregates 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'PrimaryUserDaily'
}

resource workflowState 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'PrimaryUserState'
}

resource assignmentAudit 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'PrimaryUserAudit'
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

resource dailyAggregatesContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dailyAggregates.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: dailyAggregates
  properties: {
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource workflowStateContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workflowState.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: workflowState
  properties: {
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource assignmentAuditContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(assignmentAudit.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: assignmentAudit
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