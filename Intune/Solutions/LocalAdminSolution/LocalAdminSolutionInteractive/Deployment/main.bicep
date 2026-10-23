targetScope = 'resourceGroup'

@description('Azure region used for all resources.')
param location string = resourceGroup().location

@description('Globally unique Storage account name.')
@minLength(3)
@maxLength(24)
param storageAccountName string

@description('Globally unique Storage account name dedicated to governance tables.')
@minLength(3)
@maxLength(24)
param governanceStorageAccountName string

@description('Azure Automation account name.')
@minLength(6)
@maxLength(50)
param automationAccountName string

@description('Origins allowed to query Azure Table Storage from the live HTML report. Leave empty to disable CORS.')
param allowedCorsOrigins array = []

@description('Deploy the Azure Functions BFF and its supporting resources.')
param deployBff bool = false

@description('Globally unique Azure Function App name. Required when deployBff is true.')
param functionAppName string = ''

@description('Function Consumption plan name. Defaults to <functionAppName>-plan when empty.')
param functionPlanName string = ''

@description('Application Insights name. Defaults to <functionAppName>-ai when empty.')
param applicationInsightsName string = ''

@description('Globally unique Storage account used by the Azure Functions host. Required when deployBff is true.')
param functionStorageAccountName string = ''

@description('Microsoft Entra tenant accepted by the BFF.')
param tenantId string = ''

@description('Microsoft Entra API application client ID accepted as the BFF token audience.')
param apiClientId string = ''

@description('Microsoft Entra SPA application client ID allowed to call the BFF.')
param spaClientId string = ''

@description('Origins allowed to call the BFF. Use exact HTTPS origins where possible.')
param bffAllowedOrigins array = []

@description('Conditional Access authentication context ID required by BFF Admin mode.')
param adminAuthContextId string = 'c1'

@description('Maximum Admin-mode lifetime in minutes after the step-up sign-in.')
@minValue(5)
@maxValue(240)
param adminSessionMaxMinutes int = 30

@description('Tags applied to resources that support tags.')
param tags object = {}

var storageTableDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)
var storageBlobDataReaderRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
)
var resolvedFunctionPlanName = empty(functionPlanName) ? '${functionAppName}-plan' : functionPlanName
var resolvedApplicationInsightsName = empty(applicationInsightsName) ? '${functionAppName}-ai' : applicationInsightsName

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

resource governanceStorageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: governanceStorageAccountName
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

resource governanceTableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: governanceStorageAccount
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

// Endpoint SAS access is used for inventory tables. Governance data is isolated in a separate account.
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

resource localAdminDevices 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'LocalAdminDevices'
}

resource localAdminAllowRules 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: governanceTableService
  name: 'LocalAdminAllowRules'
}

resource localAdminUserSettings 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: governanceTableService
  name: 'LocalAdminUserSettings'
}

resource localAdminReviewActions 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: governanceTableService
  name: 'LocalAdminReviewActions'
}

resource localAdminAuditRecords 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: governanceTableService
  name: 'LocalAdminAuditRecords'
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

resource deviceRegistryContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(localAdminDevices.id, automationAccount.id, storageTableDataContributorRoleDefinitionId)
  scope: localAdminDevices
  properties: {
    principalId: automationAccount.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource functionStorageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = if (deployBff) {
  name: functionStorageAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource functionBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = if (deployBff) {
  parent: functionStorageAccount
  name: 'default'
}

resource functionPackageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (deployBff) {
  parent: functionBlobService
  name: 'function-packages'
  properties: {
    publicAccess: 'None'
  }
}

resource functionPlan 'Microsoft.Web/serverfarms@2023-12-01' = if (deployBff) {
  name: resolvedFunctionPlanName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = if (deployBff) {
  name: resolvedApplicationInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    IngestionMode: 'ApplicationInsights'
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = if (deployBff) {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: functionPlan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    reserved: true
    siteConfig: {
      alwaysOn: false
      ftpsState: 'Disabled'
      http20Enabled: true
      linuxFxVersion: 'Node|22'
      minTlsVersion: '1.2'
      cors: {
        allowedOrigins: bffAllowedOrigins
        supportCredentials: false
      }
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'node'
        }
        {
          name: 'FUNCTIONS_NODE_BLOCK_ON_ENTRY_POINT_ERROR'
          value: '1'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~22'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorageAccount!.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${functionStorageAccount!.listKeys().keys[0].value}'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights!.properties.ConnectionString
        }
        {
          name: 'TENANT_ID'
          value: tenantId
        }
        {
          name: 'API_CLIENT_ID'
          value: apiClientId
        }
        {
          name: 'SPA_CLIENT_ID'
          value: spaClientId
        }
        {
          name: 'GOVERNANCE_TABLE_ENDPOINT'
          value: governanceStorageAccount.properties.primaryEndpoints.table
        }
        {
          name: 'ALLOWED_ORIGINS'
          value: join(bffAllowedOrigins, ',')
        }
        {
          name: 'ADMIN_AUTH_CONTEXT_ID'
          value: adminAuthContextId
        }
        {
          name: 'ADMIN_SESSION_MAX_MINUTES'
          value: string(adminSessionMaxMinutes)
        }
      ]
    }
  }
}

resource functionProfileContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployBff) {
  name: guid(localAdminUserSettings.id, functionApp!.id, storageTableDataContributorRoleDefinitionId)
  scope: localAdminUserSettings
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource functionAuditContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployBff) {
  name: guid(localAdminAuditRecords.id, functionApp!.id, storageTableDataContributorRoleDefinitionId)
  scope: localAdminAuditRecords
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource functionReviewActionContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployBff) {
  name: guid(localAdminReviewActions.id, functionApp!.id, storageTableDataContributorRoleDefinitionId)
  scope: localAdminReviewActions
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource functionAllowRuleContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployBff) {
  name: guid(localAdminAllowRules.id, functionApp!.id, storageTableDataContributorRoleDefinitionId)
  scope: localAdminAllowRules
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
  }
}

resource functionPackageReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployBff) {
  name: guid(functionPackageContainer!.id, functionApp!.id, storageBlobDataReaderRoleDefinitionId)
  scope: functionPackageContainer
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataReaderRoleDefinitionId
  }
}

output automationAccountName string = automationAccount.name
output automationManagedIdentityPrincipalId string = automationAccount.identity.principalId
output storageAccountName string = storageAccount.name
output tableEndpoint string = storageAccount.properties.primaryEndpoints.table
output governanceStorageAccountName string = governanceStorageAccount.name
output governanceTableEndpoint string = governanceStorageAccount.properties.primaryEndpoints.table
output bffBaseUrl string = deployBff ? 'https://${functionAppName}.azurewebsites.net/v1' : ''
output deployedFunctionAppName string = deployBff ? functionAppName : ''
output functionPlanName string = deployBff ? resolvedFunctionPlanName : ''
output applicationInsightsName string = deployBff ? resolvedApplicationInsightsName : ''
