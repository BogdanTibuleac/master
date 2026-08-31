targetScope = 'resourceGroup'

@description('Short lowercase prefix used in Azure resource names.')
@minLength(3)
@maxLength(18)
param namePrefix string

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('Immutable API image tag, normally the full Git commit SHA.')
param imageTag string

@description('Set false for the bootstrap pass that creates ACR before the first image exists.')
param deployApplication bool = true

@description('Private model-container prefix containing model.txt and metrics.json.')
param modelBlobPrefix string

@description('Explicit browser origins allowed to call the API.')
@minLength(1)
param corsOrigins array

@description('Repository name within Azure Container Registry.')
param imageRepository string = 'malware-robustness-api'

@description('Maximum in-memory upload size accepted by the API.')
@minValue(1048576)
@maxValue(26214400)
param maximumUploadBytes int = 26214400

@description('Days to retain metadata-only scan results.')
@minValue(1)
@maxValue(365)
param scanMetadataRetentionDays int = 30

@description('Minimum warm replicas. Keep at least one to avoid model-cache cold starts.')
@minValue(0)
@maxValue(10)
param minReplicas int = 1

@description('Maximum API replicas for the minimal service.')
@minValue(1)
@maxValue(10)
param maxReplicas int = 3

var compactPrefix = toLower(replace(namePrefix, '-', ''))
var resourceSuffix = take(uniqueString(subscription().id, resourceGroup().id), 8)
var registryName = take('${compactPrefix}${resourceSuffix}acr', 50)
var storageAccountName = take('${compactPrefix}${resourceSuffix}st', 24)
var identityName = '${namePrefix}-${resourceSuffix}-api'
var logWorkspaceName = '${namePrefix}-${resourceSuffix}-logs'
var environmentName = '${namePrefix}-${resourceSuffix}-env'
var applicationName = '${namePrefix}-${resourceSuffix}-api'
var modelContainerName = 'models'
var scanContainerName = 'scan-metadata'
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var blobDataReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
var blobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource runtimeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    dataEndpointEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource acrPullRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: acrPullRoleId
}

resource registryPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, runtimeIdentity.id, acrPullRole.id)
  scope: registry
  properties: {
    principalId: runtimeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRole.id
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
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
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    isVersioningEnabled: true
  }
}

resource modelContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: modelContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource scanContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: scanContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource blobDataReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: blobDataReaderRoleId
}

resource blobDataContributorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: blobDataContributorRoleId
}

resource modelReadAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(modelContainer.id, runtimeIdentity.id, blobDataReaderRole.id)
  scope: modelContainer
  properties: {
    principalId: runtimeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: blobDataReaderRole.id
  }
}

resource scanWriteAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scanContainer.id, runtimeIdentity.id, blobDataContributorRole.id)
  scope: scanContainer
  properties: {
    principalId: runtimeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: blobDataContributorRole.id
  }
}

resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'expire-scan-metadata'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                '${scanContainerName}/'
              ]
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: scanMetadataRetentionDays
                }
              }
              version: {
                delete: {
                  daysAfterCreationGreaterThan: 7
                }
              }
            }
          }
        }
      ]
    }
  }
}

resource logWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logWorkspaceName
  location: location
  properties: {
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource containerEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logWorkspace.properties.customerId
        sharedKey: logWorkspace.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = if (deployApplication) {
  name: applicationName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runtimeIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnvironment.id
    configuration: {
      activeRevisionsMode: 'Single'
      maxInactiveRevisions: 5
      ingress: {
        allowInsecure: false
        external: true
        targetPort: 8000
        transport: 'auto'
      }
      registries: [
        {
          identity: runtimeIdentity.id
          server: registry.properties.loginServer
        }
      ]
    }
    template: {
      terminationGracePeriodSeconds: 30
      containers: [
        {
          name: 'api'
          image: '${registry.properties.loginServer}/${imageRepository}:${imageTag}'
          env: [
            {
              name: 'MALWARE_STORAGE_BACKEND'
              value: 'azure_blob'
            }
            {
              name: 'MALWARE_BLOB_ACCOUNT_URL'
              value: storage.properties.primaryEndpoints.blob
            }
            {
              name: 'MALWARE_MODEL_CONTAINER'
              value: modelContainerName
            }
            {
              name: 'MALWARE_SCAN_CONTAINER'
              value: scanContainerName
            }
            {
              name: 'MALWARE_MODEL_BLOB_PREFIX'
              value: modelBlobPrefix
            }
            {
              name: 'MALWARE_MODEL_CACHE_DIR'
              value: '/tmp/malware-model-cache'
            }
            {
              name: 'MALWARE_AZURE_CLIENT_ID'
              value: runtimeIdentity.properties.clientId
            }
            {
              name: 'MALWARE_MAX_UPLOAD_BYTES'
              value: string(maximumUploadBytes)
            }
            {
              name: 'MALWARE_CORS_ORIGINS'
              value: join(corsOrigins, ',')
            }
          ]
          probes: [
            {
              type: 'Startup'
              failureThreshold: 30
              periodSeconds: 5
              timeoutSeconds: 3
              httpGet: {
                path: '/health'
                port: 8000
                scheme: 'HTTP'
              }
            }
            {
              type: 'Liveness'
              failureThreshold: 3
              initialDelaySeconds: 10
              periodSeconds: 30
              timeoutSeconds: 5
              httpGet: {
                path: '/health'
                port: 8000
                scheme: 'HTTP'
              }
            }
            {
              type: 'Readiness'
              failureThreshold: 3
              initialDelaySeconds: 5
              periodSeconds: 10
              timeoutSeconds: 5
              httpGet: {
                path: '/ready'
                port: 8000
                scheme: 'HTTP'
              }
            }
          ]
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-concurrency'
            http: {
              metadata: {
                concurrentRequests: '10'
              }
            }
          }
        ]
      }
    }
  }
  dependsOn: [
    registryPullAssignment
    modelReadAssignment
    scanWriteAssignment
  ]
}

output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
output storageAccountName string = storage.name
output storageBlobEndpoint string = storage.properties.primaryEndpoints.blob
output runtimeIdentityClientId string = runtimeIdentity.properties.clientId
output containerAppName string = applicationName
