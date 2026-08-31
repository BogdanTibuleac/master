using '../main.bicep'

param namePrefix = 'aegisdev'
param location = 'westeurope'
param imageTag = 'replace-with-full-git-sha'
param deployApplication = false
param modelBlobPrefix = 'releases/replace-with-model-version'
param corsOrigins = [
  'https://replace-with-frontend-host.example'
]
param scanMetadataRetentionDays = 14
param minReplicas = 1
param maxReplicas = 2
