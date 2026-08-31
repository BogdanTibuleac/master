# Azure deployment and operations runbook

This runbook describes the minimal production foundation for the synchronous malware
scanning API. The checked-in work creates no Azure resources by itself. An operator must
run every provisioning or deployment command explicitly.

RabbitMQ workers and scanner UI hosting are outside this foundation. Uploaded PE bytes
remain in API memory for the duration of a synchronous request and are never written to
Blob Storage.

## Architecture

| Component | Purpose | Runtime access |
|---|---|---|
| Azure Container Apps | Runs one non-root Uvicorn process per replica with startup, liveness, and readiness probes | Public HTTPS ingress |
| Azure Container Registry | Stores the API image with the admin account disabled | Managed-identity `AcrPull` |
| `models` Blob container | Stores immutable release prefixes containing `model.txt` and `metrics.json` | Runtime identity has container-scoped `Storage Blob Data Reader` |
| `scan-metadata` Blob container | Stores JSON scan results only | Runtime identity has container-scoped `Storage Blob Data Contributor` |
| Log Analytics | Collects Container Apps console and system logs | Wired by the managed environment |

The application downloads one selected model release to its ephemeral cache, validates
both files, and loads the LightGBM model before `/ready` succeeds. Scan records are shared
through Blob Storage, so history remains consistent when Container Apps scales to multiple
replicas. Blob names contain opaque scan IDs; uploaded binaries are never assigned a blob
name or sent to the storage SDK.

## Security posture and boundaries

The Bicep template enforces these controls:

- Blob public access and storage shared-key authorization are disabled. Code authenticates
  with `DefaultAzureCredential` and a user-assigned managed identity.
- RBAC is scoped to each Blob container. The API can read models but cannot replace them;
  it can write metadata but has no model-container write permission.
- Storage accepts HTTPS with TLS 1.2 or newer, infrastructure encryption is enabled, Blob
  versioning and seven-day soft delete are enabled, and scan metadata expires after the
  configured retention period.
- ACR has no admin credentials. The Container App pulls its image with managed identity.
- The image runs as UID/GID 10001, installs only runtime dependencies, and uses one worker
  per replica to keep model memory bounded.
- CORS origins are explicit deployment parameters. Environment examples contain only
  non-secret identifiers and URLs.

The minimal template leaves the ACR, Blob, and Container Apps ingress endpoints publicly
routable, with Microsoft Entra authorization required for registry and Blob data. Before
using the service for confidential or regulated workloads, place Container Apps in a VNet,
add private endpoints and private DNS for ACR and Storage, disable their public network
access, add a WAF/API gateway and application authentication, and use zone redundancy in
a supported region. Static ML remains a triage signal, not a malware detonation sandbox.

The Log Analytics shared key is obtained inside the ARM deployment expression and is never
stored in source control or injected into the application. Do not place credentials in
`.bicepparam`, `.env`, image build arguments, or deployment command history. Use workload
identity or a protected CI service connection for automation.

## Prerequisites

- Azure CLI with Bicep support (`az bicep version`).
- Docker for local builds, or permission to use `az acr build`.
- A subscription role that can create resources and role assignments in the target resource
  group (for example Owner, or Contributor plus User Access Administrator).
- A dedicated resource group. The template deploys at resource-group scope and must not be
  pointed at a shared group without review.
- A completed hardened model release at `artifacts/robust_lightgbm/model.txt` and
  `artifacts/robust_lightgbm/metrics.json`.

Useful Microsoft references are the [Container Apps managed-identity image-pull guide](https://learn.microsoft.com/azure/container-apps/managed-identity-image-pull),
[Blob data RBAC guide](https://learn.microsoft.com/azure/storage/blobs/assign-azure-role-data-access),
and [Bicep RBAC guidance](https://learn.microsoft.com/azure/azure-resource-manager/bicep/scenarios-rbac).

## Local validation

Run all checks from the repository root:

```powershell
.\scripts\validate-deployment.ps1
```

This synchronizes the locked Python environment with the `azure` and `dev` extras, runs
Ruff and pytest, compiles both Bicep files, and builds `malware-robustness-api:local`. It
does not log in to Azure or submit a deployment. If Docker is installed but its daemon is
not running, use:

```powershell
.\scripts\validate-deployment.ps1 -SkipDocker
```

The default container smoke test expects `/health` to return 200 and `/ready` to return 503
because the image intentionally contains no model:

```powershell
.\scripts\smoke-container.ps1
```

To verify ready behavior with a local hardened model, build the image and mount the parent
artifact directory read-only:

```powershell
.\scripts\smoke-container.ps1 -ArtifactDirectory .\artifacts
```

## Provision and release

The first release is two-phase because ACR must exist before its first application image.
Use immutable Git commit SHAs for image tags and immutable release identifiers for model
prefixes. The example below is PowerShell; replace every value before running it.

```powershell
$SubscriptionId = '<subscription-id>'
$ResourceGroup = '<dedicated-resource-group>'
$Location = 'westeurope'
$DeploymentName = 'malware-api-foundation'
$ImageRepository = 'malware-robustness-api'
$ImageTag = (git rev-parse HEAD)
$ModelVersion = '<immutable-model-release-id>'
$ModelPrefix = "releases/$ModelVersion"

az login
az account set --subscription $SubscriptionId
az group create --name $ResourceGroup --location $Location
```

Review the change set before either deployment pass:

```powershell
az deployment group what-if `
  --resource-group $ResourceGroup `
  --template-file infra/main.bicep `
  --parameters infra/parameters/dev.bicepparam `
  --parameters location=$Location deployApplication=false imageTag=$ImageTag modelBlobPrefix=$ModelPrefix
```

Bootstrap ACR, Storage, identity, RBAC, logging, and the Container Apps environment without
creating the application:

```powershell
az deployment group create `
  --name $DeploymentName `
  --resource-group $ResourceGroup `
  --template-file infra/main.bicep `
  --parameters infra/parameters/dev.bicepparam `
  --parameters location=$Location deployApplication=false imageTag=$ImageTag modelBlobPrefix=$ModelPrefix

$Outputs = az deployment group show `
  --name $DeploymentName `
  --resource-group $ResourceGroup `
  --query properties.outputs -o json | ConvertFrom-Json
$RegistryName = $Outputs.registryName.value
$StorageAccount = $Outputs.storageAccountName.value
$ContainerAppName = $Outputs.containerAppName.value
```

The deployment identity intentionally cannot upload a model. Grant the human or CI release
principal `Storage Blob Data Contributor` on only the `models` container, then wait for RBAC
propagation. For an interactive release principal:

```powershell
$OperatorObjectId = az ad signed-in-user show --query id -o tsv
$StorageId = az storage account show `
  --name $StorageAccount `
  --resource-group $ResourceGroup `
  --query id -o tsv
$ModelContainerScope = "$StorageId/blobServices/default/containers/models"

az role assignment create `
  --assignee-object-id $OperatorObjectId `
  --assignee-principal-type User `
  --role 'Storage Blob Data Contributor' `
  --scope $ModelContainerScope
```

Publish both model files under a new prefix. `--overwrite false` preserves release
immutability:

```powershell
az storage blob upload `
  --account-name $StorageAccount `
  --container-name models `
  --name "$ModelPrefix/model.txt" `
  --file artifacts/robust_lightgbm/model.txt `
  --auth-mode login `
  --overwrite false

az storage blob upload `
  --account-name $StorageAccount `
  --container-name models `
  --name "$ModelPrefix/metrics.json" `
  --file artifacts/robust_lightgbm/metrics.json `
  --auth-mode login `
  --overwrite false
```

Build the locked image in ACR, then review and apply the second pass with the exact image and
model versions:

```powershell
az acr build `
  --registry $RegistryName `
  --image "${ImageRepository}:$ImageTag" `
  .

az deployment group what-if `
  --resource-group $ResourceGroup `
  --template-file infra/main.bicep `
  --parameters infra/parameters/dev.bicepparam `
  --parameters location=$Location deployApplication=true imageTag=$ImageTag modelBlobPrefix=$ModelPrefix

az deployment group create `
  --name $DeploymentName `
  --resource-group $ResourceGroup `
  --template-file infra/main.bicep `
  --parameters infra/parameters/dev.bicepparam `
  --parameters location=$Location deployApplication=true imageTag=$ImageTag modelBlobPrefix=$ModelPrefix
```

Role assignments can take several minutes to propagate. A revision may start while `/ready`
returns 503; do not weaken the probe. If it remains unready, use the checks below.

## Post-deployment verification

```powershell
$Fqdn = az containerapp show `
  --name $ContainerAppName `
  --resource-group $ResourceGroup `
  --query properties.configuration.ingress.fqdn -o tsv

Invoke-RestMethod "https://$Fqdn/health"
Invoke-RestMethod "https://$Fqdn/ready"
az containerapp revision list `
  --name $ContainerAppName `
  --resource-group $ResourceGroup `
  --query '[].{name:name,active:properties.active,health:properties.healthState}' -o table
```

Expected readiness payload:

```json
{
  "status": "ready",
  "checks": {
    "model_artifacts": true,
    "scan_metadata": true
  }
}
```

Do not use a live malware sample as a deployment smoke test. Automated route tests create a
synthetic, harmless PE fixture without downloading or executing a binary.

## Operations and troubleshooting

View revision and application logs:

```powershell
az containerapp logs show `
  --name $ContainerAppName `
  --resource-group $ResourceGroup `
  --type console `
  --follow
```

Readiness check interpretation:

| Check | Likely cause | Action |
|---|---|---|
| `model_artifacts: false` | Wrong prefix, missing file, invalid metrics/model, or model-container RBAC propagation | Verify both blobs under the configured prefix and the runtime identity's reader assignment |
| `scan_metadata: false` | Container missing, identity/RBAC issue, or Storage unavailable | Verify the private container and contributor assignment at container scope |
| Both false | Managed identity selection, account URL, or broad Storage outage | Compare `MALWARE_AZURE_CLIENT_ID` with the deployed identity client ID and inspect platform logs |

The API deliberately returns only dependency names and booleans; credential or storage error
details are not exposed to callers. Keep the selected model prefix immutable for the lifetime
of a revision. Each new model release gets a new prefix and a new Container Apps revision.

The metadata history adapter enumerates and sorts Blob properties before downloading the
requested page. This is acceptable for the minimal service with lifecycle expiry, but move
history to an indexed database before retaining high-volume scan records or adding complex
queries.

## Rollback

Keep the previous image tag and model prefix as one tested release pair. Roll back by running
the second deployment pass with both previous values, never by overwriting blobs or reusing an
image tag:

```powershell
az deployment group create `
  --name $DeploymentName `
  --resource-group $ResourceGroup `
  --template-file infra/main.bicep `
  --parameters infra/parameters/dev.bicepparam `
  --parameters deployApplication=true imageTag='<previous-git-sha>' modelBlobPrefix='releases/<previous-model-id>'
```

Verify `/ready` and revision health after rollback. Blob versioning and soft delete protect
against accidental metadata or artifact deletion, but they are not a substitute for an
independent backup and tested restore procedure.

## Incident response and access review

1. Disable ingress or set the Container App's minimum and maximum replicas to zero if serving
   must stop immediately.
2. Remove the runtime identity's container-scoped role assignments if storage access must be
   revoked. Do not rotate or distribute account keys; shared-key access is disabled.
3. Preserve Container Apps and Log Analytics evidence according to the incident policy.
4. Review the `scan-metadata` container for metadata only. The design cannot recover uploaded
   PE bytes because they are never retained.
5. Release a new immutable image/model pair, deploy it, and verify readiness before restoring
   normal traffic.
6. Periodically remove temporary model-publisher assignments and review all assignments on
   ACR, the `models` container, and the `scan-metadata` container.
