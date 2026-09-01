# Configuration reference

## 1. Loading model

Backend settings are read from environment variables when the FastAPI app or runtime CLI starts.
There is no committed `.env` loader in the application; `.env` is ignored by Git. Set variables
in the process environment or through the deployment platform.

Paths are resolved relative to the process working directory unless absolute paths are supplied.
Run commands from the repository root for the documented defaults.

## 2. Backend paths and capacity

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_DATA_DIR` | `data/raw` | EMBER2018 raw dataset root |
| `MALWARE_ARTIFACT_DIR` | `artifacts` | Models, metrics, and experiment artifacts |
| `MALWARE_SCAN_DIR` | `data/scans` | Legacy synchronous metadata |
| `MALWARE_QUARANTINE_DIR` | `data/quarantine` | Local hostile sample storage |
| `MALWARE_RESULT_DIR` | `data/results` | Local immutable public result storage |
| `MALWARE_MAX_UPLOAD_BYTES` | `26214400` (25 MiB) | Integer from 1 byte through 100 MiB |
| `MALWARE_MAX_CONCURRENT_SCANS` | `4` | Integer from 1 through 32 |
| `MALWARE_UPLOAD_GRANT_TTL_SECONDS` | `900` | Integer from 1 through 3,600 seconds |

The HTTP multipart request guard adds 64 KiB to the configured file limit for envelope overhead.

## 3. Identity and policy

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_UPLOAD_GRANT_SECRET` | Random 32-byte process secret | HMAC secret for local upload grants; configure a stable secret if grants must survive restart |
| `MALWARE_HOSTILE_TENANT_ID` | `local-development` | Non-empty configured tenant used by the current single-tenant edge |
| `MALWARE_ANALYSIS_RELEASE_ID` | Built-in deterministic `sha256:` identity | Exactly `sha256:` plus 64 lowercase hexadecimal characters |
| `MALWARE_POLICY_SNAPSHOT_ID` | `static-pe-policy/local-v1` | Non-empty policy provenance identity |
| `MALWARE_FEATURE_SCHEMA_ID` | `ember-v2/2381` | Non-empty bounded schema name |
| `MALWARE_FEATURE_SCHEMA_DIGEST` | Built-in deterministic `sha256:` identity | Immutable schema implementation identity |
| `MALWARE_EXTRACTOR_IMAGE_DIGEST` | Built-in deterministic `sha256:` identity | Immutable extractor release identity |
| `MALWARE_WORKER_IMAGE_DIGEST` | Built-in deterministic `sha256:` identity | Immutable trusted worker release identity |
| `MALWARE_BENIGN_THRESHOLD` | `0.2` | Numeric low-risk boundary |
| `MALWARE_MALICIOUS_THRESHOLD` | `0.6` | Numeric malicious boundary |
| `MALWARE_HIGH_RISK_THRESHOLD` | `0.9` | Numeric strongest-decision boundary |

Thresholds must satisfy:

```text
0 <= benign < malicious < high_risk <= 1
```

The default high-risk corroboration count is two distinct evidence families with `high` or
`critical` severity. It is a domain constant in the current composition, not an environment
variable.

## 4. Workflow and PostgreSQL

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_WORKFLOW_BACKEND` | `memory` | `memory` or `postgres` |
| `MALWARE_DATABASE_URL` | None | Required when workflow backend is `postgres`; Psycopg connection string |
| `MALWARE_OUTBOX_OWNER` | `outbox-local-1` | Bounded non-empty publisher lease identity |
| `MALWARE_WORKER_OWNER` | `analysis-local-1` | Bounded non-empty worker lease identity |

`malware-outbox` and `malware-worker` require the PostgreSQL workflow backend. The API can use
either backend.

## 5. RabbitMQ

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_RABBITMQ_URL` | `amqp://guest:guest@127.0.0.1:5672/%2F` | Non-empty AMQP connection URL |
| `MALWARE_RABBITMQ_QUEUE` | `malware.scan` | Bounded non-empty durable queue name |

Use `amqps://` with a least-privilege service identity outside local development. Keep the URL in
a secret manager, not source control or logs.

## 6. Quarantine backend and Azure

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_QUARANTINE_BACKEND` | `local` | `local` or `azure` |
| `MALWARE_AZURE_ACCOUNT_URL` | None | Required for Azure; credential-free HTTPS account origin only |
| `MALWARE_AZURE_QUARANTINE_CONTAINER` | None | Required for Azure; private versioned container name |

The account URL cannot contain username, password, path, query, or fragment. Authentication uses
`DefaultAzureCredential`, so identity-specific variables are consumed by the Azure SDK rather
than this settings class.

Azure quarantine and `MALWARE_RUNTIME_AUTO_PROCESS=true` are intentionally incompatible. Use the
distributed publisher/worker profile for Azure.

## 7. Processing and extractor

| Variable | Default | Validation and purpose |
|---|---|---|
| `MALWARE_RUNTIME_AUTO_PROCESS` | `false` | Boolean local convenience mode; accepted true values: `1`, `true`, `yes`, `on` |
| `MALWARE_EXTRACTOR_RUNNER` | `disabled` | `disabled`, development-only `process`, or `container` |
| `MALWARE_ALLOW_UNSAFE_PROCESS_EXTRACTOR` | `false` | Required acknowledgement before same-host process extraction is allowed |
| `MALWARE_EXTRACTOR_CONTAINER_CLI` | `docker` | `docker` or `nerdctl` |
| `MALWARE_EXTRACTOR_IMAGE_REFERENCE` | None | Required in container mode; registry digest or local immutable `sha256:` identity |
| `MALWARE_EXTRACTOR_SECCOMP_PROFILE` | `docker/extractor/seccomp-profile.json` | Required deny-by-default seccomp profile attached at launch |

Accepted false values are `0`, `false`, `no`, and `off`, case-insensitive. Any other Boolean text
is rejected.

Example digest-pinned image configuration:

```powershell
$digest = "sha256:<64-lowercase-hex>"
$env:MALWARE_EXTRACTOR_RUNNER = "container"
$env:MALWARE_EXTRACTOR_IMAGE_DIGEST = $digest
$env:MALWARE_EXTRACTOR_IMAGE_REFERENCE = "registry.example/aegis-extractor@$digest"
$env:MALWARE_EXTRACTOR_CONTAINER_CLI = "docker"
```

## 8. CORS

| Variable | Default |
|---|---|
| `MALWARE_CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000,https://aegis-lab-malware.endava-8536.chatgpt.site` |

Supply a comma-separated list of exact HTTP/HTTPS origins. Paths, queries, credentials, and
wildcard `*` are rejected. Default ports are normalized away and duplicates are removed.

Azure Blob CORS is a separate storage-account setting; backend CORS does not authorize the
browser to upload directly to Azure.

## 9. Frontend

| Variable | Default | Purpose |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://127.0.0.1:8000` | Browser-visible backend base URL |

Set it when building/running the frontend:

```powershell
$env:NEXT_PUBLIC_API_URL = "https://api.example.com"
npm run build
```

Because it is browser-visible, never place credentials in this value.

## 10. Experiment YAML schema

All files under `configs/` have these sections:

```yaml
experiment_name: baseline_lightgbm_representative
random_seed: 42

data:
  train_path: data/processed/representative/train.parquet
  validation_path: data/processed/representative/validation.parquet
  test_path: data/processed/representative/test.parquet
  label_column: label

model:
  objective: binary
  learning_rate: 0.05
  num_leaves: 31
  n_estimators: 300
  n_jobs: -1

evaluation:
  decision_threshold: 0.5
  calibrate_threshold: true
```

The committed configurations are:

| File | Experiment | Purpose |
|---|---|---|
| `configs/baseline.yaml` | `baseline_lightgbm` | Generic prepared-table baseline |
| `configs/ember2018-sample.yaml` | `baseline_lightgbm_representative` | Real representative EMBER baseline and robustness input |
| `configs/robust-lightgbm.yaml` | `robust_lightgbm` | Adversarial hardening and runtime model artifact |

## 11. Recommended configuration discipline

- Store secrets in the deployment secret manager.
- Use stable, unique owner IDs per publisher and worker instance.
- Pin image references by digest and deploy the matching release identity.
- Change `MALWARE_ANALYSIS_RELEASE_ID` whenever extractor, schema, model, calibrator, or trusted
  decision behavior changes.
- Change the policy snapshot identity whenever thresholds or policy logic changes.
- Use absolute persistent paths or managed volumes outside local development.
- Validate all settings during deployment startup before accepting traffic.
- Do not use the random local upload secret when grants must remain valid across API replicas or
  restarts.

## 12. Invalid combinations

Startup fails intentionally when:

- PostgreSQL is selected without `MALWARE_DATABASE_URL`;
- Azure quarantine is selected without account URL and container;
- Azure account URL is not a credential-free HTTPS origin;
- local auto-processing is combined with Azure quarantine;
- container extraction lacks a digest-pinned image reference;
- any configured digest is not canonical lowercase SHA-256 identity text;
- thresholds are unordered;
- capacities or TTLs are outside their bounds;
- CORS contains no valid explicit origin or includes a wildcard.
