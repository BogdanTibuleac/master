# Malware Classifier Robustness

> The maintained technical documentation portal is
> [`documentation/README.md`](documentation/README.md). It covers architecture, API contracts,
> scanner behavior, configuration, development, deployment, security, testing, and roadmap.

This project evaluates the robustness of a static malware classifier using the EMBER feature
representation. It uses only offline research data and simulated feature-space perturbations;
it does not create, execute, or distribute malware.

## MVP scope

1. Train a LightGBM baseline on prepared EMBER features.
2. Evaluate standard classification metrics.
3. Apply safe, simulated feature perturbations to the held-out malware samples.
4. Measure the robustness impact and retrain with augmented data.
5. Scan quarantined Windows PE files through a durable, isolated static-analysis workflow.

The runtime now includes optional PostgreSQL, RabbitMQ, and Azure Blob adapters. The default
developer profile remains local and requires no cloud account.

## Hostile-content runtime

The asynchronous path is intentionally split by trust boundary:

- The FastAPI edge creates tenant-scoped workflows, issues short-lived upload capabilities,
  seals exact object generations, and returns metadata/results. It does not parse content.
- PostgreSQL owns workflow state, append-only events, leases, fencing tokens, and the
  transactional outbox.
- RabbitMQ carries a strict, versioned metadata-only task; file bytes, filenames, URLs,
  extracted strings, and feature vectors are rejected from that contract.
- A disposable extractor verifies the sealed size and SHA-256, then emits an exact 2,381-value
  EMBER-v2 envelope plus bounded semantic evidence. Its container profile is networkless,
  non-root, read-only, capability-free, and resource bounded.
- The trusted decision runtime validates the untrusted envelope, runs native LightGBM margin
  scoring, calibration and policy, then publishes a canonical content-hashed result manifest.

The local auto-processing profile is disabled until an extractor is explicitly configured. The
same-host child-process runner is available only for controlled test fixtures with an explicit
unsafe acknowledgement; normal scans use a digest-pinned, disposable container. A container is
still not a replacement for a production microVM or separate hardened host.

## EMBER2018 dataset

The local MVP uses the official EMBER2018 feature-version-2 archive hosted by
Elastic. It contains extracted static features rather than executable malware.

```powershell
malware-data download --raw-dir data/raw
malware-data verify --raw-dir data/raw
malware-data smoke-test --raw-dir data/raw
```

The acquisition command supports resumed HTTP downloads, verifies Elastic's
published SHA-256 before extraction, and records provenance in
`data/raw/ember2018/manifest.json`. Raw records are streamed in bounded-memory
batches and converted to the official 2,381-value feature layout used by the
included benchmark LightGBM model.

## Data contract

The local pipeline accepts CSV and Parquet feature tables. Each table must have a
binary `label` column (0 for benign, 1 for malware) and one or more numeric feature
columns, with no missing values. `split_feature_table` makes deterministic,
stratified train/validation/test partitions from a single prepared table; persist
the resulting partitions through your experiment workflow before model training.

## Repository layout

- `src/malware_robustness/api/`: FastAPI application factory and dependency wiring.
- `src/malware_robustness/routes/`: versioned HTTP endpoints only.
- `src/malware_robustness/services/`: transport-independent application workflows.
- `src/malware_robustness/repositories/`: dataset and future persistence adapters.
- `src/malware_robustness/domain/`: shared business entities and repository contracts.
- `src/malware_robustness/schemas/`: validated HTTP response contracts.
- `src/malware_robustness/core/`: runtime settings and cross-cutting infrastructure.
- `configs/`: versioned experiment configuration.
- `data/`: local data only; excluded from Git.
- `artifacts/`: generated models, metrics, and figures; excluded from Git.
- `tests/`: automated tests.
- `docs/`: project documentation.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
```

After creating `artifacts/robust_lightgbm/model.txt` with `malware-harden`, start the complete
local asynchronous flow with:

```powershell
$env:MALWARE_RUNTIME_AUTO_PROCESS = "true"
malware-api
```

The API is available at `http://127.0.0.1:8000`, with interactive documentation
at `/docs`. Routes depend on services, services depend on repository contracts,
and only repository implementations access dataset files.

## Frontend dashboard

The dashboard lives in `frontend/` and uses the local API URL from
`NEXT_PUBLIC_API_URL` (default: `http://127.0.0.1:8000`). Start it separately:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` to scan a suspicious PE file, inspect its malware
probability and static evidence, review scan history, and explore the supporting
dataset and robustness experiments.

## Static file scanning

The `Scan` workspace accepts `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, and `.ocx`
files up to 25 MB. With `X-Aegis-Scan: hostile-content-v1`, the browser first creates a
workflow, uploads to a write-once quarantine capability, and seals the object by size and
SHA-256. Only the disposable extraction boundary parses it; neither the edge API nor RabbitMQ
receives the executable bytes. The prior `X-Aegis-Scan: static-pe-v1` compatibility endpoint has
been retired and returns `410 Gone`; it cannot be used to parse uploaded bytes in the API process.
`MALWARE_MAX_UPLOAD_BYTES` can set a 1-byte to 100-MB file limit, while
`MALWARE_MAX_CONCURRENT_SCANS` can set 1 to 32 in-flight scans (default: 4).

Local quarantine objects live under `data/quarantine/`, while public manifests live under
`data/results/` as create-only, content-hashed JSON. The result contract separates calibrated
prediction, policy decision, model contributors, independently observed indicators, limitations,
and immutable release provenance. The manifest always records `executed: false`.

The API exposes:

- `POST /api/v1/scans` — create an asynchronous metadata-only workflow.
- `PUT /api/v1/scans/{scan_id}/content` — local development upload capability only.
- `POST /api/v1/scans/{scan_id}:seal` — verify and queue one immutable object generation.
- `GET /api/v1/scans` — recent metadata-only workflow/result history.
- `GET /api/v1/scans/{scan_id}` — workflow state and immutable public result.

## Distributed runtime

Install the deployment adapters with `pip install -e '.[runtime,azure]'`. Apply
`db/migrations/001_scan_workflows.sql` followed by `002_workflow_delivery.sql` to PostgreSQL,
then configure the API, outbox publisher, and worker with the same environment:

```powershell
$env:MALWARE_WORKFLOW_BACKEND = "postgres"
$env:MALWARE_DATABASE_URL = "postgresql://..."
$env:MALWARE_RABBITMQ_URL = "amqps://..."
$env:MALWARE_RABBITMQ_QUEUE = "malware.scan"

malware-api       # edge/API process
malware-outbox    # transactional-outbox publisher
malware-worker    # metadata consumer + disposable extractor + trusted decision
```

For Azure direct upload, set `MALWARE_QUARANTINE_BACKEND=azure`,
`MALWARE_AZURE_ACCOUNT_URL`, and `MALWARE_AZURE_QUARANTINE_CONTAINER`. The account uses
`DefaultAzureCredential`; upload grants are user-delegation SAS tokens scoped to one block blob,
HTTPS, create/write only, and at most 15 minutes. Public containers and mutable/latest object
resolution are rejected. Configure Blob CORS for the dashboard origin separately.

See `docs/hostile-content-runtime.md` for trust boundaries, configuration, and the remaining
production hardening work.

Static ML is a triage signal rather than proof that a file is safe or malicious.
Signature reputation and isolated behavioral sandboxing remain later defense layers.
The detailed upload trust boundaries, controls, residual risks, and deployment
recommendations are recorded in `docs/pe-upload-threat-model.md`.

## Baseline training

Prepare the train, validation, and test tables configured in `configs/baseline.yaml`,
then run the reproducible LightGBM experiment:

```powershell
malware-train --config configs/baseline.yaml --artifacts-dir artifacts
```

The run uses validation-based early stopping and writes a native LightGBM model plus
accuracy, precision, recall, F1, ROC-AUC, average precision, and confusion-matrix
counts to `artifacts/<experiment_name>/`.

For a fast first run on real EMBER2018 records, prepare deterministic, class-balanced
partitions sampled uniformly across all source files and train them with:

```powershell
malware-data prepare-sample --raw-dir data/raw --output-dir data/processed/representative
malware-train --config configs/ember2018-sample.yaml --artifacts-dir artifacts
```

The sample experiment calibrates its decision threshold on validation data, keeps
the held-out test set untouched until final evaluation, and preserves older run
artifacts while the API exposes the newest completed baseline.

Run the safe held-out feature-space robustness study with:

```powershell
malware-robustness --config configs/ember2018-sample.yaml --artifacts-dir artifacts
```

The evaluation simulates bounded histogram smoothing, string-feature attenuation,
hashed-feature dropout, and their combination. It operates only on copied numeric
feature vectors and records detection-rate, evasion-rate, and confidence changes.

Train and compare the hardened model with:

```powershell
malware-harden --config configs/robust-lightgbm.yaml --artifacts-dir artifacts
```

Only the training partition is augmented. Clean validation data calibrates the
threshold, the untouched test partition measures normal performance, and the same
robustness suite compares baseline and hardened detection under perturbation.

## Branch delivery plan

| Branch | Purpose |
|---|---|
| `chore/project-scaffold` | Reproducible project foundation |
| `feature/data-pipeline` | Dataset loading, validation, and split handling |
| `feature/baseline-model` | Training and standard evaluation |
| `feature/robustness-evaluation` | Safe simulated perturbations and robustness metrics |
| `feature/adversarial-training` | Augmented training and comparison |
| `feature/file-scanning` | Safe PE upload, static inference, explanations, and scan history |
| `feature/rabbitmq-orchestration` | Optional distributed task workflow |
| `feature/azure-integration` | Optional cloud storage and execution support |

Each branch will be pushed for review and merged only after tests pass.
