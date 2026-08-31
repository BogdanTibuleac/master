# Malware Classifier Robustness

This project evaluates the robustness of a static malware classifier using the EMBER feature
representation. It uses only offline research data and simulated feature-space perturbations;
it does not create, execute, or distribute malware.

## MVP scope

1. Train a LightGBM baseline on prepared EMBER features.
2. Evaluate standard classification metrics.
3. Apply safe, simulated feature perturbations to the held-out malware samples.
4. Measure the robustness impact and retrain with augmented data.
5. Scan uploaded Windows PE files with the hardened model without executing or retaining them.

RabbitMQ and Azure are planned after the local scientific workflow is validated.

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

Start the local backend with:

```powershell
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
files up to 25 MB. The API validates the DOS and PE signatures, parses the file in
memory, extracts the EMBER feature-version-2 vector, and scores all 2,381 values
with `artifacts/robust_lightgbm/model.txt`. It never launches the uploaded file.
The upload boundary accepts exactly one file, bounds the complete multipart body,
limits concurrent scans, and rejects pathological PE structures before feature
extraction. Browser scan POSTs must come from an explicitly configured CORS origin
and include `X-Aegis-Scan: static-pe-v1`; clients without an `Origin` header remain
supported for local CLI and server-to-server use.
`MALWARE_MAX_UPLOAD_BYTES` can set a 1-byte to 100-MB file limit, while
`MALWARE_MAX_CONCURRENT_SCANS` can set 1 to 32 in-flight scans (default: 4).

Completed scan metadata is stored under `data/scans/`; the uploaded binary is not
written there or retained after scoring. Metadata files are committed with an
atomic replace so readers never observe partial history entries. Each result includes the SHA-256, model
probability and threshold, verdict, grouped model contributions, static indicators,
PE type, architecture, section/import counts, and scan duration.

The API exposes:

- `POST /api/v1/scans` — multipart PE upload and synchronous static scan.
- `GET /api/v1/scans` — recent metadata-only scan history.
- `GET /api/v1/scans/{scan_id}` — one persisted scan result.

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
