# Malware Classifier Robustness

This project evaluates the robustness of a static malware classifier using the EMBER feature
representation. It uses only offline research data and simulated feature-space perturbations;
it does not create, execute, or distribute malware.

## MVP scope

1. Train a LightGBM baseline on prepared EMBER features.
2. Evaluate standard classification metrics.
3. Apply safe, simulated feature perturbations to the held-out malware samples.
4. Measure the robustness impact and retrain with augmented data.

RabbitMQ and Azure are planned after the local scientific workflow is validated.

## Data contract

The local pipeline accepts CSV and Parquet feature tables. Each table must have a
binary `label` column (0 for benign, 1 for malware) and one or more numeric feature
columns, with no missing values. `split_feature_table` makes deterministic,
stratified train/validation/test partitions from a single prepared table; persist
the resulting partitions through your experiment workflow before model training.

## EMBER2024 MVP dataset

The first end-to-end experiment uses the official EMBER2024 `.NET` train and test
subsets plus the evasive-malware challenge set. Install and acquire them with:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
malware-data download --dataset-dir data/raw/ember2024-dotnet
malware-data verify --dataset-dir data/raw/ember2024-dotnet
python -m pip install -e ".[ember2024]"
malware-data vectorize --dataset-dir data/raw/ember2024-dotnet
```

The download command is idempotent and records file sizes and SHA-256 checksums in
`data/raw/ember2024-dotnet/manifest.json`. Dataset content remains excluded from Git.

## Repository layout

- `src/malware_robustness/`: application package.
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

## Branch delivery plan

| Branch | Purpose |
|---|---|
| `chore/project-scaffold` | Reproducible project foundation |
| `feature/data-pipeline` | Dataset loading, validation, and split handling |
| `feature/baseline-model` | Training and standard evaluation |
| `feature/robustness-evaluation` | Safe simulated perturbations and robustness metrics |
| `feature/adversarial-training` | Augmented training and comparison |
| `feature/rabbitmq-orchestration` | Optional distributed task workflow |
| `feature/azure-integration` | Optional cloud storage and execution support |

Each branch will be pushed for review and merged only after tests pass.
