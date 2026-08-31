# Local development

## 1. Prerequisites

Install:

- Python 3.11 or newer;
- Node.js 22.13 or newer and npm;
- Git;
- optional Docker when testing the container extractor;
- sufficient disk space for EMBER2018 and generated artifacts.

The default local profile does not require PostgreSQL, RabbitMQ, Azure, or Hugging Face.

## 2. Backend setup on Windows PowerShell

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If PowerShell blocks activation, either adjust the current-user execution policy according to
your organization's policy or call `.\.venv\Scripts\python.exe` explicitly for each command.

Verify the package:

```powershell
python -c "from importlib.metadata import version; print(version('malware-robustness'))"
python -m pytest -q
ruff check .
```

## 3. Prepare a model

The scanner runtime expects:

```text
artifacts/robust_lightgbm/model.txt
```

If an approved artifact is already present, verify it:

```powershell
Test-Path artifacts/robust_lightgbm/model.txt
Get-FileHash artifacts/robust_lightgbm/model.txt -Algorithm SHA256
```

To build it from the documented dataset:

```powershell
malware-data download --raw-dir data/raw
malware-data verify --raw-dir data/raw
malware-data prepare-sample `
  --raw-dir data/raw `
  --output-dir data/processed/representative
malware-harden `
  --config configs/robust-lightgbm.yaml `
  --artifacts-dir artifacts
```

The download can be large and may take time. It is only required for model training and dataset
dashboard features, not for scanning once a compatible approved model exists.

## 4. Start the complete local backend

Enable local asynchronous processing and start the API:

```powershell
$env:MALWARE_RUNTIME_AUTO_PROCESS = "true"
malware-api
```

The process listens on `127.0.0.1:8000`. This profile uses:

- in-memory workflow state;
- local write-once quarantine;
- a fresh Python child process for extraction;
- local immutable result manifests.

Keep this terminal running. In another terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Start-Process http://127.0.0.1:8000/docs
```

If you only need the research dashboard and not file scanning, the API can start without a model,
but scan processing will report model unavailability.

## 5. Frontend setup

Open a second PowerShell terminal:

```powershell
Set-Location frontend
npm ci
$env:NEXT_PUBLIC_API_URL = "http://127.0.0.1:8000"
npm run dev
```

Open `http://localhost:3000`. The menu contains Scan, Overview, Datasets, Experiments,
Robustness, and Runs.

The backend's default CORS list includes both `http://localhost:3000` and
`http://127.0.0.1:3000`. If Vite chooses another port, add that exact origin through
`MALWARE_CORS_ORIGINS` and restart the API.

## 6. First-run verification

### Dataset and experiment views

The dashboard can load even when no dataset or experiment artifacts exist. Empty states are
expected until the corresponding generated files are available.

Check API responses directly:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/datasets/ember2018/status
Invoke-RestMethod http://127.0.0.1:8000/api/v1/experiments/baseline
Invoke-RestMethod http://127.0.0.1:8000/api/v1/experiments/robustness
Invoke-RestMethod http://127.0.0.1:8000/api/v1/experiments/comparison
```

### File scan

1. Select **Scan**.
2. Choose a controlled PE test file no larger than 25 MiB.
3. Select **Start static scan**.
4. Confirm the view progresses through create, upload, seal, extraction, scoring, policy, and
   publication.
5. Confirm the final result displays the manifest digest, analysis release, risk, decision,
   observed indicators, limitations, and non-execution statement.

Do not use uncontrolled live malware on a normal workstation. The local process boundary is for
development, not a containment guarantee.

## 7. Useful development commands

### Backend

```powershell
python -m pytest -q
ruff check .
malware-data --help
malware-train --help
malware-robustness --help
malware-harden --help
```

### Frontend

```powershell
Set-Location frontend
npm run build
npm run lint
npm run format -- --check
```

`npm run format` is backed by Oxfmt; check the local CLI help if the installed version uses a
different check flag. Do not run a write-format operation over unrelated user changes without
reviewing its scope.

## 8. Generated local directories

| Path | Contents | Safe to commit? |
|---|---|---|
| `data/raw/` | Downloaded EMBER archive, extracted JSONL, manifest | No |
| `data/processed/` | Prepared train/validation/test feature tables | No |
| `data/quarantine/` | Uploaded hostile sample bytes | Never |
| `data/results/` | Immutable public scan manifests | Normally no |
| `data/scans/` | Legacy scan metadata | Normally no |
| `artifacts/` | Models and experiment results | No; promote through an artifact process |

All are ignored by Git. Removing them destroys local state; no built-in recovery or retention
workflow exists.

## 9. Common problems

### Frontend opens but reports offline

The current dashboard probes dataset and three experiment endpoints as a group. Verify all four,
not only `/health`. Confirm `NEXT_PUBLIC_API_URL` and backend CORS.

### File selected but scan cannot start or finish

- Confirm the backend is running.
- Confirm `artifacts/robust_lightgbm/model.txt` exists.
- Confirm `MALWARE_RUNTIME_AUTO_PROCESS=true` was set before starting the API.
- Check backend logs for a safe terminal reason.
- Confirm the file is a PE32/PE32+ binary rather than an archive, installer wrapper unsupported by
  the parser, shortcut, text file, or zero-byte file.

### Scan remains queued

Local mode does not process automatically unless enabled. For the distributed profile, both
`malware-outbox` and `malware-worker` must be running and connected to the same PostgreSQL and
RabbitMQ environment.

### History vanishes after restart

This is expected with the default in-memory workflow repository. Quarantine/result files can
remain on disk even though the edge no longer reconstructs all presentation state.

### Browser rejects cross-origin request

Set the exact frontend origin:

```powershell
$env:MALWARE_CORS_ORIGINS = "http://localhost:3000"
malware-api
```

Wildcards are intentionally invalid.

### Dataset verification fails

Run the CLI verification to receive the precise archive/manifest/file error. A bad archive is not
automatically trusted or extracted. Preserve the failure details, then reacquire from the pinned
official URL.

## 10. Development data hygiene

- Use dedicated, access-controlled test directories.
- Do not sync quarantine to consumer cloud drives.
- Do not attach sample files to issues, chat, or source control.
- Treat filenames and embedded strings as potentially sensitive and attacker-controlled.
- Clear generated content through an approved, explicit retention procedure.
- Keep credentials out of `.env`, shell history, screenshots, and test fixtures committed to Git.
