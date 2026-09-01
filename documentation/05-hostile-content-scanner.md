# Hostile-content scanner reference

## Table of contents

1. [Quick reference](#quick-reference)
2. [Purpose](#purpose)
3. [Tool type and data model](#tool-type-and-data-model)
4. [Data sources and storage](#data-sources-and-storage)
5. [Configuration](#configuration)
6. [Runtime modes](#runtime-modes)
7. [Downloads and updates](#downloads-and-updates)
8. [Runtime flow](#runtime-flow)
9. [What the scanner checks](#what-the-scanner-checks)
10. [Validation commands](#validation-commands)
11. [Output contract](#output-contract)
12. [Troubleshooting](#troubleshooting)
13. [Security and interpretation limits](#security-and-interpretation-limits)

## Quick reference

| Item | Value |
|---|---|
| Scanner category | Static PE malware triage and ML classification |
| Input | One Windows PE file, default maximum 25 MiB |
| Execution behavior | File is never intentionally executed |
| Feature schema | EMBER-v2, exactly 2,381 finite numeric values |
| Model | Native LightGBM text model |
| Default model path | `artifacts/robust_lightgbm/model.txt` |
| Preferred protocol | `X-Aegis-Scan: hostile-content-v1` |
| Local API | `http://127.0.0.1:8000` |
| Frontend | `http://localhost:3000` |
| Quarantine | `data/quarantine/` locally, or a private versioned Azure Blob container |
| Public results | `data/results/` as immutable content-addressed JSON |
| External scan-time database | None |
| Network required while scanning locally | No |
| Local start | Rancher stack plus an explicitly configured host worker |

## Purpose

The scanner provides a bounded static assessment of a suspicious Windows PE. It is designed to
answer whether the file's static structure and learned EMBER-v2 representation resemble the
training distribution for malware, and to expose relevant structural observations to a human
reviewer.

It is not an antivirus engine, vulnerability scanner, source-code analyzer, YARA engine, or
behavioral sandbox. It does not name malware families and does not prove a low-risk file is safe.

## Tool type and data model

### Classifier

The classifier is a LightGBM binary model loaded from its native text format. The trusted worker
requests the raw model margin and applies the configured binary logistic calibrator to produce a
risk value in `[0, 1]`.

The model input is the fixed EMBER-v2 layout:

- byte histogram;
- byte-entropy histogram;
- printable-string statistics;
- general PE metadata;
- COFF and optional-header fields;
- section statistics;
- hashed imports;
- hashed exports;
- data-directory values.

The complete vector must contain exactly 2,381 finite values. Unknown, missing, extra, Boolean,
non-numeric, `NaN`, and infinite values are rejected.

### Evidence model

Semantic observations are generated independently from the model score. Each observation has a
bounded indicator ID, family, severity, and summary. A maximum of 32 evidence items can cross the
trusted envelope boundary; the current PE observation extractor emits at most eight.

Model contributors and observed indicators are different result fields. The trusted runtime is
currently composed without an explainer, so contributor output is normally empty and
`explanation_status` is `not_requested`.

### Decision policy

Default thresholds are:

| Range | Result |
|---|---|
| `risk < 0.20` | `likely_benign`, unless extractor quality warnings force review |
| `0.20 <= risk < 0.60` | `needs_review` |
| `0.60 <= risk < 0.90` | `likely_malicious` |
| `risk >= 0.90` | `high_risk` only with at least two distinct high/critical evidence families; otherwise `likely_malicious` |

This prevents a high model score alone from being presented as the strongest policy decision.

## Data sources and storage

### Model and feature schema

| Data | Source | Storage | Update behavior |
|---|---|---|---|
| LightGBM model | Output of `malware-harden` or an approved release process | `artifacts/robust_lightgbm/model.txt` | Replaced only as part of an explicitly identified release |
| Feature schema | EMBER feature version 2 implemented in source | Python package and immutable configured digest | Changes require coordinated extractor/model/release changes |
| Calibrator | Built-in binary logistic v1 adapter | Trusted worker code | Versioned by `calibrator_id` |
| Policy | Environment thresholds plus `MALWARE_POLICY_SNAPSHOT_ID` | Worker configuration/result provenance | Restart with a new snapshot identity when policy changes |
| Static indicators | Built-in bounded PE inspection rules | `pe_features.py` | Code release only |

There is no signature, CVE, reputation, IOC, YARA, template, or threat-intelligence database to
download for scanner operation. Scan-time behavior is deterministic from the bytes and pinned
release inputs.

### Uploaded samples

Local quarantine uses opaque server-generated keys under `data/quarantine/`. An HMAC capability
is bound to tenant, scan, object key, generation, and expiry. The upload is create-only and the
seal operation verifies exact size, SHA-256, `MZ`, and PE signature.

Azure mode uses a private, versioned Block Blob container. The API issues an HTTPS user-delegation
SAS scoped to create/write one blob for at most 15 minutes. Public containers, overwrites,
multiple unexpected versions, and mutable latest-version reads are rejected.

### Results

Public result objects are canonical JSON. Local keys have the form:

```text
data/results/results/objects/sha256/<first-two-hex>/<manifest-digest>.json
data/results/results/claims/<first-two-hex>/<scan-release-identity>.json
```

Objects are create-only and are verified against their digest on every repository read. The
public manifest contains no raw sample bytes and no 2,381-value feature vector.

### Generated versus committed data

`data/raw/`, `data/processed/`, `data/quarantine/`, `data/results/`, `data/scans/`, and
`artifacts/` are generated and ignored by Git. Scanner source, experiment configuration,
database migrations, and the extractor container definition are committed.

## Configuration

The most relevant scanner variables are:

| Variable | Default | Purpose |
|---|---|---|
| `MALWARE_MAX_UPLOAD_BYTES` | `26214400` | Accepted file bytes; valid range 1 byte to 100 MiB |
| `MALWARE_MAX_CONCURRENT_SCANS` | `4` | Concurrent guarded scan/upload requests; range 1–32 |
| `MALWARE_RUNTIME_AUTO_PROCESS` | `false` | Run the local outbox and analysis handler after seal |
| `MALWARE_QUARANTINE_BACKEND` | `local` | `local` or `azure` |
| `MALWARE_WORKFLOW_BACKEND` | `memory` | `memory` or `postgres` |
| `MALWARE_EXTRACTOR_RUNNER` | `disabled` | `disabled`, development-only `process`, or `container` |
| `MALWARE_EXTRACTOR_CONTAINER_CLI` | `docker` | `docker` or Rancher Desktop `nerdctl` |
| `MALWARE_ANALYSIS_RELEASE_ID` | deterministic local SHA-256 identity | Immutable release identifier |
| `MALWARE_FEATURE_SCHEMA_ID` | `ember-v2/2381` | Human-readable schema identity |
| `MALWARE_BENIGN_THRESHOLD` | `0.2` | Upper boundary for likely benign |
| `MALWARE_MALICIOUS_THRESHOLD` | `0.6` | Malicious decision boundary |
| `MALWARE_HIGH_RISK_THRESHOLD` | `0.9` | High-risk score boundary |
| `MALWARE_POLICY_SNAPSHOT_ID` | `static-pe-policy/local-v1` | Policy provenance string |

All runtime variables are documented in [Configuration reference](08-configuration-reference.md).

## Runtime modes

### Local asynchronous mode

Use this mode for development and demonstrations:

```powershell
$env:MALWARE_RUNTIME_AUTO_PROCESS = "true"
$env:MALWARE_EXTRACTOR_RUNNER = "process"
$env:MALWARE_ALLOW_UNSAFE_PROCESS_EXTRACTOR = "true"
malware-api
```

It uses in-memory workflows, local quarantine/results, and a same-host child process. It follows
the same create/upload/seal/result contracts but bypasses RabbitMQ. It is **development-only** and
must never be used for untrusted samples outside controlled fixtures.

### Distributed mode

Use PostgreSQL for workflow state and RabbitMQ for delivery:

```powershell
$env:MALWARE_WORKFLOW_BACKEND = "postgres"
$env:MALWARE_DATABASE_URL = "postgresql://scanner:secret@db.example/aegis"
$env:MALWARE_RABBITMQ_URL = "amqps://scanner:secret@mq.example/aegis"

malware-api
malware-outbox
malware-worker
```

Each command is a separate long-running process. PostgreSQL migrations must be applied first.

### Azure direct-upload mode

Set:

```powershell
$env:MALWARE_QUARANTINE_BACKEND = "azure"
$env:MALWARE_AZURE_ACCOUNT_URL = "https://account.blob.core.windows.net"
$env:MALWARE_AZURE_QUARANTINE_CONTAINER = "quarantine"
```

`DefaultAzureCredential` resolves the service identity. The Blob account and container must have
versioning enabled, public access disabled, and browser CORS configured for the dashboard origin.
Local auto-processing cannot be combined with Azure quarantine.

### Container extractor mode

Set a digest-pinned image reference:

```powershell
$env:MALWARE_EXTRACTOR_RUNNER = "container"
$env:MALWARE_EXTRACTOR_IMAGE_DIGEST = "sha256:<64-lowercase-hex>"
$env:MALWARE_EXTRACTOR_IMAGE_REFERENCE = "registry.example/aegis-extractor@sha256:<same-hex>"
$env:MALWARE_EXTRACTOR_CONTAINER_CLI = "nerdctl" # Rancher Desktop
```

The runner uses `--pull=never`, no network, a read-only root, non-root UID/GID 65534, no Linux
capabilities, `no-new-privileges`, a validated deny-by-default seccomp profile,
PID/memory/CPU/file limits, and a `noexec` temporary filesystem. It re-hashes the configured
seccomp file before every launch and fails closed if the profile changes.

## Downloads and updates

### Scanner operation

The scanner does not download rules or databases at startup or per scan. It can operate offline
once Python dependencies, the model artifact, and optional container image are present.

### Model update

A model update should be handled as a release, not as an in-place mutable file replacement:

1. Reproduce data preparation and training from a versioned YAML configuration.
2. Review clean and robustness metrics.
3. place the approved native model at the configured artifact path;
4. calculate and record immutable model/image/schema identities;
5. assign a new `MALWARE_ANALYSIS_RELEASE_ID`;
6. deploy workers and edge configuration coherently;
7. retain enough provenance to reproduce the result.

The current local composition hashes the model into `model_id`; release promotion and artifact
signing are not automated.

### EMBER data update

Research data acquisition is independent of scan-time operation. See
[ML and data pipeline](07-ml-data-pipeline.md). The command downloads the official archive from
Elastic, resumes through a `.part` file, verifies the pinned SHA-256, safely extracts it, and
writes a local manifest.

## Runtime flow

1. The client creates a scan with declared filename, byte size, media type, and idempotency key.
2. The edge creates `AWAITING_UPLOAD` and returns a short-lived write capability.
3. The browser uploads directly to local or Azure quarantine.
4. The browser calculates SHA-256 and sends a seal request.
5. The intake service independently verifies exact generation, size, SHA-256, and PE identity.
6. The workflow commits immutable content identity and a transactional outbox intent.
7. The publisher sends a strict metadata-only task.
8. The worker obtains a fenced lease and re-verifies the exact quarantined object.
9. A disposable extractor parses the bytes and writes one bounded framed JSON envelope.
10. The trusted worker rejects malformed, oversized, incomplete, or non-finite output.
11. LightGBM computes a raw margin and the calibrator produces risk.
12. Policy combines risk, extraction quality, and corroborating evidence families.
13. A canonical immutable manifest is persisted and referenced by the completed workflow.
14. The browser polls status and renders only public result fields.

## What the scanner checks

The ML model consumes the full EMBER representation. Separately, the evidence extractor can
surface these static observations:

| Observation | Example trigger | Interpretation |
|---|---|---|
| Known packer section | Section name resembles UPX, ASPack, or MPRESS | Packing can conceal code; legitimate software may also be packed |
| High section entropy | Entropy at least 7.2 | May indicate compression, encryption, or packed content |
| Writable and executable section | PE flags include write and execute | Weakens memory protections and can support unpacking/self-modification |
| Process-injection APIs | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection`, `QueueUserAPC` | APIs commonly used in injection chains; imports alone do not prove use |
| Persistence APIs | `CreateServiceA/W` or `schtasks` references | Can support service or scheduled-task persistence |
| Registry modification | Registry-writing APIs or registry path references | May indicate configuration or persistence behavior |
| Network/download APIs | Network or download-related imports | Indicates network capability, not necessarily malicious intent |
| Anti-analysis APIs | Debugger or analysis-detection imports | May indicate evasion behavior |
| Embedded URL | Printable content contains URL-like text | Potential network endpoint or benign embedded resource |
| Missing Authenticode table | No certificate data-directory entry | Absence of a signature is contextual evidence, not proof of malware |
| Large overlay | More than 20% of file or 256 KiB | May contain appended payload/configuration or legitimate installer data |
| Unusual timestamp | zero, before 1995, or more than one year in the future | May indicate tampering, reproducible build output, or malformed metadata |

The parser bounds sections to 96, optional-header bytes to 1,024, import libraries to 2,048,
import symbols to 65,536, exports to 8,192, symbol names to 1,024 bytes, and printable fragments
to 100,000. PE32 and PE32+ are supported.

## Validation commands

### Verify API liveness

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Verify model presence

```powershell
Test-Path artifacts/robust_lightgbm/model.txt
Get-FileHash artifacts/robust_lightgbm/model.txt -Algorithm SHA256
```

### Run scanner-focused backend tests

```powershell
python -m pytest -q `
  tests/test_scans.py `
  tests/test_hostile_content_api.py `
  tests/test_hostile_content_auto_runtime.py `
  tests/test_extraction_runtime.py `
  tests/test_decision_runtime.py
```

### Validate the complete backend

```powershell
python -m pytest -q
ruff check .
```

### Validate the frontend

```powershell
Set-Location frontend
npm ci
npm run build
```

### Manual browser check

Open `http://localhost:3000`, select **Scan**, choose a valid PE within the configured limit,
start the scan, and confirm the lifecycle reaches a terminal state. A successful result should
show a decision, calibrated risk, manifest digest, release identities, indicators, limitations,
and `executed=false` provenance.

## Output contract

The public result uses schema `static-pe-result/v1`. Its major sections are:

| Field | Meaning |
|---|---|
| `manifest_schema` | Public schema identity |
| `manifest_digest` | SHA-256 over canonical manifest content |
| `analysis_status` | `complete` or `inconclusive` |
| `sample_digest` | Sealed sample SHA-256 when available |
| `job_nonce` | Queue/workflow attempt identity |
| `release` | Analysis, extractor, worker, feature schema, model, and calibrator identities |
| `extraction` | Completeness and bounded warnings |
| `prediction` | Raw margin and calibrated risk for complete analysis |
| `decision` | Label, policy identity, corroborating families, and reason codes |
| `observed_indicators` | Independently observed bounded static evidence |
| `model_contributors` | Optional model-space attribution, currently not requested |
| `explanation_status` | `available`, `unavailable`, or `not_requested` |
| `limitations` | Required caveats and quality/policy limitations |
| `executed` | Always `false` |

An inconclusive result cannot contain a trusted prediction. A complete non-inconclusive result
must contain one.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Scan button returns model unavailable | `artifacts/robust_lightgbm/model.txt` is absent or invalid | Run the hardening workflow or place an approved native model at the exact path, then restart |
| Upload succeeds but scan remains queued locally | `MALWARE_RUNTIME_AUTO_PROCESS` is false | Enable it for local development or run PostgreSQL/RabbitMQ publisher and worker |
| Browser reports network failure | Backend is down, API URL is wrong, or CORS origin is missing | Check `/health`, `NEXT_PUBLIC_API_URL`, and `MALWARE_CORS_ORIGINS` |
| Azure upload blocked by browser | Blob service CORS is not configured for the dashboard origin | Add the exact origin and required PUT headers in the storage account CORS policy |
| Azure settings rejected at startup | URL contains credentials/path/query or container is absent | Use a credential-free HTTPS account origin and configure the container separately |
| Container mode rejected | Image reference is not pinned to the configured digest | Set reference as `name@sha256:<digest>` and use the same digest variable |
| Seal returns conflict | Size/hash/generation differs, object was overwritten, or workflow already advanced | Do not retry with altered identity; create a new scan for different content |
| Valid file is rejected as not PE | Missing/invalid `MZ`, PE offset, or `PE\0\0` signature | Confirm the input is a supported PE32/PE32+ file rather than an archive or shortcut |
| Result is `inconclusive` | Extraction envelope failed completeness/quality requirements | Inspect terminal reason and server logs; do not reinterpret it as benign |
| History disappears after restart | Default workflows and presentation context are in memory | Use PostgreSQL and complete persistent presentation reconstruction before production |
| Full frontend lint reports UI primitive findings | Generated shadcn components contain existing lint patterns | Keep scanner files clean and review/suppress generated-code findings deliberately |

## Security and interpretation limits

- Static analysis cannot observe runtime-only behavior, decrypted payloads, command-and-control
  traffic, or environment-triggered actions.
- Packers, signatures, imports, URLs, entropy, and timestamps are contextual indicators with
  legitimate and malicious uses.
- A model can be evaded, drift from current malware, or be confidently wrong.
- The local child-process mode is not a production sandbox.
- The container boundary reduces exposure but shares a host kernel; a hardened microVM or
  separate analysis host is the recommended stronger boundary.
- Authentication, authorization, quotas per user/tenant, retention enforcement, audit export,
  and centralized monitoring are not implemented.
- Quarantined samples remain stored until an operator removes them; there is no automatic
  retention service.
- The strongest `high_risk` label requires semantic corroboration, but all labels still require
  analyst judgment and defense-in-depth controls.
