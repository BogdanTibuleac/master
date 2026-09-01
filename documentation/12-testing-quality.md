# Testing and quality

## 1. Quality strategy

The backend test suite emphasizes strict boundary contracts and failure paths in addition to
normal model behavior. The frontend currently relies on a production build and linting; automated
UI tests are a known gap.

The principal validation layers are:

1. pure domain invariant tests;
2. adapter tests with fakes or temporary storage;
3. service orchestration tests;
4. FastAPI HTTP contract tests;
5. local end-to-end hostile-content runtime tests;
6. ML/data reproducibility tests;
7. frontend type/build and lint checks;
8. controlled manual scan verification.

## 2. Backend test inventory

The repository has 27 backend test modules.

### Data and ML

| Test module | Coverage |
|---|---|
| `test_config.py` | YAML parsing and experiment validation |
| `test_data.py` | CSV/Parquet contracts and deterministic stratified splits |
| `test_ember2018.py` | Download/verify/extract/manifest/vectorization/sample preparation |
| `test_preprocessing.py` | Feature preparation behavior |
| `test_modeling.py` | Training, thresholding, metrics, and artifact behavior |
| `test_robustness.py` | Safe perturbation scenarios and robustness metrics |
| `test_hardening.py` | Training-only augmentation and baseline/hardened comparison |

### Legacy scanner

| Test module | Coverage |
|---|---|
| `test_scans.py` | Multipart validation, PE checks, model integration, limits, metadata persistence |

### Hostile-content intake and workflow

| Test module | Coverage |
|---|---|
| `test_intake.py` | Write-once local quarantine, hashing, PE validation, identity conflicts |
| `test_upload_grants.py` | Scoped HMAC capabilities, expiry, tampering, binding |
| `test_azure_quarantine.py` | Exact Azure version and private-container behavior |
| `test_azure_sdk_integration.py` | Azure SDK-compatible composition |
| `test_workflows.py` | Legal transitions, leases, fencing, terminal immutability, outbox |
| `test_postgres_workflows.py` | PostgreSQL SQL/repository transaction and retrieval behavior |
| `test_workflow_outbox_adapter.py` | Workflow-to-delivery adapter semantics |
| `test_outbox_dispatcher.py` | Claims, confirms, retry/failure, stale-owner fencing |

### Queue, extraction, decision, and results

| Test module | Coverage |
|---|---|
| `test_scan_queue_contract.py` | Exact metadata allowlist, serialization, message properties, retry/DLQ behavior |
| `test_quarantine_extraction_reader.py` | Exact generation/size/SHA revalidation |
| `test_extraction_runtime.py` | Framing, strict JSON, bounds, child process/container command, timeouts |
| `test_decision_components.py` | Native LightGBM and calibrator adapters |
| `test_decision_service.py` | Release validation, calibration, thresholds, corroboration, limitations |
| `test_decision_runtime.py` | Immutable publication and workflow completion |
| `test_analysis_runtime.py` | Full worker task orchestration and failure transitions |

### API and composition

| Test module | Coverage |
|---|---|
| `test_hostile_content_api.py` | Create/upload/seal/status/history contracts and security headers |
| `test_hostile_content_auto_runtime.py` | Local async end-to-end automatic processing |
| `test_runtime_composition.py` | Allowed runtime combinations and concrete wiring |
| `test_backend_architecture.py` | Layering/import boundaries and application structure |

## 3. Standard backend gates

From the repository root with the development extra installed:

```powershell
python -m pytest -q
ruff check .
```

For more diagnostic output:

```powershell
python -m pytest -ra
```

The repository's Pytest configuration adds `src` to the import path and discovers tests under
`tests/`. Ruff targets Python 3.11, line length 100, and rule groups `E`, `F`, `I`, `B`, and `UP`.

### Last verified backend result

On 31 August 2026, the complete suite at the documented revision produced:

```text
296 passed, 1 skipped
```

One LightGBM deprecation warning was present. This is a point-in-time evidence record, not a
substitute for running the gates on every change.

## 4. Frontend gates

From `frontend/`:

```powershell
npm ci
npm run build
npm run lint
```

The production build checks TypeScript and Vinext/Vite integration. Oxlint scans the frontend.
The shared generated shadcn primitive set currently contains pre-existing full-suite lint
findings; scanner/business files should be linted cleanly, and generated-code policy should be
made explicit rather than ignoring all lint output.

There are no committed Vitest, React Testing Library, Playwright, or accessibility tests.

## 5. Documentation gates

For changes under `documentation/`:

- verify every relative Markdown link resolves;
- verify every path, command, endpoint, environment variable, and default against source;
- use `git diff --check` for whitespace errors;
- avoid putting secrets or real sample names/hashes in examples;
- distinguish implemented, development-only, adapter-available, and future behavior;
- update the review date when performing a full implementation audit.

## 6. Manual end-to-end acceptance test

Use a controlled benign PE fixture in the local profile:

1. Start the API with `MALWARE_RUNTIME_AUTO_PROCESS=true`.
2. Start the frontend with the local API URL.
3. Confirm `/health` returns `{"status":"ok"}`.
4. Create a scan and capture its opaque ID.
5. Upload, seal, and observe every lifecycle transition.
6. Confirm one terminal state is reached within the expected extraction timeout.
7. For `complete`, verify:
   - sample SHA-256 matches the local file;
   - release identities are populated;
   - calibrated score is in `[0, 1]`;
   - decision matches threshold/corroboration policy;
   - manifest digest is present;
   - `executed` is false;
   - no feature vector or binary is returned.
8. Restart the local API and document the expected in-memory history limitation.
9. Inspect `data/quarantine/` and `data/results/` only through approved local tooling and confirm
   neither is tracked by Git.

Run hostile or parser-fuzzing samples only inside the approved stronger isolation environment.

## 7. Distributed acceptance tests still needed

Before a production deployment, automate tests for:

- PostgreSQL migrations against a real supported server;
- multi-publisher `SKIP LOCKED` and fencing races;
- RabbitMQ publisher confirms, broker restart, retry, and dead-letter replay policy;
- Azure user-delegation SAS, CORS, versioning, overwrite conflicts, and exact-version reads;
- API replica restart/failover and presentation reconstruction;
- worker crash at every state boundary;
- duplicate and reordered task delivery;
- immutable result conflict and storage corruption detection;
- container/microVM network denial, credential absence, syscall policy, and resource exhaustion;
- authenticated tenant isolation, quota, and authorization matrix;
- retention, expiry, legal hold, and deletion reconciliation.

## 8. Frontend test backlog

Recommended minimum suite:

- unit tests for response normalization, digest formatting, verdict mapping, and status parsing;
- component tests for file validation, lifecycle, terminal errors, empty result sections, and
  collapsed navigation;
- integration tests for create/upload/seal/poll and rejection of protocol downgrades;
- Playwright tests for all six views at desktop and mobile widths;
- accessibility checks with keyboard traversal and axe-compatible tooling;
- contract fixtures generated from strict backend schemas;
- tests confirming raw file bytes, SAS URLs, and capabilities never enter local storage or logs.

## 9. Release quality checklist

- [ ] Backend tests pass with no unexplained skip or warning increase.
- [ ] Ruff passes.
- [ ] Frontend production build passes.
- [ ] Scanner-specific lint passes; full lint findings are reviewed.
- [ ] Database migration is tested forward on a supported PostgreSQL version.
- [ ] Model and image hashes match release metadata.
- [ ] Controlled end-to-end scan passes in the target runtime profile.
- [ ] Threat model and configuration reference match the release.
- [ ] No generated data, quarantine content, credentials, or artifacts are staged in Git.
- [ ] Rollback, retention, and incident procedures are reviewed.
