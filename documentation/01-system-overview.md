# System overview

## 1. Purpose

Aegis is a static malware-classification and robustness platform for Windows Portable
Executable (PE) files. It combines an ML research workflow with a hostile-content processing
runtime and a browser dashboard.

The application answers two different questions:

- **Model engineering:** How accurate and robust is a LightGBM classifier using EMBER-v2
  static features?
- **File triage:** Given one quarantined PE file, what calibrated risk and independently
  observed static indicators can be reported without executing that file?

The system intentionally keeps these concerns related but separate. Experiment artifacts
produce a model release; the runtime consumes a pinned native LightGBM artifact and produces a
strict public result manifest.

## 2. Capabilities available today

| Capability | Status | Notes |
|---|---|---|
| Acquire and verify EMBER2018 | **Implemented** | Downloads from Elastic, verifies a pinned SHA-256, safely extracts, and records provenance. No Hugging Face dependency exists. |
| Prepare representative feature partitions | **Implemented** | Streams source records and writes deterministic, class-balanced Parquet partitions. |
| Train LightGBM baseline | **Implemented** | Uses validation early stopping and optional validation-only threshold calibration. |
| Evaluate robustness | **Implemented** | Applies safe numeric feature-space perturbations to held-out malware rows. |
| Train hardened model | **Implemented** | Augments training data only and compares clean and perturbed performance. |
| Upload a PE file from the dashboard | **Implemented** | Supports `.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, and `.ocx` selections up to the configured limit. |
| Asynchronous quarantine and seal workflow | **Implemented** | Create, direct upload, exact size/SHA-256 verification, queue intent, extraction, scoring, policy, result publication. |
| Isolated static extraction | **Implemented** | Fresh child process locally; digest-pinned, networkless container runner available. |
| Immutable result manifests | **Implemented** | Canonical JSON, content SHA-256, create-only storage, no file bytes or feature vector. |
| Local web dashboard | **Implemented** | Scan, Overview, Datasets, Experiments, Robustness, and Runs views. |
| PostgreSQL workflow state | **Adapter available** | Migrations and repository are implemented; infrastructure and deployment configuration are required. |
| RabbitMQ delivery | **Adapter available** | Transactional outbox publisher and manually acknowledged worker are implemented. |
| Azure Blob direct quarantine upload | **Adapter available** | Private, versioned Block Blob with user-delegation SAS; Azure configuration is required. |
| Authentication and authorization | **Required before production** | The API currently has no user identity, role, or tenant authorization layer. |
| Behavioral sandboxing | Not implemented | Files are never executed by this application. |
| Signature/reputation scanning | Not implemented | No antivirus signature, YARA, certificate reputation, or threat-intelligence feed is queried. |

## 3. What a scan means

The scanner creates an assessment from:

1. A 2,381-value EMBER-v2 static feature vector extracted from the uploaded PE bytes.
2. A native LightGBM raw margin converted to a calibrated risk score.
3. A versioned threshold policy.
4. Bounded semantic observations such as high-entropy sections, writable/executable sections,
   suspicious API imports, URLs, packer names, and overlay size.

The result is one of:

| Decision | Default policy meaning |
|---|---|
| `likely_benign` | Risk below `0.20` and no extraction-quality warning prevents this decision. |
| `needs_review` | Risk from `0.20` to below `0.60`, or a low-risk result with quality warnings. |
| `likely_malicious` | Risk from `0.60` upward, including a high score without enough corroborating high-severity evidence families. |
| `high_risk` | Risk at least `0.90` plus at least two distinct high/critical evidence families. |
| `inconclusive` | A trusted prediction could not be produced from a valid complete extraction envelope. |

The thresholds are configurable, but their order is enforced. A scan manifest always states
`executed: false` and includes limitations explaining that static evidence is incomplete.

## 4. Runtime profiles

### 4.1 Local development profile

The default profile uses:

- in-memory workflow state;
- write-once files under `data/quarantine/`;
- immutable result JSON under `data/results/`;
- a fresh Python child process for extraction;
- optional in-process delivery when `MALWARE_RUNTIME_AUTO_PROCESS=true`;
- the frontend at `http://localhost:3000` and API at `http://127.0.0.1:8000`.

This profile demonstrates the end-to-end contract with minimal infrastructure. Workflow
presentation metadata and in-memory workflow state do not survive a process restart.

### 4.2 Distributed runtime profile

The distributed profile uses:

- PostgreSQL 15+ for workflow state, events, leases, and transactional outbox;
- RabbitMQ for strict metadata-only tasks;
- local or Azure Blob quarantine storage;
- a separate worker and disposable extractor;
- immutable result persistence.

The building blocks exist, but the repository does not yet provide deployment manifests,
infrastructure as code, centralized observability, authentication, or a complete retention
service. It must therefore be treated as an integration-ready runtime, not a production-ready
managed service.

## 5. Primary users

| User | Primary activity |
|---|---|
| Security analyst | Upload a suspicious PE, inspect verdict, indicators, limitations, and history. |
| ML engineer | Prepare EMBER data, train models, evaluate robustness, and compare hardening. |
| Backend engineer | Extend workflow, storage, extraction, scoring, and policy adapters. |
| Platform engineer | Configure PostgreSQL, RabbitMQ, Azure Blob, image identities, and process isolation. |
| Security reviewer | Verify trust boundaries, non-execution guarantees, evidence provenance, and residual risk. |

## 6. Important non-goals

The current implementation does not:

- execute submitted files;
- unpack or detonate content in a behavioral sandbox;
- establish that a low-risk file is safe;
- identify a malware family;
- query live threat intelligence, reputation services, CVE databases, YARA rules, or antivirus
  signatures;
- provide user accounts, API keys, roles, or tenant isolation at the HTTP boundary;
- automatically delete quarantined content or generated artifacts;
- expose scan cancellation, deletion, or resubmission APIs;
- deliver a production SLA.

## 7. Technology summary

| Area | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, Pydantic, Uvicorn |
| ML | LightGBM, NumPy, pandas, scikit-learn, PyArrow |
| PE parsing | `pefile` plus bounded native parsing for the extractor contract |
| Workflow persistence | In-memory repository or PostgreSQL via Psycopg |
| Queue | RabbitMQ via Pika |
| Object storage | Local filesystem or Azure Blob Storage |
| Frontend | React 19, TypeScript, Vinext/Vite, Tailwind CSS, shadcn/Base UI, Recharts |
| Tests and linting | Pytest, Ruff, Oxlint, TypeScript/Vite production build |

## 8. Success criteria for the current MVP

The MVP is successful when a developer can:

1. Verify or prepare EMBER-v2 feature data.
2. Train or supply `artifacts/robust_lightgbm/model.txt`.
3. Start the local backend with automatic processing enabled.
4. Start the frontend and upload a valid Windows PE file.
5. Observe the complete lifecycle and a content-hashed result manifest.
6. Reproduce model metrics and robustness comparisons from versioned configuration.

Production readiness has a higher bar. The required controls are tracked in
[Known limitations and roadmap](14-known-limitations-roadmap.md).
