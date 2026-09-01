# Data and artifact catalog

## 1. Purpose

This catalog identifies what the application reads and writes, whether it is committed, its
sensitivity, and its current lifecycle. It is not a substitute for an organizational data
classification or retention policy.

## 2. Committed inputs

| Path | Type | Purpose | Sensitivity |
|---|---|---|---|
| `configs/*.yaml` | Experiment configuration | Reproducible model/training settings | Low |
| `db/migrations/*.sql` | Database schema | Workflow, events, leases, and outbox constraints | Low |
| `docker/extractor/Dockerfile` | Build definition | Minimal disposable extractor image | Low |
| `docker/extractor/seccomp-profile.json` | Runtime policy | Companion deny-by-default syscall allowlist | Security configuration |
| `src/malware_robustness/` | Source | Backend, ML, scanner, adapters, runtime | Intellectual property |
| `frontend/` | Source and lock file | Dashboard and UI dependency graph | Intellectual property |
| `tests/` | Tests/fixtures | Contract and behavior validation | Usually low; review fixture provenance |
| `uv.lock`, `frontend/package-lock.json` | Dependency locks | Reproducible dependency resolution | Low |

No executable malware sample should be committed.

## 3. Generated research data

| Path | Producer | Contents | Git | Lifecycle |
|---|---|---|---|---|
| `data/raw/ember2018/` | `malware-data download` | Official feature JSONL, benchmark model, provenance manifest | Ignored | Manual retention/removal |
| `data/raw/ember_dataset_2018_2.tar.bz2` | Downloader | Verified source archive | Ignored | Manual retention/removal |
| `data/processed/representative/` | `malware-data prepare-sample` | Balanced train/validation/test Parquet | Ignored | Reproducible from raw input |
| `data/processed/*.parquet` | User pipeline | Generic prepared partitions | Ignored | Project-specific |

EMBER records are extracted features, not executable samples. They still constitute third-party
research data and may be subject to license, storage, or redistribution requirements.

## 4. Model and experiment artifacts

| Path | Producer/consumer | Contents |
|---|---|---|
| `artifacts/<experiment>/model.txt` | Training; experiment review | Native LightGBM model |
| `artifacts/<experiment>/metrics.json` | Training; API/dashboard | Clean evaluation metrics |
| `artifacts/<experiment>/robustness.json` | Robustness CLI; API/dashboard | Perturbation results |
| `artifacts/<experiment>/comparison.json` | Hardening CLI; API/dashboard | Baseline vs hardened deltas |
| `artifacts/robust_lightgbm/model.txt` | Hardening; scan runtime | Default production-candidate scanner model |

`artifacts/` is ignored by Git. A production model should be promoted through a versioned,
immutable, signed artifact store rather than copied ad hoc between hosts.

Model artifacts can encode sensitive training behavior and should be integrity-protected. Store
their cryptographic identity with release metadata.

## 5. Runtime data

### Quarantine

| Property | Local implementation | Azure implementation |
|---|---|---|
| Root | `data/quarantine/` | Configured private container |
| Key | Opaque server-generated object key | Opaque server-generated blob name |
| Mutation | Create once | Create/write one version; exact version sealed |
| Data | Original submitted PE bytes | Original submitted PE bytes |
| Public access | Private filesystem permissions | Public container access rejected |
| Retention | Manual | Storage policy/operator; app has no cleanup worker |

Quarantine is the highest-sensitivity application store. Access should be limited to the upload
capability, validation service, and extractor reader. Analysts should not need direct storage
access for ordinary result review.

### Public immutable results

Local root: `data/results/`.

Object keys are content-addressed:

```text
results/objects/sha256/<two-hex>/<manifest-sha256>.json
```

Claim keys bind a scan/release identity to one object:

```text
results/claims/<two-hex>/<identity-sha256>.json
```

The canonical manifest is limited to 256 KiB by default and 1 MiB by an absolute repository
bound. It contains result metadata and bounded observations, never the sample bytes or full
feature vector.

The Azure-compatible result repository implements the same create-only contract, but current
runtime composition uses the local result repository regardless of quarantine backend.

### Workflow state and events

| Store | Data |
|---|---|
| In-memory repository | Development workflow, events, leases, and outbox; lost on restart |
| PostgreSQL `scan_workflows` | Aggregate state, content identity, lease/fence, failure, result reference |
| PostgreSQL `scan_workflow_events` | Append-only transition/audit payloads |
| PostgreSQL `scan_workflow_outbox` | Metadata-only delivery intents and delivery state |

Database constraints reject common hostile-content field names in event/outbox JSON. This is a
guardrail; application reviews must still prevent sensitive strings or new aliases from entering
control-plane payloads.

### Legacy scan metadata

`data/scans/` stores JSON metadata produced by the synchronous compatibility scanner. The binary
is not intentionally retained by that repository. These records use a different response schema
and lifecycle from async workflows.

## 6. Transient data

| Location | Data | Control |
|---|---|---|
| Browser memory | Selected file, calculated SHA-256, upload grant, status/result | Cleared with page lifecycle; application does not intentionally persist it |
| API request stream | Scoped local quarantine upload chunks | Size/concurrency bounded; creation endpoint never receives file bytes |
| Extractor stdin | Framed metadata and exact sample bytes | Child/container lifetime only |
| Extractor stdout | Bounded strict feature/evidence envelope | Output size and schema bounded |
| Worker memory | Validated feature vector, model score, manifest | Process lifetime only |
| RabbitMQ | Nine allowlisted metadata fields | Persistent delivery, bounded retry/DLQ |

Core dumps are disabled for the container extractor command. Equivalent process-level controls
must be enforced for all production roles.

## 7. Data propagation matrix

| Data element | Browser | Edge | Quarantine | PostgreSQL | RabbitMQ | Extractor | Result |
|---|---:|---:|---:|---:|---:|---:|---:|
| File bytes | Yes | Upload stream only | Yes | No | No | Yes | No |
| Filename | Yes | Yes | Not required | Presentation/workflow context | No | No | Yes at job wrapper level |
| Sample SHA-256 | Yes after hashing | Yes | Verified | Yes | Yes | Yes | Yes |
| Object generation | No/optional | Yes | Yes | Yes | Yes | Input metadata | No |
| Upload capability/SAS | Yes | Issuer | Authorization only | No | No | No | No |
| 2,381 features | No | No | No | No | No | Produces | No |
| Static evidence | No before scan | Public read only | No | Result reference only | No | Produces | Yes, bounded |
| Model score/decision | No before scan | Public read only | No | Result reference only | No | No | Yes |

## 8. Retention status

The repository does not implement retention or secure deletion. Today:

- local quarantine remains until manually removed;
- local results remain until manually removed;
- in-memory workflow state disappears on restart;
- PostgreSQL rows persist indefinitely unless an operator applies policy;
- RabbitMQ dead-letter messages persist according to broker policy;
- datasets and artifacts persist until manually removed.

This mismatch can leave orphaned storage objects or workflows with missing objects if operators
delete directories independently.

## 9. Required retention design

A production design should define, by data class:

- owner and lawful purpose;
- classification and residency;
- default retention and maximum retention;
- legal-hold behavior;
- user/tenant deletion rights;
- deletion ordering and tombstone/reconciliation behavior;
- backup expiration;
- audit evidence;
- orphan detection;
- cryptographic erasure requirements.

Deletion jobs must reference exact opaque identities and revalidate that targets remain inside the
intended store. Never use filenames, unresolved globs, or broad directory deletion for hostile
content.

## 10. Git and sharing controls

`.gitignore` excludes virtual environments, Python caches, `.env`, all runtime data directories,
and artifacts. Before each commit:

```powershell
git status --short
git diff --check
```

Ignored status is a convenience, not a data-loss prevention control. Configure repository secret
scanning and artifact/sample detection in CI, and review patches for hashes, filenames, signed
URLs, embedded strings, and credentials.
