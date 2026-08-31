# Backend design

## 1. Package structure

The Python package is under `src/malware_robustness/`. The design uses explicit layers instead
of placing transport, business logic, and persistence in one module.

```text
src/malware_robustness/
├── api/             FastAPI application, dependency wiring, middleware
├── core/            Environment-backed runtime settings
├── domain/          Entities, value objects, protocols, invariants
├── integrations/    External SDK composition, currently Azure Blob
├── queues/          RabbitMQ queue adapter
├── repositories/    Local, PostgreSQL, Azure, and artifact adapters
├── routes/          HTTP endpoint handlers
├── schemas/         Pydantic HTTP and public-result schemas
├── services/        Transport-independent application workflows
├── runtime_*.py     Publisher/worker entry points and process composition
├── worker.py        RabbitMQ worker loop
└── ML modules       Data, EMBER, training, robustness, and hardening
```

The intended dependency direction is:

```text
routes -> services -> domain contracts
                    -> repository/queue protocols

repository and integration adapters -> domain contracts
runtime composition -> all concrete implementations
```

## 2. HTTP layer

### `api/app.py`

`create_app()` constructs FastAPI, installs middleware, configures explicit CORS origins, and
registers the four route groups. Passing `BackendSettings` directly creates a deterministic app
for tests; the module-level app loads settings from the environment.

The API enables only `GET`, `POST`, and `PUT` through CORS and allows the headers required by the
two scan protocols. Credentials are disabled. CORS is a browser control, not authentication.

### `api/middleware.py`

`ScanUploadGuardMiddleware` rejects oversized scan requests and limits concurrent upload/scan
requests before expensive parsing or inference. The configured multipart allowance is the file
limit plus 64 KiB of envelope overhead.

### `routes/`

| Module | Responsibility |
|---|---|
| `health.py` | Process liveness response at `GET /health` |
| `datasets.py` | EMBER status, archive verification, and smoke test |
| `experiments.py` | Read latest baseline, robustness, and comparison artifacts |
| `scans.py` | Async hostile-content create/upload/seal/status/history and legacy synchronous scan |

Routes translate transport errors and status codes. They do not construct database connections,
parse model files, or access storage directly.

## 3. Application services

| Service module | Main responsibility |
|---|---|
| `services/platform.py` | Hostile-content edge orchestration: create, grant, upload, seal, retrieve, and local processing |
| `services/workflows.py` | Legal state transitions and outbox intent creation |
| `services/intake.py` | Write-once quarantine upload and exact size/hash/PE validation |
| `services/upload_capabilities.py` | Local HMAC capability creation and verification |
| `services/azure_upload_grants.py` | User-delegation SAS grants for one private Azure blob |
| `services/outbox.py` | Fenced, retryable outbox dispatch |
| `services/extraction_runtime.py` | Process/container launch and strict framed envelope parsing |
| `services/analysis_runtime.py` | Task validation, exact object read, lifecycle transitions, extraction, and decision call |
| `services/decision.py` | Envelope validation, model score, calibration, policy, explanation, and manifest construction |
| `services/decision_runtime.py` | Immutable result publication and workflow completion |
| `services/scans.py` | Local-only synchronous compatibility scanner |
| `services/datasets.py` | Dataset status, verification, and smoke-test use cases |
| `services/experiments.py` | Artifact discovery and presentation for the dashboard |

Services expose domain-oriented methods so they can be called from HTTP handlers, background
tasks, or worker processes without duplicating rules.

## 4. Domain model

The `domain/` package contains the invariants that must remain true regardless of transport or
storage implementation.

### Workflow domain

`domain/workflows.py` defines scan states, content identities, result references, leases,
events, and the repository protocol. It enforces:

- opaque bounded identities;
- legal state transitions only;
- immutable committed content identity;
- immutable terminal state;
- optimistic version checks;
- lease ownership and fencing.

### Analysis domain

`domain/analysis.py` defines the trust boundary between extraction and scoring:

- exact EMBER-v2 feature count of 2,381;
- finite numeric values only;
- bounded evidence and warning counts;
- strict evidence types and severities;
- immutable analysis release identities;
- ordered policy thresholds;
- canonical public result manifests;
- `executed=false` as a mandatory invariant.

### Intake and queue domains

`domain/intake.py` defines opaque object identities, upload receipts, and sealed content.
`domain/scan_jobs.py` defines the metadata-only queue schema. These contracts intentionally make
it impossible to represent sample bytes or feature vectors in a normal queue task.

## 5. Repository layer

| Adapter | Backing store | Role |
|---|---|---|
| `repositories/workflows.py` | Memory | Development workflow/events/outbox implementation |
| `repositories/postgres_workflows.py` | PostgreSQL | Durable workflow, event, lease, and outbox implementation |
| `repositories/quarantine.py` | Filesystem | Private, opaque, write-once local sample storage |
| `repositories/azure_quarantine.py` | Azure Blob | Exact-version hostile-object reads and validation |
| `repositories/results.py` | Filesystem or Azure-compatible blob client | Canonical immutable result objects and claims |
| `repositories/scans.py` | Filesystem | Metadata persistence for the legacy synchronous scanner |
| `repositories/datasets.py` | Filesystem | EMBER dataset status and verification adapter |
| `repositories/experiments.py` | Filesystem | Latest completed experiment artifact discovery |
| `repositories/decision_components.py` | Native files/in-memory logic | LightGBM model and calibrator adapters |
| `repositories/outbox_delivery.py` | Workflow repository adapter | Outbox claim/complete/fail port used by publisher |

Repository APIs accept validated identities rather than raw user paths. Filesystem adapters
resolve generated paths under configured roots, reject unsafe path traversal, and use
create-only or exact-read behavior where immutability matters.

## 6. Runtime composition

`runtime_composition.py` is the concrete dependency assembly point.

### API composition

- selects in-memory or PostgreSQL workflows;
- selects local or Azure quarantine;
- creates upload grants for the selected quarantine backend;
- uses `LocalResultRepository` for public manifests;
- loads `artifacts/robust_lightgbm/model.txt`;
- creates process or container extraction runner;
- constructs the edge service and optional local auto-processing handler.

### Publisher composition

`malware-outbox` requires PostgreSQL. It builds a PostgreSQL outbox adapter and a RabbitMQ queue
publisher. Publisher confirms are required before a claim is marked delivered.

### Worker composition

`malware-worker` requires PostgreSQL. It consumes RabbitMQ tasks with manual acknowledgements,
loads the same runtime release configuration, retrieves the exact quarantine object, invokes
the extractor, publishes the immutable result, and persists a terminal transition before ACK.

## 7. Validation boundaries

The system validates the same identity at multiple independent boundaries:

1. The client declares filename, content type, and size during creation.
2. The quarantine adapter accepts no more than the configured bytes.
3. Seal recomputes exact size and SHA-256 and verifies `MZ` and PE identity.
4. The task contract validates a strict, exact set of fields.
5. The worker reopens the exact object generation and recomputes size and SHA-256.
6. The extractor emits a framed JSON object with strict field and size bounds.
7. The trusted decision service validates 2,381 finite values and bounded evidence.
8. The result repository revalidates the public schema and content digest on write and read.

No earlier validation makes a later trust boundary optional.

## 8. Error model

Application-specific exceptions carry safe public messages and HTTP status intent. The route
layer maps them to status codes without exposing internal paths, credentials, model internals,
or parser traces.

Typical classes are:

- validation errors: `400` or `422`;
- missing scan/object/result: `404`;
- state, identity, or write-once conflict: `409`;
- oversized request: `413`;
- scanner capacity or missing model: `503`;
- unexpected internal failure: generic `500` response with server-side logging.

The distributed worker distinguishes retryable delivery failures from poison tasks. Failed
attempts are bounded and can be dead-lettered rather than requeued indefinitely.

## 9. Persistence caveats

- The default workflow repository is in memory.
- `HostileContentService` keeps presentation and upload-grant context in process memory. Using a
  PostgreSQL workflow repository does not yet make every edge response field restart-safe.
- Local quarantine objects and local result manifests persist across restart, but no automatic
  reconciliation or retention worker is implemented.
- The Azure immutable-result adapter is implemented but is not selected by current environment
  settings or runtime composition.
- Legacy scan metadata is local JSON and is separate from async workflow records.

## 10. Adding a backend feature

For a normal feature:

1. Put durable rules and value validation in `domain/`.
2. Define or extend a repository protocol at the domain/service boundary.
3. Implement orchestration in `services/` without importing FastAPI.
4. Add a concrete adapter in `repositories/`, `queues/`, or `integrations/`.
5. Wire the adapter in `runtime_composition.py` or `api/dependencies.py`.
6. Define strict request/response schemas in `schemas/`.
7. Add a thin route in `routes/`.
8. Cover domain rules, adapter behavior, HTTP behavior, and failure paths with tests.

For a new extractor field, update the extractor and trusted envelope schema together. Do not
silently accept unknown fields, and do not place new hostile strings or feature vectors in
RabbitMQ or public result storage.

## 11. Naming note

The package retains the research name `malware_robustness`, while the dashboard presents the
product as Aegis. Renaming the Python distribution is not required for functionality, but a
future productization pass should choose one canonical product/package naming scheme.
