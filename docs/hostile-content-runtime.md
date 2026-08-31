# Hostile-content runtime

This runtime implements the first production-oriented slice of the hostile-content platform.
It preserves the existing scientific/training workflow while moving user-supplied PE parsing out
of the edge API.

## Implemented boundaries

1. **Edge and intake**
   - Idempotent scan creation and a complete upload/seal/status HTTP contract.
   - Server-generated object identities, bounded upload capabilities, strict CORS/header guards,
     and independent size/SHA-256/PE sealing.
   - Local HMAC upload grants for development and managed-identity user-delegation SAS grants for
     private Azure block blobs.

2. **Durable orchestration**
   - The complete workflow state machine, optimistic versions, expiring worker leases, monotonic
     fencing tokens, append-only events, and atomic outbox intents.
   - A PostgreSQL DB-API adapter with tenant scoping and `FOR UPDATE SKIP LOCKED` outbox claims.
   - At-least-once RabbitMQ publication with publisher confirms, bounded retries, dead lettering,
     deterministic job nonces, and poison-message rejection.

3. **Disposable extraction**
   - Exact-generation object reads and host-side size/SHA-256 revalidation before parsing.
   - Strict framed stdin/stdout with bounded metadata, sample, result, and wall-time sizes.
   - A digest-pinned Docker runner with no network, read-only root, non-root UID, no capabilities,
     no privilege escalation, bounded CPU/memory/PIDs/files, and a no-exec tmpfs.
   - A companion deny-by-default seccomp profile under `docker/extractor/`.

4. **Trusted decision and results**
   - Fail-closed validation of exactly 2,381 finite EMBER-v2 values and bounded evidence.
   - Native LightGBM text-model loading, raw-margin prediction, deterministic logistic calibration,
     governed thresholds, and separate model-contributor/observed-evidence rails.
   - Canonical, create-only, content-hashed public manifests. File bytes and feature vectors cannot
     enter result storage.

## Local demonstration profile

Set `MALWARE_RUNTIME_AUTO_PROCESS=true` and start `malware-api`. Sealing schedules one local
outbox pass. The outbox invokes the same fenced analysis handler used by RabbitMQ, while extraction
runs in a fresh child process. This profile exists so the dashboard can display every lifecycle
stage and the final immutable result without external services.

Do not use process mode as the production parser boundary. Set
`MALWARE_EXTRACTOR_RUNNER=container` and provide a digest-pinned
`MALWARE_EXTRACTOR_IMAGE_REFERENCE`. A KVM/microVM runner should replace this adapter before
processing hostile content in a production threat model.

## Production processes

The API, outbox publisher, and worker must share PostgreSQL configuration. The worker and API must
also address the same quarantine store. Run `malware-outbox` and `malware-worker` independently;
neither process accepts file bytes from RabbitMQ.

Required PostgreSQL variables:

- `MALWARE_WORKFLOW_BACKEND=postgres`
- `MALWARE_DATABASE_URL`

Required RabbitMQ variables:

- `MALWARE_RABBITMQ_URL`
- `MALWARE_RABBITMQ_QUEUE`
- unique `MALWARE_OUTBOX_OWNER` and `MALWARE_WORKER_OWNER` values per replica

Azure variables:

- `MALWARE_QUARANTINE_BACKEND=azure`
- `MALWARE_AZURE_ACCOUNT_URL`
- `MALWARE_AZURE_QUARANTINE_CONTAINER`

Release/policy variables:

- `MALWARE_ANALYSIS_RELEASE_ID`
- `MALWARE_EXTRACTOR_IMAGE_DIGEST`
- `MALWARE_WORKER_IMAGE_DIGEST`
- `MALWARE_FEATURE_SCHEMA_ID`
- `MALWARE_FEATURE_SCHEMA_DIGEST`
- `MALWARE_POLICY_SNAPSHOT_ID`
- `MALWARE_BENIGN_THRESHOLD`, `MALWARE_MALICIOUS_THRESHOLD`, `MALWARE_HIGH_RISK_THRESHOLD`

These identities must name one immutable, reviewed release bundle. Neither the worker nor the
extractor resolves a `latest` model, schema, image, object generation, or result.

## Still required before production

- Replace the container runner with one-file/one-microVM isolation and prove teardown/scratch-disk
  destruction.
- Persist edge presentation/upload-reservation metadata so any API replica can complete a create
  or seal request after process restart.
- Store public results in the configured cloud result container and emit completion outbox events.
- Add tenant authentication, quotas, admission/backpressure states, cancellation/expiry
  reconciliation, retention deletion, audit export, tracing, metrics, and alerting.
- Build and sign a release manifest/SBOM, golden-vector compatibility corpus, calibration report,
  drift references, and rollback controls.
- Split extraction, scoring, finalization, and infrastructure retry queues when measured workload
  justifies them.

The current Docker boundary materially reduces risk but is not represented as a microVM. The
current default release digests are development identities and must be replaced by signed artifact
digests for production.
