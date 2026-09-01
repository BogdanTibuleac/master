# Rancher Desktop local stack

## Purpose

`compose.yaml` provides a local integration environment for the dashboard, API, PostgreSQL,
RabbitMQ, and transactional-outbox publisher. It is intended for Rancher Desktop or a compatible
Docker Compose runtime on one development workstation. It is not a production deployment.

The analysis worker is intentionally not a Compose service. It launches a fresh, unprivileged
extractor container for each sealed sample. Putting that worker in Compose would require mounting
the Docker/containerd control socket into it; that would turn the worker into an effectively
host-privileged process and weaken the hostile-content boundary.

## Services and trust boundaries

| Component | Runtime | Responsibility |
|---|---|---|
| `frontend` | Long-running container, port `3000` | Browser dashboard |
| `api` | Long-running non-root container, port `8000` | Workflow creation, scoped upload grants, sealing, and reads; never parses file bytes |
| `postgres` | Long-running container, port `5432` | Durable workflow, events, leases, and outbox state |
| `rabbitmq` | Long-running container, ports `5672` and `15672` | Metadata-only task delivery |
| `outbox` | Long-running container | Fenced transactional-outbox publisher |
| `malware-worker` | Host process | Reads exact quarantined object, launches extractor, validates envelope, scores, and writes result |
| extractor | Short-lived Rancher Docker container | Parses one sample with no network, no capabilities, read-only root, non-root UID, resource limits, and seccomp |

The extractor appears in Rancher Desktop only during a scan. It is removed immediately after the
framed extraction result is collected, whether the scan succeeds or fails.

## Prerequisites

1. Start Rancher Desktop and wait until its container engine is running.
2. Ensure its Docker client can reach the engine:

   ```powershell
   & "C:\Program Files\Rancher Desktop\resources\resources\win32\bin\docker.exe" version
   ```

   If the server version is absent, Rancher Desktop has not finished starting its Moby container
   runtime. Start or reset the runtime from Rancher Desktop, then rerun the command. The
   repository cannot start containers until that succeeds.
3. Install Python 3.11+ and Node.js 22+ for the host worker and local diagnostics.
4. Place the approved model at `artifacts/robust_lightgbm/model.txt`. The stack can start without
   it, but a worker cannot complete a scan without a compatible model artifact.

## Start the long-running services

From the repository root:

```powershell
Copy-Item .env.example .env
# Replace all placeholder values in .env with local secrets before starting.

$rdDocker = "C:\Program Files\Rancher Desktop\resources\resources\win32\bin\docker.exe"
& $rdDocker compose -f compose.yaml up --build -d
& $rdDocker compose -f compose.yaml ps
```

Open the dashboard at `http://localhost:3000`, API health at
`http://127.0.0.1:8000/health`, API documentation at `http://127.0.0.1:8000/docs`, and the local
RabbitMQ management UI at `http://127.0.0.1:15672`. Ports bind only to loopback.

The PostgreSQL initialization scripts run only when `postgres-data` is first created. To apply
future schema migrations, use the project migration procedure rather than assuming an existing
volume reruns `db/migrations/` automatically.

## Build and configure the disposable extractor

Build the extractor image locally after Rancher Desktop is ready:

```powershell
$rdDocker = "C:\Program Files\Rancher Desktop\resources\resources\win32\bin\docker.exe"
& $rdDocker build --tag aegis-extractor:local --file docker/extractor/Dockerfile .
$extractorDigest = (& $rdDocker image inspect --format '{{.Id}}' aegis-extractor:local).Trim()
$extractorDigest
```

`$extractorDigest` must be a `sha256:` value with 64 lowercase hexadecimal characters. For a
shared registry, use a repository digest instead, for example
`registry.example/aegis-extractor@sha256:<digest>`. Tags such as `latest` are rejected by the
application.

Open a new PowerShell terminal for the host worker. It must use the same checked-out repository,
the same `data/` directory, and the same `.env` values as Compose:

```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^(?<name>[A-Z0-9_]+)=(?<value>.*)$') {
    Set-Item -Path "Env:$($matches.name)" -Value $matches.value
  }
}

$env:MALWARE_WORKFLOW_BACKEND = "postgres"
$env:MALWARE_DATABASE_URL = "postgresql://aegis:$env:POSTGRES_PASSWORD@127.0.0.1:5432/aegis"
$env:MALWARE_RABBITMQ_URL = "amqp://aegis:$env:RABBITMQ_PASSWORD@127.0.0.1:5672/%2F"
$env:MALWARE_QUARANTINE_BACKEND = "local"
$env:MALWARE_DATA_DIR = (Resolve-Path data\raw)
$env:MALWARE_SCAN_DIR = (Resolve-Path data\scans)
$env:MALWARE_QUARANTINE_DIR = (Resolve-Path data\quarantine)
$env:MALWARE_RESULT_DIR = (Resolve-Path data\results)
$env:MALWARE_ARTIFACT_DIR = (Resolve-Path artifacts)
$env:MALWARE_EXTRACTOR_RUNNER = "container"
$env:MALWARE_EXTRACTOR_CONTAINER_CLI = "docker"
$env:MALWARE_EXTRACTOR_IMAGE_DIGEST = $extractorDigest
$env:MALWARE_EXTRACTOR_IMAGE_REFERENCE = $extractorDigest
$env:MALWARE_EXTRACTOR_SECCOMP_PROFILE = (Resolve-Path docker\extractor\seccomp-profile.json)

malware-worker
```

The runner validates the seccomp file before startup and checks its content digest before every
extractor launch. If Rancher Desktop rejects the seccomp option, stop the worker and fix the
runtime/profile compatibility; do not set `MALWARE_EXTRACTOR_RUNNER=process` as a workaround for
untrusted samples.

## Verification and operations

```powershell
& $rdDocker compose -f compose.yaml ps
& $rdDocker ps -a
& $rdDocker compose -f compose.yaml logs --tail 100 api outbox
```

When an upload has been sealed, the scanner history should move from `awaiting_upload` to
`queued`, then through extraction/scoring states to a terminal state. The worker terminal logs
should contain lifecycle diagnostics, never raw sample bytes, file contents, or extractor output.

To stop the long-running local services while preserving PostgreSQL and RabbitMQ volumes:

```powershell
& $rdDocker compose -f compose.yaml down
```

Do not remove volumes or `data/` directories as routine cleanup: they contain workflow state,
quarantine objects, results, and potentially sensitive local samples. Follow the retention policy
before deleting them.
