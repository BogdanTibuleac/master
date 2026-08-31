# API reference

## 1. Conventions

The local base URL is:

```text
http://127.0.0.1:8000
```

Versioned application routes use `/api/v1`. JSON request objects reject unknown fields where a
strict schema is defined. Times are ISO 8601 values. Scan identifiers, object keys, generations,
release identities, and nonces are opaque and must not be parsed by clients.

Interactive OpenAPI is available at `/docs`, and the JSON schema is at `/openapi.json`.

## 2. Endpoint summary

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | API process liveness |
| `GET` | `/api/v1/datasets/ember2018/status` | Local EMBER availability |
| `POST` | `/api/v1/datasets/ember2018/verify` | Verify archive hash, manifest, and expected extracted files |
| `POST` | `/api/v1/datasets/ember2018/smoke-test` | Vectorize one held-out real record |
| `GET` | `/api/v1/experiments/baseline` | Latest completed baseline metrics |
| `GET` | `/api/v1/experiments/robustness` | Latest completed robustness metrics |
| `GET` | `/api/v1/experiments/comparison` | Latest baseline/hardened comparison |
| `POST` | `/api/v1/scans` | Create async scan, or invoke explicit legacy multipart mode |
| `PUT` | `/api/v1/scans/{scan_id}/content` | Local quarantine upload endpoint from a scoped grant |
| `POST` | `/api/v1/scans/{scan_id}:seal` | Verify uploaded object and commit queue intent |
| `GET` | `/api/v1/scans` | Recent metadata/results, maximum 100 |
| `GET` | `/api/v1/scans/{scan_id}` | One workflow and public result |

## 3. Scan protocol selection

`POST /api/v1/scans` supports two contracts selected by exactly one `X-Aegis-Scan` header:

| Header value | Body | Intended use |
|---|---|---|
| `hostile-content-v1` | JSON | Preferred asynchronous quarantine workflow |
| `static-pe-v1` | Multipart field `file` | Local-only synchronous compatibility workflow |

Missing, duplicate, or unknown selector headers are rejected with `403`. If an `Origin` header is
present, it must occur exactly once and match one of the configured explicit CORS origins.

Because one route accepts two media types conditionally, generated OpenAPI includes the legacy
multipart body and does not completely describe the preferred JSON body. Use this document for
the protocol contract.

## 4. Asynchronous hostile-content API

### 4.1 Create a scan

```http
POST /api/v1/scans
Content-Type: application/json
X-Aegis-Scan: hostile-content-v1
Idempotency-Key: 23a34a85-7d94-44c6-b78e-ccbe3546e541
```

```json
{
  "filename": "sample.exe",
  "size_bytes": 5138024,
  "content_type": "application/vnd.microsoft.portable-executable"
}
```

Constraints:

- `filename`: 1–255 characters;
- `size_bytes`: positive and no more than 100 MiB at schema level, then constrained by
  `MALWARE_MAX_UPLOAD_BYTES` at runtime;
- `content_type`: 1–255 characters;
- `Idempotency-Key`: exactly one non-empty value, maximum 255 characters.

Response: `201 Created`.

```json
{
  "scan": {
    "id": "opaque-scan-id",
    "scan_id": "opaque-scan-id",
    "filename": "sample.exe",
    "size_bytes": 5138024,
    "sample_sha256": null,
    "status": "awaiting_upload",
    "transport": "direct_quarantine",
    "created_at": "2026-08-31T10:00:00Z",
    "updated_at": "2026-08-31T10:00:00Z",
    "analysis_release_id": "sha256:...",
    "progress_percent": 0,
    "terminal_reason": null,
    "result": null
  },
  "upload": {
    "url": "http://127.0.0.1:8000/api/v1/scans/opaque-scan-id/content",
    "method": "PUT",
    "headers": {
      "X-Aegis-Upload-Token": "short-lived-capability"
    },
    "fields": {},
    "expires_at_utc": "2026-08-31T10:15:00Z"
  }
}
```

The response is illustrative; all identities and timestamps are server-generated. Reusing the
same tenant/idempotency key with conflicting creation data is rejected.

### 4.2 Upload content

Send the exact file bytes to the returned URL using the returned method and headers. In local
mode this calls:

```http
PUT /api/v1/scans/{scan_id}/content
X-Aegis-Upload-Token: <capability>
Content-Type: application/octet-stream
```

The response is `201 Created`, with an `ETag` and local generation header. Azure grants point
directly to Blob Storage rather than this API route and return the storage service's version and
ETag headers. Clients must not log or persist the upload URL or capability.

### 4.3 Seal content

```http
POST /api/v1/scans/{scan_id}:seal
Content-Type: application/json
```

```json
{
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "size_bytes": 5138024,
  "upload_etag": "optional-storage-etag",
  "object_generation": "optional-storage-version-id"
}
```

`sha256` is exactly 64 lowercase hexadecimal characters. `upload_etag` and
`object_generation` are bounded opaque values. The service independently opens and verifies the
quarantined object; client claims are never accepted without storage verification.

The response is the current scan job. In local auto-processing mode a background task begins
after the seal response is created.

### 4.4 Retrieve status

```http
GET /api/v1/scans/{scan_id}
```

The response contains:

- declared filename and size;
- sample SHA-256 after sealing;
- workflow status and progress;
- analysis release identity;
- safe terminal reason when present;
- immutable public `result` when published.

Valid lifecycle values are:

```text
awaiting_upload
upload_received
validating
queued
extracting
validating_features
scoring
applying_policy
publishing
complete
rejected
inconclusive
failed
cancelled
expired
```

The terminal values are `complete`, `rejected`, `inconclusive`, `failed`, `cancelled`, and
`expired`.

### 4.5 List recent scans

```http
GET /api/v1/scans?limit=25
```

`limit` is from 1 to 100, default 25. The endpoint merges async workflow entries and local legacy
scan metadata, then returns:

```json
{
  "items": [],
  "count": 0
}
```

This is recent-history retrieval, not stable cursor pagination. Ordering and persistence across
restart are not yet a production history API contract.

## 5. Complete local scan example in PowerShell

Run from the repository root after starting the backend:

```powershell
$filePath = (Resolve-Path .\sample.exe).Path
$fileInfo = Get-Item -LiteralPath $filePath
$apiBase = "http://127.0.0.1:8000"
$createHeaders = @{
  "X-Aegis-Scan" = "hostile-content-v1"
  "Idempotency-Key" = [guid]::NewGuid().ToString()
}
$createBody = @{
  filename = $fileInfo.Name
  size_bytes = $fileInfo.Length
  content_type = "application/octet-stream"
} | ConvertTo-Json

$created = Invoke-RestMethod `
  -Uri "$apiBase/api/v1/scans" `
  -Method Post `
  -Headers $createHeaders `
  -ContentType "application/json" `
  -Body $createBody

$uploadHeaders = @{}
$created.upload.headers.psobject.Properties | ForEach-Object {
  $uploadHeaders[$_.Name] = [string]$_.Value
}
$uploaded = Invoke-WebRequest `
  -Uri $created.upload.url `
  -Method Put `
  -Headers $uploadHeaders `
  -ContentType "application/octet-stream" `
  -InFile $filePath

$digest = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
$sealBody = @{
  sha256 = $digest
  size_bytes = $fileInfo.Length
  upload_etag = [string]$uploaded.Headers.ETag
} | ConvertTo-Json

$sealed = Invoke-RestMethod `
  -Uri "$apiBase/api/v1/scans/$($created.scan.id):seal" `
  -Method Post `
  -ContentType "application/json" `
  -Body $sealBody

do {
  Start-Sleep -Milliseconds 1250
  $current = Invoke-RestMethod "$apiBase/api/v1/scans/$($created.scan.id)"
} until ($current.status -in @("complete", "rejected", "inconclusive", "failed", "cancelled", "expired"))

$current | ConvertTo-Json -Depth 20
```

Do not use a real sensitive or uncontrolled sample on an inadequately isolated developer host.

## 6. Legacy synchronous API

```http
POST /api/v1/scans
Content-Type: multipart/form-data
X-Aegis-Scan: static-pe-v1
```

The form must contain exactly one field named `file` and no other fields. The response is a
legacy `ScanResponse` with verdict, probability, basic PE metadata, static signals, and grouped
contributions. The implementation keeps the upload in memory for the request and persists only
scan metadata under `data/scans/`.

This mode does not provide the async quarantine/extractor trust boundary and is not intended for
production.

## 7. Dataset API

### Status

`GET /api/v1/datasets/ember2018/status` is read-only and returns:

```json
{
  "name": "EMBER2018",
  "raw_directory": "data/raw",
  "archive_available": false,
  "manifest_available": false,
  "extracted_files_available": false,
  "ready": false
}
```

### Verify

`POST /api/v1/datasets/ember2018/verify` verifies archive provenance and extracted file
completeness. Missing or invalid data returns `409 Conflict`.

### Smoke test

`POST /api/v1/datasets/ember2018/smoke-test` vectorizes one held-out real record and returns
`feature_count`, `label`, and whether every value is finite. Unavailable or invalid data returns
`409 Conflict`.

These endpoints do not download the dataset.

## 8. Experiment API

Each experiment endpoint returns:

```json
{
  "available": false,
  "metrics": null
}
```

When a completed artifact exists, `available` is true and `metrics` contains the persisted JSON.
The API reads the newest recognized artifact; it does not launch training.

## 9. Error behavior

| Status | Typical meaning |
|---|---|
| `400` | Malformed request, missing/duplicate idempotency key, malformed multipart |
| `403` | Invalid scan selector, origin, or local upload capability |
| `404` | Unknown scan or quarantine/result object |
| `409` | Workflow/object identity conflict, dataset unavailable or invalid |
| `413` | Request or file exceeds configured maximum |
| `422` | Strict JSON/schema/PE validation failure |
| `503` | Scanner capacity exhausted or required model unavailable |
| `500` | Unexpected internal failure; response omits sensitive detail |

Clients should retry only requests known to be idempotent and only for transient conditions.
Creation retries must reuse the same `Idempotency-Key`; a different file or declaration must use
a new key.

## 10. Security constraints for API consumers

- The API currently has no authentication or authorization. Do not expose it to an untrusted
  network.
- CORS is not access control for non-browser clients.
- Treat upload grants as credentials until expiration.
- Never place sample bytes, capabilities, signed URLs, feature vectors, or extracted strings in
  logs, traces, analytics, or queue messages.
- Use HTTPS at every network boundary outside local development.
- Validate `manifest_schema`, `manifest_digest`, `analysis_release_id`, and decision limitations
  before downstream automation.
- Do not automate destructive action solely from a static ML verdict.
