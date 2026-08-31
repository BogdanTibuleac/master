# Untrusted PE upload threat model

## Scope and security objective

`POST /api/v1/scans` accepts an attacker-controlled Windows PE image and performs static
feature extraction and model inference. The objective is to provide bounded triage without
executing or retaining the binary, exposing host paths or parser diagnostics, corrupting scan
history, or allowing one client to exhaust all scanner capacity. RabbitMQ, Azure, behavioral
sandboxing, authentication, and frontend behavior are outside this hardening pass.

The uploaded bytes, multipart metadata, filename, PE headers, sections, imports, exports, and
embedded strings are all untrusted. The hardened model artifacts, process environment, scan
metadata directory, and configured CORS origins are trusted administrative inputs.

## Trust boundaries and assets

1. The HTTP/ASGI boundary receives an untrusted multipart stream.
2. The multipart parser turns that stream into an in-memory spooled file.
3. `PEFeatureExtractor` passes bounded bytes into `pefile` and NumPy feature extraction.
4. `HardenedModelRepository` passes the 2,381-value vector into LightGBM.
5. `ScanRepository` crosses the filesystem boundary with metadata-only JSON.

Assets to protect are service availability, model and host integrity, scan-history integrity,
the confidentiality of internal paths/errors, and the promise that uploaded executable bytes
are not retained by the application.

## Threats and implemented controls

| Threat | Control |
|---|---|
| Oversized file or multipart envelope | The ASGI guard validates `Content-Length` when present and counts streamed body bytes when absent or inaccurate. The envelope is limited to the configured file limit plus 64 KiB, and the file itself is checked against the exact configured limit. |
| Multipart part explosion or temporary binary retention | The endpoint accepts exactly one file and zero form fields. Its parser spool threshold is kept above the bounded request size, so the application does not roll the upload to a temporary file. The form and upload are closed on every outcome. |
| CPU/memory exhaustion through parallel uploads | The complete upload-and-scan request and the service scan operation have configured concurrency bounds. Excess requests receive a fixed `503` response with `Retry-After`. |
| Path traversal, confusing display names, or huge filenames | Only a cross-platform basename is retained. Unicode is normalized; control, bidirectional-formatting, and platform-unsafe characters are replaced; the display name is bounded to 255 characters while preserving a normal extension. The name is never used as a storage path. |
| Malformed or pathological PE structures | A pre-parser check bounds section count and optional-header size, validates the section table and raw ranges, and accepts only PE32/PE32+. `pefile` uses fast loading and parses only imports and exports. Import/export counts, symbol names, and printable-string fragments are bounded. Resource-related exceptions become safe validation errors. |
| Parser diagnostics or internal exceptions leaking to a client | Expected validation failures use fixed public messages. Unexpected upload failures are logged server-side and returned as a generic `500`; capacity and unavailable-model failures use bounded public responses. |
| Partial or racing history writes | JSON is written to a unique same-directory temporary file, flushed and fsynced, then atomically replaced. Readers ignore temporary, symlinked, corrupt, and non-object entries. In-process model loading/prediction and repository operations are synchronized. |
| Binary retention in history | `ScanRecord` contains only a sanitized basename, SHA-256, size, bounded extracted metadata, signals, contributions, and result fields. Only that record is serialized, with `binary_retained=false`; no upload path or bytes reach the repository. |
| Cross-site scan submission | Credentialed CORS is disabled. Browser POSTs with an `Origin` header are rejected unless the canonical origin is explicitly configured, and the required non-simple `X-Aegis-Scan` header forces a browser preflight. Wildcard origins are rejected at startup. Requests without `Origin` remain available to CLI/server clients. |

## Documented API adjustments

Successful responses and persisted schemas are unchanged. Security rejection behavior is now
explicit: malformed multipart bodies return `400`, oversized bodies/files return `413`, invalid
browser origins return `403`, missing/wrong multipart file fields return `422`, and exhausted
capacity returns `503` with `Retry-After`. Deployments that previously used
`MALWARE_CORS_ORIGINS=*` must configure explicit HTTP(S) origins. The configured upload limit
must be between 1 byte and 100 MB, and `MALWARE_MAX_CONCURRENT_SCANS` must be between 1 and 32;
the defaults remain 25 MB and four concurrent scans.

## Residual risks and deployment requirements

- `pefile`, NumPy, and LightGBM remain native or complex parser/model dependencies. Structural
  and concurrency limits reduce exposure but are not a substitute for OS-level isolation.
- The application has no parser wall-clock kill switch because Python threads cannot safely
  terminate a stuck native/parser call. Production deployments should use disposable workers
  with process memory/CPU/time limits and recycle a worker that exceeds its request deadline.
- A reverse proxy or ASGI server may buffer request bodies outside the application. It must use
  an equal or smaller body limit, enforce request/header/body timeouts, and be configured not to
  persist upload bodies.
- CORS and the scan marker header are browser boundaries, not authentication or authorization.
  The API and metadata history should sit behind TLS, authentication, network policy, and an
  identity-aware rate limiter when exposed beyond a trusted local environment.
- SHA-256 values and filenames can themselves be sensitive operational metadata. History access
  requires the same deployment access control as scan submission.
- Static classification can be evaded and does not establish that a file is safe. Do not execute
  uploads on the API host; use a separately isolated behavioral-analysis system when needed.
