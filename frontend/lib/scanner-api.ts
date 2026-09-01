import type {
  AnalysisProvenance,
  CreateScanRequest,
  CreatedScan,
  ExtractionQuality,
  FeatureContribution,
  IndicatorSeverity,
  ScanHistory,
  ScanJob,
  ScanLifecycleState,
  ScanResult,
  SealScanRequest,
  StaticSignal,
  UploadGrant,
  Verdict,
} from '@/components/scanner/types';

type JsonObject = Record<string, unknown>;
type Fetcher = typeof fetch;

const lifecycleStateSet = new Set<ScanLifecycleState>([
  'awaiting_upload',
  'upload_received',
  'validating',
  'queued',
  'extracting',
  'validating_features',
  'scoring',
  'applying_policy',
  'publishing',
  'complete',
  'rejected',
  'inconclusive',
  'failed',
  'cancelled',
  'expired',
]);

const verdictSet = new Set<Verdict>([
  'likely_benign',
  'needs_review',
  'likely_malicious',
  'high_risk',
  'inconclusive',
]);

export class ScannerApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | null = null,
  ) {
    super(message);
    this.name = 'ScannerApiError';
  }
}

export class ScannerContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScannerContractError';
  }
}

export type DirectUploadReceipt = {
  upload_etag?: string;
  object_generation?: string;
};

export type ScannerApiClient = {
  createScan: (
    request: CreateScanRequest,
    idempotencyKey: string,
    signal?: AbortSignal,
  ) => Promise<CreatedScan>;
  uploadFile: (
    grant: UploadGrant,
    file: File,
    signal?: AbortSignal,
  ) => Promise<DirectUploadReceipt>;
  sealScan: (
    scanId: string,
    request: SealScanRequest,
    signal?: AbortSignal,
  ) => Promise<ScanJob>;
  getScan: (scanId: string, signal?: AbortSignal) => Promise<ScanJob>;
  listScans: (limit?: number, signal?: AbortSignal) => Promise<ScanHistory>;
};

export function createScannerApi(
  apiUrl: string,
  fetcher: Fetcher = fetch,
): ScannerApiClient {
  const scansUrl = scanCollectionUrl(apiUrl);

  return {
    async createScan(request, idempotencyKey, signal) {
      const payload = await requestJson(
        fetcher,
        scansUrl,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': idempotencyKey,
            'X-Aegis-Scan': 'hostile-content-v1',
          },
          body: JSON.stringify(request),
          signal,
        },
        'The secure scan could not be created.',
      );
      const object = asObject(payload);
      if (!object) {
        throw new ScannerContractError('The create response was not an object.');
      }

      const uploadObject =
        asObject(object.upload) ?? asObject(object.upload_grant);
      if (!uploadObject) {
        throw new ScannerContractError(
          'The create response did not contain a direct upload grant.',
        );
      }

      const upload = normalizeUploadGrant(uploadObject, apiUrl);
      const scan = normalizeScanJob(asObject(object.scan) ?? object, {
        defaultStatus: 'awaiting_upload',
        defaultTransport: 'direct_quarantine',
        fallbackFilename: request.filename,
        fallbackSize: request.size_bytes,
      });
      return { scan, upload };
    },

    async uploadFile(grant, file, signal) {
      const headers = new Headers(grant.headers);
      let body: BodyInit;
      if (grant.method === 'POST') {
        const form = new FormData();
        for (const [key, value] of Object.entries(grant.fields)) {
          form.append(key, value);
        }
        form.append('file', file, file.name);
        body = form;
      } else {
        if (!headers.has('Content-Type')) {
          headers.set('Content-Type', 'application/octet-stream');
        }
        body = file;
      }

      const response = await fetcher(grant.url, {
        method: grant.method,
        headers,
        body,
        signal,
      });
      if (!response.ok) {
        throw await responseError(
          response,
          'The direct quarantine upload failed.',
        );
      }
      return {
        upload_etag: response.headers.get('etag') ?? undefined,
        object_generation:
          response.headers.get('x-ms-version-id') ??
          response.headers.get('x-goog-generation') ??
          undefined,
      };
    },

    async sealScan(scanId, request, signal) {
      const payload = await requestJson(
        fetcher,
        `${scansUrl}/${encodeURIComponent(scanId)}:seal`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request),
          signal,
        },
        'The uploaded object could not be sealed for analysis.',
      );
      return normalizeScanJob(payload, {
        defaultStatus: 'upload_received',
        defaultTransport: 'direct_quarantine',
      });
    },

    async getScan(scanId, signal) {
      const payload = await requestJson(
        fetcher,
        `${scansUrl}/${encodeURIComponent(scanId)}`,
        { signal },
        'The latest scan status could not be loaded.',
      );
      return normalizeScanJob(payload, {
        defaultTransport: 'direct_quarantine',
      });
    },

    async listScans(limit = 12, signal) {
      const payload = await requestJson(
        fetcher,
        `${scansUrl}?limit=${encodeURIComponent(limit)}`,
        { signal },
        'The scanner API did not return recent scans.',
      );
      const object = asObject(payload);
      const rawItems = object && Array.isArray(object.items) ? object.items : [];
      const items = rawItems.map((item) =>
        normalizeScanJob(item, {
          defaultTransport: hasLifecycleStatus(item)
            ? 'direct_quarantine'
            : 'legacy_local',
        }),
      );
      return {
        items,
        count: numberValue(object?.count) ?? items.length,
      };
    },
  };
}

export function createIdempotencyKey() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join(
    '',
  );
}

export async function sha256File(file: File) {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (value) =>
    value.toString(16).padStart(2, '0'),
  ).join('');
}

export function normalizeScanJob(
  payload: unknown,
  options: {
    defaultStatus?: ScanLifecycleState;
    defaultTransport?: ScanJob['transport'];
    fallbackFilename?: string;
    fallbackSize?: number;
  } = {},
): ScanJob {
  const object = asObject(payload);
  if (!object) {
    throw new ScannerContractError('The scan response was not an object.');
  }

  const rawStatus = stringValue(object.status ?? object.analysis_status);
  const status = lifecycleState(rawStatus) ?? options.defaultStatus ?? 'complete';
  const resultObject =
    asObject(object.result) ??
    asObject(object.manifest) ??
    (looksLikeResult(object) ? object : null);
  const fallbackId = stringValue(object.scan_id ?? object.id);
  if (!fallbackId) {
    throw new ScannerContractError('The scan response did not contain an id.');
  }

  const result = resultObject
    ? normalizeScanResult(resultObject, {
        id: fallbackId,
        filename: stringValue(object.filename) ?? options.fallbackFilename,
        sizeBytes: numberValue(object.size_bytes) ?? options.fallbackSize,
        analysisReleaseId: stringValue(object.analysis_release_id),
      })
    : null;
  const now = new Date().toISOString();
  const terminalObject =
    asObject(object.terminal_detail) ??
    asObject(object.failure) ??
    asObject(object.error);

  return {
    id: fallbackId,
    filename:
      stringValue(object.filename ?? object.original_filename) ??
      result?.filename ??
      options.fallbackFilename ??
      'Unnamed sample',
    size_bytes:
      numberValue(object.size_bytes) ??
      result?.size_bytes ??
      options.fallbackSize ??
      0,
    sha256:
      stringValue(object.sha256 ?? object.sample_sha256 ?? object.input_digest) ??
      result?.sha256 ??
      null,
    status,
    transport:
      options.defaultTransport ??
      (hasLifecycleStatus(object) ? 'direct_quarantine' : 'legacy_local'),
    created_at_utc:
      stringValue(object.created_at_utc ?? object.created_at) ??
      result?.scanned_at_utc ??
      now,
    updated_at_utc:
      stringValue(
        object.updated_at_utc ??
          object.updated_at ??
          object.published_at_utc ??
          object.scanned_at_utc,
      ) ??
      result?.scanned_at_utc ??
      now,
    analysis_release_id:
      stringValue(object.analysis_release_id) ??
      result?.provenance.analysis_release_id ??
      null,
    last_completed_status: lifecycleState(
      stringValue(object.last_completed_status ?? object.last_successful_state),
    ),
    progress_percent: boundedPercent(
      numberValue(object.progress_percent ?? object.progress),
    ),
    terminal_detail: terminalObject
      ? {
          code: stringValue(terminalObject.code),
          message: stringValue(
            terminalObject.message ?? terminalObject.detail ?? terminalObject.reason,
          ),
          retryable: booleanValue(terminalObject.retryable),
        }
      : stringValue(object.terminal_reason)
        ? {
            code: null,
            message: stringValue(object.terminal_reason),
            retryable: null,
          }
        : null,
    result,
  };
}

export function normalizeScanResult(
  payload: unknown,
  fallback: {
    id?: string;
    filename?: string;
    sizeBytes?: number;
    analysisReleaseId?: string | null;
  } = {},
): ScanResult {
  const object = asObject(payload);
  if (!object) {
    throw new ScannerContractError('The result manifest was not an object.');
  }
  const prediction = asObject(object.prediction);
  const decision = asObject(object.decision);
  const qualityObject = asObject(object.quality);
  const provenanceObject = asObject(object.provenance);
  const releaseObject = asObject(object.release);
  const verdict = verdictValue(decision?.label ?? object.verdict);
  if (!verdict) {
    throw new ScannerContractError('The completed result has no policy verdict.');
  }

  const featureCount = numberValue(
    qualityObject?.feature_count ?? object.feature_count,
  ) ?? featureCountFromSchema(stringValue(releaseObject?.feature_schema_id));
  const analysisReleaseId =
    stringValue(
      provenanceObject?.analysis_release_id ??
        object.analysis_release_id ??
        releaseObject?.analysis_release_id,
    ) ??
    fallback.analysisReleaseId ??
    null;

  return {
    id: stringValue(object.id ?? object.scan_id) ?? fallback.id ?? 'unknown',
    filename:
      stringValue(object.filename ?? object.original_filename) ??
      fallback.filename ??
      'Unnamed sample',
    sha256:
      digestValue(
        object.sha256 ??
          object.sample_sha256 ??
          object.input_digest ??
          object.sample_digest,
      ) ??
      '',
    size_bytes:
      numberValue(object.size_bytes) ?? fallback.sizeBytes ?? 0,
    scanned_at_utc:
      stringValue(
        object.scanned_at_utc ?? object.published_at_utc ?? object.completed_at,
      ) ?? new Date().toISOString(),
    scan_duration_ms: numberValue(object.scan_duration_ms),
    verdict,
    malware_probability: numberValue(object.malware_probability),
    calibrated_risk_score: numberValue(
      prediction?.calibrated_risk_score ?? object.calibrated_risk_score,
    ),
    raw_margin: numberValue(prediction?.raw_margin ?? object.raw_margin),
    confidence: numberValue(object.confidence),
    model_name:
      stringValue(
        object.model_name ?? provenanceObject?.model_id ?? releaseObject?.model_id,
      ) ?? null,
    decision_threshold: numberValue(object.decision_threshold),
    feature_count: featureCount,
    file_type: stringValue(object.file_type),
    architecture: stringValue(object.architecture),
    section_count: numberValue(object.section_count),
    import_count: numberValue(object.import_count),
    signature_status: signatureStatus(object),
    binary_retained: booleanValue(object.binary_retained),
    model_contributors: contributionList(
      object.model_contributors ?? object.contributions,
    ),
    observed_indicators: indicatorList(
      object.observed_indicators ?? object.signals,
    ),
    quality: normalizeQuality(qualityObject, object, releaseObject, featureCount),
    provenance: normalizeProvenance(
      provenanceObject,
      object,
      releaseObject,
      analysisReleaseId,
    ),
    limitations: stringList(object.limitations),
  };
}

function scanCollectionUrl(apiUrl: string) {
  const base = apiUrl.replace(/\/$/, '');
  if (/\/api\/v1$/i.test(base) || /\/v1$/i.test(base)) {
    return `${base}/scans`;
  }
  return `${base}/api/v1/scans`;
}

function normalizeUploadGrant(object: JsonObject, apiUrl: string): UploadGrant {
  const rawUrl = stringValue(object.url ?? object.upload_url);
  if (!rawUrl) {
    throw new ScannerContractError('The upload grant did not contain a URL.');
  }
  const rawMethod = stringValue(object.method)?.toUpperCase() ?? 'PUT';
  if (rawMethod !== 'PUT' && rawMethod !== 'POST') {
    throw new ScannerContractError(`Unsupported direct upload method: ${rawMethod}.`);
  }
  return {
    url: resolveUploadUrl(rawUrl, apiUrl),
    method: rawMethod,
    headers: stringRecord(object.headers),
    fields: stringRecord(object.fields),
    expires_at_utc: stringValue(
      object.expires_at_utc ?? object.expires_at ?? object.expiration,
    ),
  };
}

function resolveUploadUrl(value: string, apiUrl: string) {
  try {
    return new URL(value, `${apiUrl.replace(/\/$/, '')}/`).toString();
  } catch {
    throw new ScannerContractError('The direct upload URL was invalid.');
  }
}

async function requestJson(
  fetcher: Fetcher,
  url: string,
  init: RequestInit,
  fallbackMessage: string,
) {
  const response = await fetcher(url, init);
  if (!response.ok) throw await responseError(response, fallbackMessage);
  try {
    return (await response.json()) as unknown;
  } catch {
    throw new ScannerContractError('The scanner API returned invalid JSON.');
  }
}

async function responseError(response: Response, fallbackMessage: string) {
  let code: string | null = null;
  let message = fallbackMessage;
  try {
    const payload = asObject(await response.json());
    code = stringValue(payload?.code ?? asObject(payload?.error)?.code);
    message =
      stringValue(
        payload?.detail ?? payload?.message ?? asObject(payload?.error)?.message,
      ) ?? fallbackMessage;
  } catch {
    // Signed object stores commonly return non-JSON error bodies.
  }
  return new ScannerApiError(message, response.status, code);
}

function normalizeQuality(
  quality: JsonObject | null,
  result: JsonObject,
  release: JsonObject | null,
  featureCount: number | null,
): ExtractionQuality {
  const extraction = stringValue(quality?.extraction ?? result.extraction);
  return {
    extraction:
      extraction === 'complete' ||
      extraction === 'partial' ||
      extraction === 'unavailable'
        ? extraction
        : extraction === 'failed'
          ? 'unavailable'
          : 'not_reported',
    parser_disagreement: booleanValue(quality?.parser_disagreement),
    schema_compatible: booleanValue(
      quality?.schema_compatible ??
        quality?.feature_schema_compatible ??
        (release?.feature_schema_id ? true : null),
    ),
    feature_count: featureCount,
    warnings: stringList(quality?.warnings),
  };
}

function normalizeProvenance(
  provenance: JsonObject | null,
  result: JsonObject,
  release: JsonObject | null,
  analysisReleaseId: string | null,
): AnalysisProvenance {
  return {
    analysis_release_id: analysisReleaseId,
    extractor_digest: stringValue(
      provenance?.extractor_digest ??
        result.extractor_digest ??
        release?.extractor_image_digest,
    ),
    feature_schema_id: stringValue(
      provenance?.feature_schema_id ??
        result.feature_schema_id ??
        release?.feature_schema_id,
    ),
    feature_schema_digest: stringValue(
      provenance?.feature_schema_digest ??
        result.feature_schema_digest ??
        release?.feature_schema_digest,
    ),
    model_id: stringValue(
      provenance?.model_id ?? result.model_id ?? result.model_name ?? release?.model_id,
    ),
    model_digest: stringValue(provenance?.model_digest ?? result.model_digest),
    calibrator_id: stringValue(
      provenance?.calibrator_id ?? result.calibrator_id ?? release?.calibrator_id,
    ),
    policy_id: stringValue(
      provenance?.policy_id ?? asObject(result.decision)?.policy_id,
    ),
    result_digest: stringValue(
      provenance?.result_digest ?? result.result_digest ?? result.manifest_digest,
    ),
  };
}

function indicatorList(value: unknown): StaticSignal[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const object = asObject(item);
    if (!object) return [];
    const title = stringValue(
      object.title ?? object.name ?? object.indicator ?? object.indicator_id,
    );
    if (!title) return [];
    return [
      {
        title,
        description:
          stringValue(
            object.description ??
              object.detail ??
              object.observation ??
              object.summary,
          ) ?? 'Observed during bounded static extraction.',
        severity: severityValue(object.severity),
        family: stringValue(object.family ?? object.category),
      },
    ];
  });
}

function contributionList(value: unknown): FeatureContribution[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const object = asObject(item);
    if (!object) return [];
    const featureGroup = stringValue(
      object.feature_group ?? object.feature_family ?? object.group,
    );
    const contribution = numberValue(
      object.contribution ?? object.raw_margin_contribution ?? object.value,
    );
    if (!featureGroup || contribution === null) return [];
    const directionValue = stringValue(object.direction);
    return [
      {
        feature_group: featureGroup,
        description:
          stringValue(object.description) ??
          'Grouped TreeSHAP contribution in raw-margin space.',
        contribution,
        direction:
          directionValue === 'benign' || contribution < 0
            ? 'benign'
            : 'malicious',
      },
    ];
  });
}

function signatureStatus(object: JsonObject): ScanResult['signature_status'] {
  const value = stringValue(object.signature_status);
  if (
    value === 'absent' ||
    value === 'valid_trusted' ||
    value === 'valid_untrusted' ||
    value === 'invalid' ||
    value === 'unknown_offline'
  ) {
    return value;
  }
  const signed = booleanValue(object.signed);
  if (signed === false) return 'absent';
  if (signed === true) return 'valid_untrusted';
  return 'not_reported';
}

function hasLifecycleStatus(value: unknown) {
  const object = asObject(value);
  return Boolean(
    lifecycleState(stringValue(object?.status ?? object?.analysis_status)),
  );
}

function looksLikeResult(object: JsonObject) {
  return Boolean(
    verdictValue(asObject(object.decision)?.label ?? object.verdict) ||
      object.prediction,
  );
}

function lifecycleState(value: string | null): ScanLifecycleState | null {
  if (!value) return null;
  const normalized = value.toLowerCase() as ScanLifecycleState;
  return lifecycleStateSet.has(normalized) ? normalized : null;
}

function verdictValue(value: unknown): Verdict | null {
  const normalized = stringValue(value)?.toLowerCase() as Verdict | undefined;
  return normalized && verdictSet.has(normalized) ? normalized : null;
}

function severityValue(value: unknown): IndicatorSeverity {
  const normalized = stringValue(value)?.toLowerCase();
  if (normalized === 'critical') return 'high';
  return normalized === 'high' || normalized === 'medium' ? normalized : 'low';
}

function digestValue(value: unknown): string | null {
  const digest = stringValue(value);
  return digest?.startsWith('sha256:') ? digest.slice(7) : digest;
}

function featureCountFromSchema(value: string | null): number | null {
  if (!value) return null;
  const match = value.match(/(?:^|[/:-])(\d{3,5})$/);
  if (!match) return null;
  const count = Number(match[1]);
  return Number.isSafeInteger(count) && count > 0 ? count : null;
}

function boundedPercent(value: number | null) {
  if (value === null) return null;
  const normalized = value <= 1 ? value * 100 : value;
  return Math.min(100, Math.max(0, normalized));
}

function asObject(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function numberValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function stringList(value: unknown) {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string')
    : [];
}

function stringRecord(value: unknown) {
  const object = asObject(value);
  if (!object) return {};
  return Object.fromEntries(
    Object.entries(object).filter(
      (entry): entry is [string, string] => typeof entry[1] === 'string',
    ),
  );
}
