import type { ScanHistory, ScanJob } from '@/components/scanner/types';
import {
  normalizeScanJob,
  ScannerApiError,
  ScannerContractError,
} from '@/lib/scanner-api';

export const legacyLocalModeNotice =
  'Local compatibility mode: this API does not expose quarantine upload grants, so the file is sent only to the local synchronous scanner. Do not use this path for a public deployment.';

export async function runLegacyLocalScan(
  apiUrl: string,
  file: File,
  signal?: AbortSignal,
): Promise<ScanJob> {
  const form = new FormData();
  form.append('file', file);
  const response = await fetch(legacyScanCollectionUrl(apiUrl), {
    method: 'POST',
    headers: { 'X-Aegis-Scan': 'static-pe-v1' },
    body: form,
    signal,
  });
  if (!response.ok) {
    let message = 'The local compatibility scan failed.';
    try {
      const payload = (await response.json()) as { detail?: string };
      message = payload.detail ?? message;
    } catch {
      // The local API may return an empty error body.
    }
    throw new ScannerApiError(message, response.status);
  }
  try {
    return normalizeScanJob(await response.json(), {
      defaultStatus: 'complete',
      defaultTransport: 'legacy_local',
      fallbackFilename: file.name,
      fallbackSize: file.size,
    });
  } catch (error) {
    if (error instanceof ScannerContractError) throw error;
    throw new ScannerContractError('The local scanner returned an invalid result.');
  }
}

export async function listLegacyLocalScans(
  apiUrl: string,
  limit = 12,
  signal?: AbortSignal,
): Promise<ScanHistory> {
  const response = await fetch(
    `${legacyScanCollectionUrl(apiUrl)}?limit=${encodeURIComponent(limit)}`,
    { signal },
  );
  if (!response.ok) {
    throw new ScannerApiError(
      'The local scanner did not return recent results.',
      response.status,
    );
  }
  const payload = (await response.json()) as { items?: unknown[]; count?: number };
  const items = (payload.items ?? []).map((item) =>
    normalizeScanJob(item, {
      defaultStatus: 'complete',
      defaultTransport: 'legacy_local',
    }),
  );
  return { items, count: payload.count ?? items.length };
}

function legacyScanCollectionUrl(apiUrl: string) {
  const base = apiUrl.replace(/\/$/, '');
  if (/\/api\/v1$/i.test(base) || /\/v1$/i.test(base)) {
    return `${base}/scans`;
  }
  return `${base}/api/v1/scans`;
}
