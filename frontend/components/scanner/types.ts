export type ConnectionState = 'checking' | 'online' | 'offline';

export const scanLifecycleStates = [
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
] as const;

export const terminalScanStates = [
  'complete',
  'rejected',
  'inconclusive',
  'failed',
  'cancelled',
  'expired',
] as const;

export type ScanLifecycleState =
  | (typeof scanLifecycleStates)[number]
  | Exclude<(typeof terminalScanStates)[number], 'complete'>;

export type TerminalScanState = (typeof terminalScanStates)[number];

export type ScanTransport = 'direct_quarantine' | 'legacy_local';

export type Verdict =
  | 'likely_benign'
  | 'needs_review'
  | 'likely_malicious'
  | 'high_risk';

export type IndicatorSeverity = 'low' | 'medium' | 'high';

export type StaticSignal = {
  title: string;
  description: string;
  severity: IndicatorSeverity;
  family?: string | null;
};

export type FeatureContribution = {
  feature_group: string;
  description: string;
  contribution: number;
  direction: 'malicious' | 'benign';
};

export type ExtractionQuality = {
  extraction: 'complete' | 'partial' | 'unavailable' | 'not_reported';
  parser_disagreement: boolean | null;
  schema_compatible: boolean | null;
  feature_count: number | null;
  warnings: string[];
};

export type AnalysisProvenance = {
  analysis_release_id: string | null;
  extractor_digest: string | null;
  feature_schema_id: string | null;
  feature_schema_digest: string | null;
  model_id: string | null;
  model_digest: string | null;
  calibrator_id: string | null;
  policy_id: string | null;
  result_digest: string | null;
};

export type ScanResult = {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  scanned_at_utc: string;
  scan_duration_ms: number | null;
  verdict: Verdict;
  malware_probability: number | null;
  calibrated_risk_score: number | null;
  raw_margin: number | null;
  confidence: number | null;
  model_name: string | null;
  decision_threshold: number | null;
  feature_count: number | null;
  file_type: string | null;
  architecture: string | null;
  section_count: number | null;
  import_count: number | null;
  signature_status:
    | 'absent'
    | 'valid_trusted'
    | 'valid_untrusted'
    | 'invalid'
    | 'unknown_offline'
    | 'not_reported';
  binary_retained: boolean | null;
  model_contributors: FeatureContribution[];
  observed_indicators: StaticSignal[];
  quality: ExtractionQuality;
  provenance: AnalysisProvenance;
  limitations: string[];
};

export type ScanTerminalDetail = {
  code: string | null;
  message: string | null;
  retryable: boolean | null;
};

export type ScanJob = {
  id: string;
  filename: string;
  size_bytes: number;
  sha256: string | null;
  status: ScanLifecycleState;
  transport: ScanTransport;
  created_at_utc: string;
  updated_at_utc: string;
  analysis_release_id: string | null;
  last_completed_status: ScanLifecycleState | null;
  progress_percent: number | null;
  terminal_detail: ScanTerminalDetail | null;
  result: ScanResult | null;
};

export type ScanHistory = {
  items: ScanJob[];
  count: number;
};

export type HistoryState = 'loading' | 'ready' | 'error';

export type CreateScanRequest = {
  filename: string;
  size_bytes: number;
  content_type: string;
};

export type UploadGrant = {
  url: string;
  method: 'PUT' | 'POST';
  headers: Record<string, string>;
  fields: Record<string, string>;
  expires_at_utc: string | null;
};

export type CreatedScan = {
  scan: ScanJob;
  upload: UploadGrant;
};

export type SealScanRequest = {
  sha256: string;
  size_bytes: number;
  upload_etag?: string;
  object_generation?: string;
};

export function isTerminalScanState(
  status: ScanLifecycleState,
): status is TerminalScanState {
  return (terminalScanStates as readonly string[]).includes(status);
}
