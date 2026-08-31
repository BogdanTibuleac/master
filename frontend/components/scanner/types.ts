export type ConnectionState = 'checking' | 'online' | 'offline';

export type Verdict =
  | 'likely_benign'
  | 'needs_review'
  | 'likely_malicious'
  | 'high_risk';

export type StaticSignal = {
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
};

export type FeatureContribution = {
  feature_group: string;
  description: string;
  contribution: number;
  direction: 'malicious' | 'benign';
};

export type ScanResult = {
  id: string;
  filename: string;
  sha256: string;
  size_bytes: number;
  scanned_at_utc: string;
  scan_duration_ms: number;
  verdict: Verdict;
  malware_probability: number;
  confidence: number;
  model_name: string;
  decision_threshold: number;
  feature_count: number;
  file_type: string;
  architecture: string;
  section_count: number;
  import_count: number;
  signed: boolean;
  binary_retained: boolean;
  signals: StaticSignal[];
  contributions: FeatureContribution[];
};

export type ScanHistory = {
  items: ScanResult[];
  count: number;
};

export type HistoryState = 'loading' | 'ready' | 'error';
