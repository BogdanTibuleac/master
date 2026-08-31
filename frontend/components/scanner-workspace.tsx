'use client';

import {
  AlertTriangle,
  Binary,
  CheckCircle2,
  Clock3,
  FileKey2,
  FileSearch,
  Fingerprint,
  Gauge,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UploadCloud,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent } from 'react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Spinner } from '@/components/ui/spinner';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type ConnectionState = 'checking' | 'online' | 'offline';
type Verdict = 'likely_benign' | 'needs_review' | 'likely_malicious' | 'high_risk';
type StaticSignal = { title: string; description: string; severity: 'low' | 'medium' | 'high' };
type FeatureContribution = {
  feature_group: string;
  description: string;
  contribution: number;
  direction: 'malicious' | 'benign';
};
type ScanResult = {
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
type ScanHistory = { items: ScanResult[]; count: number };

const maximumBytes = 25 * 1024 * 1024;
const supportedExtensions = ['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx'];

export function ScannerWorkspace({
  apiUrl,
  connection,
}: {
  apiUrl: string;
  connection: ConnectionState;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);

  const loadHistory = useCallback(async () => {
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans?limit=12`);
      if (!response.ok) throw new Error('History is unavailable.');
      const payload = (await response.json()) as ScanHistory;
      setHistory(payload.items);
    } catch {
      setHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  }, [apiUrl]);

  useEffect(() => {
    let active = true;
    void fetch(`${apiUrl}/api/v1/scans?limit=12`)
      .then((response) => {
        if (!response.ok) throw new Error('History is unavailable.');
        return response.json() as Promise<ScanHistory>;
      })
      .then((payload) => {
        if (active) setHistory(payload.items);
      })
      .catch(() => {
        if (active) setHistory([]);
      })
      .finally(() => {
        if (active) setHistoryLoading(false);
      });
    return () => {
      active = false;
    };
  }, [apiUrl]);

  function chooseFile(candidate: File | null) {
    setError(null);
    setResult(null);
    if (!candidate) {
      setFile(null);
      return;
    }
    const extension = `.${candidate.name.split('.').pop()?.toLowerCase() ?? ''}`;
    if (!supportedExtensions.includes(extension)) {
      setFile(null);
      setError(`Unsupported file type. Choose ${supportedExtensions.join(', ')}.`);
      return;
    }
    if (candidate.size > maximumBytes) {
      setFile(null);
      setError('The selected file exceeds the 25 MB limit.');
      return;
    }
    if (candidate.size === 0) {
      setFile(null);
      setError('The selected file is empty.');
      return;
    }
    setFile(candidate);
  }

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    chooseFile(event.target.files?.[0] ?? null);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragActive(false);
    chooseFile(event.dataTransfer.files?.[0] ?? null);
  }

  async function submitScan() {
    if (!file) {
      setError('Choose a Windows PE file before starting the scan.');
      return;
    }
    setSubmitting(true);
    setError(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const response = await fetch(`${apiUrl}/api/v1/scans`, {
        method: 'POST',
        headers: { 'X-Aegis-Scan': 'static-pe-v1' },
        body: form,
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as { detail?: string } | null;
        throw new Error(payload?.detail ?? 'The file could not be scanned.');
      }
      const payload = (await response.json()) as ScanResult;
      setResult(payload);
      setFile(null);
      if (inputRef.current) inputRef.current.value = '';
      setHistoryLoading(true);
      await loadHistory();
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'The file could not be scanned.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1.1fr_.9fr]">
        <Card className="glass-card overflow-hidden border-cyan-300/10">
          <CardHeader className="border-b border-white/8 pb-4">
            <CardTitle className="flex items-center gap-2 text-white">
              <FileSearch className="size-4 text-cyan-300" />
              Upload suspicious file
            </CardTitle>
            <CardDescription>Static analysis only. The file is never launched.</CardDescription>
            <CardAction>
              <Badge className="border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
                25 MB max
              </Badge>
            </CardAction>
          </CardHeader>
          <CardContent className="space-y-4 pt-5">
            <div
              data-testid="scan-dropzone"
              onDragEnter={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragOver={(event) => event.preventDefault()}
              onDragLeave={() => setDragActive(false)}
              onDrop={handleDrop}
              className={`rounded-2xl border border-dashed px-6 py-9 text-center transition-colors ${
                dragActive
                  ? 'border-cyan-300/60 bg-cyan-300/10'
                  : file
                    ? 'border-emerald-300/30 bg-emerald-300/[0.06]'
                    : 'border-white/12 bg-black/10 hover:border-cyan-300/30 hover:bg-cyan-300/[0.035]'
              }`}
            >
              <input
                ref={inputRef}
                id="suspicious-file"
                data-testid="scan-file-input"
                type="file"
                accept={supportedExtensions.join(',')}
                className="sr-only"
                onChange={handleInput}
              />
              <div
                className={`mx-auto grid size-14 place-items-center rounded-2xl border ${
                  file
                    ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                    : 'border-cyan-300/15 bg-cyan-300/8 text-cyan-200'
                }`}
              >
                {file ? <CheckCircle2 className="size-6" /> : <UploadCloud className="size-6" />}
              </div>
              {file ? (
                <>
                  <p className="mt-4 truncate text-sm font-medium text-white">{file.name}</p>
                  <p className="mt-1 font-mono text-xs text-slate-500">{formatBytes(file.size)}</p>
                </>
              ) : (
                <>
                  <p className="mt-4 text-sm font-medium text-slate-200">Drop a PE file here</p>
                  <p className="mt-1 text-xs text-slate-500">
                    EXE, DLL, SYS, SCR, CPL or OCX
                  </p>
                </>
              )}
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-5 border-white/10 bg-white/[0.035] text-slate-200"
                onClick={() => inputRef.current?.click()}
              >
                {file ? 'Choose another file' : 'Browse files'}
              </Button>
            </div>

            {error && (
              <Alert variant="destructive" className="border-rose-300/20 bg-rose-300/[0.06]">
                <AlertTriangle />
                <AlertTitle>Scan could not start</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button
              data-testid="start-scan"
              className="h-11 w-full bg-cyan-300 text-slate-950 shadow-[0_0_28px_rgba(103,232,249,.14)] hover:bg-cyan-200"
              disabled={!file || submitting || connection === 'offline'}
              onClick={() => void submitScan()}
            >
              {submitting ? <Spinner /> : <ShieldCheck />}
              {submitting ? 'Extracting 2,381 features…' : 'Start static scan'}
            </Button>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="border-b border-white/8 pb-4">
            <CardTitle className="flex items-center gap-2 text-white">
              <LockKeyhole className="size-4 text-violet-300" />
              Safe analysis boundary
            </CardTitle>
            <CardDescription>Designed for unknown and untrusted binaries</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 pt-5">
            <SafetyRow
              icon={ShieldAlert}
              title="Never executed"
              detail="Only file bytes and PE structures are inspected."
            />
            <SafetyRow
              icon={Binary}
              title="In-memory extraction"
              detail="The binary is discarded immediately after scoring."
            />
            <SafetyRow
              icon={Fingerprint}
              title="Metadata-only history"
              detail="Verdict, SHA-256 and explanations are retained."
            />
            <SafetyRow
              icon={FileKey2}
              title="Hardened model"
              detail="The robust LightGBM model evaluates all 2,381 inputs."
            />
            <div className="mt-5 rounded-xl border border-violet-300/12 bg-violet-300/[0.045] p-4">
              <p className="text-xs font-medium uppercase tracking-[0.14em] text-violet-200">
                What this scan does not do
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                It does not run the file, contact embedded URLs, or guarantee that a file is safe.
                Static ML results should be combined with signatures and sandbox behavior later.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {result && <ScanResultPanel result={result} />}

      <Card className="glass-card">
        <CardHeader className="border-b border-white/8 pb-4">
          <CardTitle className="flex items-center gap-2 text-white">
            <Clock3 className="size-4 text-violet-300" />
            Recent scans
          </CardTitle>
          <CardDescription>Persisted findings only; uploaded binaries are not stored</CardDescription>
          <CardAction>
            <Button
              variant="ghost"
              size="sm"
              className="text-slate-400 hover:text-white"
              onClick={() => {
                setHistoryLoading(true);
                void loadHistory();
              }}
              disabled={historyLoading}
            >
              <RefreshCw className={historyLoading ? 'animate-spin' : ''} />
              Refresh
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="pt-4">
          {historyLoading ? (
            <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
              <Spinner /> Loading scan history
            </div>
          ) : history.length ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-white/8 hover:bg-transparent">
                    <TableHead className="text-slate-500">File</TableHead>
                    <TableHead className="text-slate-500">Verdict</TableHead>
                    <TableHead className="text-right text-slate-500">Risk</TableHead>
                    <TableHead className="text-right text-slate-500">Scanned</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((item) => (
                    <TableRow key={item.id} className="border-white/6 hover:bg-white/[0.025]">
                      <TableCell>
                        <p className="max-w-[260px] truncate font-medium text-slate-200">
                          {item.filename}
                        </p>
                        <p className="mt-1 font-mono text-[10px] text-slate-600">
                          {item.sha256.slice(0, 16)}…
                        </p>
                      </TableCell>
                      <TableCell>
                        <VerdictBadge verdict={item.verdict} />
                      </TableCell>
                      <TableCell className="text-right font-mono text-slate-200">
                        {formatPercent(item.malware_probability)}
                      </TableCell>
                      <TableCell className="text-right text-xs text-slate-500">
                        {formatDate(item.scanned_at_utc)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-white/10 px-5 py-9 text-center">
              <FileSearch className="mx-auto size-5 text-slate-600" />
              <p className="mt-3 text-sm text-slate-400">No scans have been recorded yet.</p>
              <p className="mt-1 text-xs text-slate-600">Your first completed scan will appear here.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ScanResultPanel({ result }: { result: ScanResult }) {
  const maximumContribution = Math.max(
    ...result.contributions.map((item) => Math.abs(item.contribution)),
    0.001,
  );
  return (
    <Card data-testid="scan-result" className="glass-card overflow-hidden border-emerald-300/10">
      <CardHeader className="border-b border-white/8 pb-4">
        <CardTitle className="flex items-center gap-2 text-white">
          <Gauge className="size-4 text-cyan-300" />
          Scan result
        </CardTitle>
        <CardDescription>{result.filename}</CardDescription>
        <CardAction>
          <VerdictBadge verdict={result.verdict} />
        </CardAction>
      </CardHeader>
      <CardContent className="pt-6">
        <div className="grid gap-8 xl:grid-cols-[250px_1fr]">
          <div className="flex flex-col items-center rounded-2xl border border-white/8 bg-black/10 p-6 text-center">
            <RiskGauge probability={result.malware_probability} verdict={result.verdict} />
            <p className="mt-5 text-sm font-medium text-white">{verdictLabel(result.verdict)}</p>
            <p className="mt-1 text-xs text-slate-500">
              Threshold {formatPercent(result.decision_threshold)} · confidence{' '}
              {formatPercent(result.confidence)}
            </p>
            <div className="mt-5 grid w-full grid-cols-2 gap-2">
              <ResultFact label="Type" value={`${result.file_type} / ${result.architecture}`} />
              <ResultFact label="Duration" value={`${result.scan_duration_ms} ms`} />
              <ResultFact label="Sections" value={result.section_count.toString()} />
              <ResultFact label="Imports" value={result.import_count.toLocaleString()} />
            </div>
          </div>

          <div className="space-y-6">
            <div>
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-medium text-slate-200">Model evidence</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Strongest grouped contributions to this prediction
                  </p>
                </div>
                <Badge variant="outline" className="border-white/10 font-mono text-slate-400">
                  {result.feature_count.toLocaleString()} features
                </Badge>
              </div>
              <div className="space-y-3">
                {result.contributions.map((item) => (
                  <div key={item.feature_group}>
                    <div className="mb-1.5 flex items-center justify-between gap-4 text-xs">
                      <span className="text-slate-300">{item.feature_group}</span>
                      <span
                        className={`font-mono ${
                          item.direction === 'malicious' ? 'text-rose-300' : 'text-emerald-300'
                        }`}
                      >
                        {item.contribution >= 0 ? '+' : ''}
                        {item.contribution.toFixed(3)}
                      </span>
                    </div>
                    <Progress
                      value={(Math.abs(item.contribution) / maximumContribution) * 100}
                      className={
                        item.direction === 'malicious'
                          ? '[&_[data-slot=progress-indicator]]:bg-rose-300'
                          : '[&_[data-slot=progress-indicator]]:bg-emerald-300'
                      }
                    />
                    <p className="mt-1.5 text-[11px] text-slate-600">{item.description}</p>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="text-sm font-medium text-slate-200">Static indicators</p>
              <p className="mt-1 text-xs text-slate-500">
                Capabilities and anomalies found without running the file
              </p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                {result.signals.length ? (
                  result.signals.map((signal) => <SignalCard key={signal.title} signal={signal} />)
                ) : (
                  <div className="sm:col-span-2 rounded-xl border border-emerald-300/12 bg-emerald-300/[0.045] p-4 text-sm text-emerald-200">
                    No notable static indicators were extracted.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="mt-6 grid gap-3 border-t border-white/8 pt-5 lg:grid-cols-[1fr_auto] lg:items-center">
          <div className="min-w-0">
            <p className="text-xs text-slate-500">SHA-256</p>
            <p className="mt-1 truncate font-mono text-xs text-slate-300">{result.sha256}</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-emerald-300">
            <Trash2 className="size-3.5" /> Uploaded binary discarded after analysis
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function RiskGauge({ probability, verdict }: { probability: number; verdict: Verdict }) {
  const color = verdict === 'likely_benign' ? '#6ee7b7' : verdict === 'needs_review' ? '#fcd34d' : '#fda4af';
  return (
    <div
      className="grid size-36 place-items-center rounded-full p-2"
      style={{
        background: `conic-gradient(${color} ${probability * 360}deg, rgba(255,255,255,.06) 0deg)`,
      }}
    >
      <div className="grid size-full place-items-center rounded-full border border-white/8 bg-[#0a0e1a]">
        <div>
          <p className="font-mono text-3xl font-semibold text-white">{formatPercent(probability)}</p>
          <p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">malware risk</p>
        </div>
      </div>
    </div>
  );
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const tones: Record<Verdict, string> = {
    likely_benign: 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200',
    needs_review: 'border-amber-300/20 bg-amber-300/10 text-amber-200',
    likely_malicious: 'border-rose-300/20 bg-rose-300/10 text-rose-200',
    high_risk: 'border-rose-300/30 bg-rose-300/15 text-rose-100',
  };
  return <Badge className={`border ${tones[verdict]}`}>{verdictLabel(verdict)}</Badge>;
}

function SignalCard({ signal }: { signal: StaticSignal }) {
  const tones = {
    low: 'border-slate-300/10 bg-white/[0.025] text-slate-300',
    medium: 'border-amber-300/15 bg-amber-300/[0.045] text-amber-200',
    high: 'border-rose-300/15 bg-rose-300/[0.045] text-rose-200',
  };
  return (
    <div className={`rounded-xl border p-3.5 ${tones[signal.severity]}`}>
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-medium">{signal.title}</p>
        <span className="text-[9px] uppercase tracking-wider opacity-60">{signal.severity}</span>
      </div>
      <p className="mt-2 text-[11px] leading-4 text-slate-500">{signal.description}</p>
    </div>
  );
}

function SafetyRow({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof ShieldCheck;
  title: string;
  detail: string;
}) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-white/7 bg-white/[0.022] p-3.5">
      <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-cyan-300/8 text-cyan-200">
        <Icon className="size-4" />
      </div>
      <div>
        <p className="text-sm font-medium text-slate-200">{title}</p>
        <p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p>
      </div>
    </div>
  );
}

function ResultFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/7 bg-white/[0.022] p-3">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p>
      <p className="mt-1.5 truncate font-mono text-xs text-slate-300">{value}</p>
    </div>
  );
}

function verdictLabel(verdict: Verdict) {
  return {
    likely_benign: 'Likely benign',
    needs_review: 'Needs review',
    likely_malicious: 'Likely malicious',
    high_risk: 'High risk',
  }[verdict];
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
}
