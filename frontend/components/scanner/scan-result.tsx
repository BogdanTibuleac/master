import { Gauge, Trash2 } from 'lucide-react';
import { useId } from 'react';

import {
  formatBytes,
  formatDate,
  formatPercent,
  verdictLabel,
} from '@/components/scanner/formatters';
import type {
  ScanResult,
  StaticSignal,
  Verdict,
} from '@/components/scanner/types';
import { VerdictBadge } from '@/components/scanner/verdict-badge';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

export function ScanResultPanel({ result }: { result: ScanResult }) {
  return (
    <Card
      data-testid="scan-result"
      className="glass-card overflow-hidden border-emerald-300/10"
    >
      <CardHeader className="border-b border-white/8 pb-4">
        <CardTitle className="flex items-center gap-2 text-white">
          <Gauge className="size-4 text-cyan-300" />
          Scan result
        </CardTitle>
        <CardDescription className="break-all sm:break-normal">
          {result.filename}
        </CardDescription>
        <CardAction>
          <VerdictBadge verdict={result.verdict} />
        </CardAction>
      </CardHeader>
      <CardContent className="pt-6">
        <ScanResultDetails result={result} />
      </CardContent>
    </Card>
  );
}

export function ScanResultDetails({ result }: { result: ScanResult }) {
  const evidenceId = useId();
  const indicatorsId = useId();
  const maximumContribution = Math.max(
    ...result.contributions.map((item) => Math.abs(item.contribution)),
    0.001,
  );

  return (
    <div>
      <div className="grid gap-6 xl:grid-cols-[250px_1fr] xl:gap-8">
        <div className="flex flex-col items-center rounded-2xl border border-white/8 bg-black/10 p-5 text-center sm:p-6">
          <RiskGauge
            probability={result.malware_probability}
            verdict={result.verdict}
          />
          <p className="mt-5 text-sm font-medium text-white">
            {verdictLabel(result.verdict)}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Threshold {formatPercent(result.decision_threshold)} · confidence{' '}
            {formatPercent(result.confidence)}
          </p>
          <div className="mt-5 grid w-full grid-cols-2 gap-2">
            <ResultFact
              label="Type"
              value={`${result.file_type} / ${result.architecture}`}
            />
            <ResultFact label="Size" value={formatBytes(result.size_bytes)} />
            <ResultFact
              label="Sections"
              value={result.section_count.toString()}
            />
            <ResultFact
              label="Imports"
              value={result.import_count.toLocaleString()}
            />
            <ResultFact label="Signed" value={result.signed ? 'Yes' : 'No'} />
            <ResultFact
              label="Duration"
              value={`${result.scan_duration_ms} ms`}
            />
          </div>
        </div>

        <div className="space-y-6">
          <section aria-labelledby={evidenceId}>
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3
                  id={evidenceId}
                  className="text-sm font-medium text-slate-200"
                >
                  Model evidence
                </h3>
                <p className="mt-1 text-xs text-slate-500">
                  Strongest grouped contributions to this prediction
                </p>
              </div>
              <Badge
                variant="outline"
                className="w-fit border-white/10 font-mono text-slate-400"
              >
                {result.feature_count.toLocaleString()} features
              </Badge>
            </div>
            {result.contributions.length ? (
              <div className="space-y-3">
                {result.contributions.map((item) => (
                  <div key={item.feature_group}>
                    <div className="mb-1.5 flex items-center justify-between gap-4 text-xs">
                      <span className="text-slate-300">
                        {item.feature_group}
                      </span>
                      <span
                        className={`font-mono ${
                          item.direction === 'malicious'
                            ? 'text-rose-300'
                            : 'text-emerald-300'
                        }`}
                      >
                        {item.contribution >= 0 ? '+' : ''}
                        {item.contribution.toFixed(3)}
                      </span>
                    </div>
                    <Progress
                      value={
                        (Math.abs(item.contribution) / maximumContribution) *
                        100
                      }
                      aria-label={`${item.feature_group} contribution strength`}
                      className={
                        item.direction === 'malicious'
                          ? '[&_[data-slot=progress-indicator]]:bg-rose-300'
                          : '[&_[data-slot=progress-indicator]]:bg-emerald-300'
                      }
                    />
                    <p className="mt-1.5 text-[11px] text-slate-600">
                      {item.description}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-white/10 p-4 text-sm text-slate-500">
                No feature contributions were reported for this scan.
              </p>
            )}
          </section>

          <section aria-labelledby={indicatorsId}>
            <h3
              id={indicatorsId}
              className="text-sm font-medium text-slate-200"
            >
              Static indicators
            </h3>
            <p className="mt-1 text-xs text-slate-500">
              Capabilities and anomalies found without running the file
            </p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {result.signals.length ? (
                result.signals.map((signal) => (
                  <SignalCard key={signal.title} signal={signal} />
                ))
              ) : (
                <div className="rounded-xl border border-emerald-300/12 bg-emerald-300/[0.045] p-4 text-sm text-emerald-200 sm:col-span-2">
                  No notable static indicators were extracted.
                </div>
              )}
            </div>
          </section>
        </div>
      </div>

      <div className="mt-6 grid gap-4 border-t border-white/8 pt-5 lg:grid-cols-[1fr_auto] lg:items-end">
        <div className="min-w-0">
          <p className="text-xs text-slate-500">SHA-256</p>
          <p className="mt-1 break-all font-mono text-xs leading-5 text-slate-300">
            {result.sha256}
          </p>
          <p className="mt-2 text-xs text-slate-600">
            {result.model_name} · scanned{' '}
            {formatDate(result.scanned_at_utc, true)}
          </p>
        </div>
        <div
          className={`flex items-center gap-2 text-xs ${
            result.binary_retained ? 'text-amber-300' : 'text-emerald-300'
          }`}
        >
          <Trash2 className="size-3.5 shrink-0" />
          {result.binary_retained
            ? 'Uploaded binary retained by the scanner'
            : 'Uploaded binary discarded after analysis'}
        </div>
      </div>
    </div>
  );
}

function RiskGauge({
  probability,
  verdict,
}: {
  probability: number;
  verdict: Verdict;
}) {
  const color =
    verdict === 'likely_benign'
      ? '#6ee7b7'
      : verdict === 'needs_review'
        ? '#fcd34d'
        : '#fda4af';

  return (
    <div
      className="grid size-36 place-items-center rounded-full p-2"
      style={{
        background: `conic-gradient(${color} ${probability * 360}deg, rgba(255,255,255,.06) 0deg)`,
      }}
    >
      <div className="grid size-full place-items-center rounded-full border border-white/8 bg-[#0a0e1a]">
        <div>
          <p className="font-mono text-3xl font-semibold text-white">
            {formatPercent(probability)}
          </p>
          <p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">
            malware risk
          </p>
        </div>
      </div>
    </div>
  );
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
        <span className="text-[9px] uppercase tracking-wider opacity-60">
          {signal.severity}
        </span>
      </div>
      <p className="mt-2 text-[11px] leading-4 text-slate-500">
        {signal.description}
      </p>
    </div>
  );
}

function ResultFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-xl border border-white/7 bg-white/[0.022] p-3">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>
      <p
        className="mt-1.5 truncate font-mono text-xs text-slate-300"
        title={value}
      >
        {value}
      </p>
    </div>
  );
}
