import {
  AlertTriangle,
  FileCheck2,
  Fingerprint,
  Gauge,
  Info,
  Layers3,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { useId } from 'react';

import {
  formatBytes,
  formatDate,
  formatPercent,
  verdictLabel,
} from '@/components/scanner/formatters';
import type {
  ExtractionQuality,
  ScanResult,
  StaticSignal,
  Verdict,
} from '@/components/scanner/types';
import { VerdictBadge } from '@/components/scanner/verdict-badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
          Governed analysis result
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
  const contributorsId = useId();
  const indicatorsId = useId();
  const qualityId = useId();
  const provenanceId = useId();
  const maximumContribution = Math.max(
    ...result.model_contributors.map((item) => Math.abs(item.contribution)),
    0.001,
  );
  const displayedRisk =
    result.calibrated_risk_score ?? result.malware_probability;
  const calibrated = result.calibrated_risk_score !== null;

  return (
    <div>
      <div className="grid gap-6 xl:grid-cols-[270px_1fr] xl:gap-8">
        <div className="flex flex-col items-center rounded-2xl border border-white/8 bg-black/10 p-5 text-center sm:p-6">
          <RiskGauge
            probability={displayedRisk}
            verdict={result.verdict}
            calibrated={calibrated}
          />
          <p className="mt-5 text-sm font-medium text-white">
            {verdictLabel(result.verdict)}
          </p>
          <p className="mt-1 text-xs leading-5 text-slate-500">
            {calibrated
              ? 'Versioned calibration applied before policy.'
              : 'Calibration was not reported; showing raw model probability.'}
          </p>
          <div className="mt-5 grid w-full grid-cols-2 gap-2">
            <ResultFact
              label="Type"
              value={joinReported(result.file_type, result.architecture)}
            />
            <ResultFact label="Size" value={formatBytes(result.size_bytes)} />
            <ResultFact
              label="Sections"
              value={formatInteger(result.section_count)}
            />
            <ResultFact
              label="Imports"
              value={formatInteger(result.import_count)}
            />
            <ResultFact
              label="Signature"
              value={signatureLabel(result.signature_status)}
            />
            <ResultFact
              label="Duration"
              value={
                result.scan_duration_ms === null
                  ? 'Not reported'
                  : `${result.scan_duration_ms} ms`
              }
            />
          </div>
          <div className="mt-3 w-full rounded-xl border border-white/7 bg-white/[0.022] p-3 text-left">
            <p className="text-[10px] uppercase tracking-wider text-slate-600">
              Policy context
            </p>
            <p className="mt-1.5 text-xs text-slate-400">
              {result.decision_threshold === null
                ? 'Threshold not reported'
                : `Threshold ${formatPercent(result.decision_threshold)}`}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              {result.confidence === null
                ? 'Confidence not reported'
                : `Confidence ${formatPercent(result.confidence)}`}
            </p>
          </div>
        </div>

        <div className="space-y-6">
          <section aria-labelledby={contributorsId}>
            <div className="mb-3 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h3
                  id={contributorsId}
                  className="flex items-center gap-2 text-sm font-medium text-slate-200"
                >
                  <Layers3 className="size-4 text-violet-300" />
                  Model contributors
                </h3>
                <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-500">
                  Grouped contributions in model-margin space. A contributor does not prove that a specific observed API or string caused the verdict.
                </p>
              </div>
              <Badge
                variant="outline"
                className="w-fit border-white/10 font-mono text-slate-400"
              >
                {result.feature_count === null
                  ? 'Feature count not reported'
                  : `${result.feature_count.toLocaleString()} features`}
              </Badge>
            </div>
            {result.model_contributors.length ? (
              <div className="space-y-3">
                {result.model_contributors.map((item) => (
                  <div key={`${item.feature_group}-${item.contribution}`}>
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
              <UnavailableCopy>
                Model contribution data was not published for this result.
              </UnavailableCopy>
            )}
          </section>

          <section aria-labelledby={indicatorsId}>
            <h3
              id={indicatorsId}
              className="flex items-center gap-2 text-sm font-medium text-slate-200"
            >
              <FileCheck2 className="size-4 text-cyan-300" />
              Observed indicators
            </h3>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              Deterministic facts extracted independently from the model. Their absence is not proof of safety.
            </p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {result.observed_indicators.length ? (
                result.observed_indicators.map((signal) => (
                  <SignalCard
                    key={`${signal.family ?? 'general'}-${signal.title}`}
                    signal={signal}
                  />
                ))
              ) : (
                <div className="rounded-xl border border-dashed border-white/10 p-4 text-sm text-slate-500 sm:col-span-2">
                  No observed indicators were published. This is not a safety claim.
                </div>
              )}
            </div>
          </section>
        </div>
      </div>

      <div className="mt-6 grid gap-4 border-t border-white/8 pt-6 xl:grid-cols-2">
        <section
          aria-labelledby={qualityId}
          className="rounded-2xl border border-white/8 bg-black/10 p-5"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3
                id={qualityId}
                className="flex items-center gap-2 text-sm font-medium text-slate-200"
              >
                <ShieldCheck className="size-4 text-emerald-300" />
                Extraction quality
              </h3>
              <p className="mt-1 text-xs text-slate-500">
                Trust gates applied before model scoring
              </p>
            </div>
            <QualityBadge quality={result.quality} />
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
            <ResultFact
              label="Schema"
              value={booleanQuality(result.quality.schema_compatible)}
            />
            <ResultFact
              label="Parser agreement"
              value={parserAgreement(result.quality.parser_disagreement)}
            />
            <ResultFact
              label="Features"
              value={formatInteger(result.quality.feature_count)}
            />
          </div>
          {result.quality.warnings.length > 0 && (
            <Alert className="mt-4 border-amber-300/15 bg-amber-300/[0.045]">
              <AlertTriangle className="text-amber-300" />
              <AlertTitle className="text-amber-200">Quality warnings</AlertTitle>
              <AlertDescription className="text-slate-500">
                <ul className="list-disc space-y-1 pl-4">
                  {result.quality.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          )}
        </section>

        <section
          aria-labelledby={provenanceId}
          className="rounded-2xl border border-violet-300/10 bg-violet-300/[0.025] p-5"
        >
          <h3
            id={provenanceId}
            className="flex items-center gap-2 text-sm font-medium text-slate-200"
          >
            <Fingerprint className="size-4 text-violet-300" />
            Analysis provenance
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Immutable release and component identifiers
          </p>
          <dl className="mt-4 space-y-3">
            <ProvenanceRow
              label="Analysis release"
              value={result.provenance.analysis_release_id}
              emphasized
            />
            <ProvenanceRow
              label="Model"
              value={
                result.provenance.model_digest ??
                result.provenance.model_id ??
                result.model_name
              }
            />
            <ProvenanceRow
              label="Feature schema"
              value={
                result.provenance.feature_schema_digest ??
                result.provenance.feature_schema_id
              }
            />
            <ProvenanceRow
              label="Extractor"
              value={result.provenance.extractor_digest}
            />
            <ProvenanceRow
              label="Calibrator"
              value={result.provenance.calibrator_id}
            />
            <ProvenanceRow
              label="Policy"
              value={result.provenance.policy_id}
            />
          </dl>
        </section>
      </div>

      {result.limitations.length > 0 && (
        <Alert className="mt-4 border-cyan-300/12 bg-cyan-300/[0.035]">
          <Info className="text-cyan-300" />
          <AlertTitle className="text-slate-200">Result limitations</AlertTitle>
          <AlertDescription className="text-slate-500">
            <ul className="list-disc space-y-1 pl-4">
              {result.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}

      <div className="mt-5 grid gap-4 border-t border-white/8 pt-5 lg:grid-cols-[1fr_auto] lg:items-end">
        <div className="min-w-0">
          <p className="text-xs text-slate-500">SHA-256</p>
          <p className="mt-1 break-all font-mono text-xs leading-5 text-slate-300">
            {result.sha256 || 'Not reported'}
          </p>
          <p className="mt-2 text-xs text-slate-600">
            {result.model_name ?? 'Model id not reported'} · published{' '}
            {formatDate(result.scanned_at_utc, true)}
          </p>
        </div>
        <div
          className={`flex max-w-sm items-start gap-2 text-xs ${
            result.binary_retained === true
              ? 'text-amber-300'
              : 'text-emerald-300'
          }`}
        >
          <Trash2 className="mt-0.5 size-3.5 shrink-0" />
          {retentionLabel(result.binary_retained)}
        </div>
      </div>
    </div>
  );
}

function RiskGauge({
  probability,
  verdict,
  calibrated,
}: {
  probability: number | null;
  verdict: Verdict;
  calibrated: boolean;
}) {
  const color =
    verdict === 'likely_benign'
      ? '#6ee7b7'
      : verdict === 'needs_review'
        ? '#fcd34d'
        : verdict === 'inconclusive'
          ? '#cbd5e1'
          : '#fda4af';
  const safeProbability = probability === null ? 0 : Math.max(0, Math.min(1, probability));

  return (
    <div
      className="grid size-36 place-items-center rounded-full p-2"
      style={{
        background:
          probability === null
            ? 'rgba(255,255,255,.06)'
            : `conic-gradient(${color} ${safeProbability * 360}deg, rgba(255,255,255,.06) 0deg)`,
      }}
    >
      <div className="grid size-full place-items-center rounded-full border border-white/8 bg-[#0a0e1a]">
        <div>
          <p className="font-mono text-3xl font-semibold text-white">
            {probability === null ? '—' : formatPercent(probability)}
          </p>
          <p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">
            {calibrated ? 'calibrated risk' : 'model probability'}
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
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium">{signal.title}</p>
          {signal.family && (
            <p className="mt-1 text-[9px] uppercase tracking-wider opacity-55">
              {signal.family}
            </p>
          )}
        </div>
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

function ProvenanceRow({
  label,
  value,
  emphasized = false,
}: {
  label: string;
  value: string | null;
  emphasized?: boolean;
}) {
  return (
    <div className="grid gap-1 sm:grid-cols-[120px_1fr] sm:gap-3">
      <dt className="text-[11px] text-slate-600">{label}</dt>
      <dd
        className={`break-all font-mono text-[11px] leading-4 ${
          emphasized && value ? 'text-violet-200' : 'text-slate-400'
        }`}
      >
        {value ?? 'Not reported'}
      </dd>
    </div>
  );
}

function QualityBadge({ quality }: { quality: ExtractionQuality }) {
  const tone =
    quality.extraction === 'complete' && quality.schema_compatible !== false
      ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
      : quality.extraction === 'not_reported'
        ? 'border-white/10 bg-white/[0.035] text-slate-400'
        : 'border-amber-300/20 bg-amber-300/10 text-amber-200';
  const label = {
    complete: 'Complete',
    partial: 'Partial',
    unavailable: 'Unavailable',
    not_reported: 'Not reported',
  }[quality.extraction];
  return <Badge className={`border ${tone}`}>{label}</Badge>;
}

function UnavailableCopy({ children }: { children: string }) {
  return (
    <p className="rounded-xl border border-dashed border-white/10 p-4 text-sm text-slate-500">
      {children}
    </p>
  );
}

function joinReported(left: string | null, right: string | null) {
  return [left, right].filter(Boolean).join(' / ') || 'Not reported';
}

function formatInteger(value: number | null) {
  return value === null ? 'Not reported' : value.toLocaleString();
}

function booleanQuality(value: boolean | null) {
  if (value === null) return 'Not reported';
  return value ? 'Compatible' : 'Mismatch';
}

function parserAgreement(disagreement: boolean | null) {
  if (disagreement === null) return 'Not reported';
  return disagreement ? 'Disagreement' : 'Agreed';
}

function signatureLabel(status: ScanResult['signature_status']) {
  return {
    absent: 'Absent',
    valid_trusted: 'Valid / trusted',
    valid_untrusted: 'Valid / untrusted',
    invalid: 'Invalid',
    unknown_offline: 'Unknown offline',
    not_reported: 'Not reported',
  }[status];
}

function retentionLabel(retained: boolean | null) {
  if (retained === true) {
    return 'The sample remains in private quarantine under the server retention policy.';
  }
  if (retained === false) {
    return 'The sample was deleted from quarantine under the server retention policy.';
  }
  return 'Quarantine retention was not reported by this scanner response.';
}
