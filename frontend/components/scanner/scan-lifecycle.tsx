import {
  AlertOctagon,
  Ban,
  Check,
  CheckCircle2,
  Circle,
  Clock3,
  CloudUpload,
  FileWarning,
  LoaderCircle,
  PackageCheck,
  ShieldCheck,
  TimerOff,
  XCircle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import {
  isTerminalScanState,
  scanLifecycleStates,
} from '@/components/scanner/types';
import type {
  ScanJob,
  ScanLifecycleState,
  TerminalScanState,
} from '@/components/scanner/types';
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

type LifecycleMetadata = {
  label: string;
  description: string;
  icon: LucideIcon;
};

const lifecycleMetadata: Record<ScanLifecycleState, LifecycleMetadata> = {
  awaiting_upload: {
    label: 'Awaiting upload',
    description: 'A private quarantine slot is ready for the file.',
    icon: CloudUpload,
  },
  upload_received: {
    label: 'Upload received',
    description: 'The direct object-store upload completed.',
    icon: PackageCheck,
  },
  validating: {
    label: 'Validating',
    description: 'Size, digest and PE format are being verified.',
    icon: ShieldCheck,
  },
  queued: {
    label: 'Queued',
    description: 'Durable orchestration accepted the immutable scan reference.',
    icon: Clock3,
  },
  extracting: {
    label: 'Extracting',
    description: 'A disposable isolated worker is inspecting the PE structure.',
    icon: LoaderCircle,
  },
  validating_features: {
    label: 'Validating features',
    description: 'The bounded feature envelope is checked against its schema.',
    icon: ShieldCheck,
  },
  scoring: {
    label: 'Scoring',
    description: 'The trusted decision service is evaluating validated features.',
    icon: LoaderCircle,
  },
  applying_policy: {
    label: 'Applying policy',
    description: 'Calibration, thresholds and corroborating evidence are applied.',
    icon: ShieldCheck,
  },
  publishing: {
    label: 'Publishing',
    description: 'An immutable result manifest is being committed.',
    icon: LoaderCircle,
  },
  complete: {
    label: 'Complete',
    description: 'The governed analysis result is ready.',
    icon: CheckCircle2,
  },
  rejected: {
    label: 'Rejected',
    description: 'The sample did not satisfy the supported input contract.',
    icon: Ban,
  },
  inconclusive: {
    label: 'Inconclusive',
    description: 'A trustworthy score could not be produced; this is not a benign result.',
    icon: FileWarning,
  },
  failed: {
    label: 'Failed',
    description: 'Infrastructure retries were exhausted before a result was committed.',
    icon: AlertOctagon,
  },
  cancelled: {
    label: 'Cancelled',
    description: 'Analysis was stopped by an authorized cancellation request.',
    icon: XCircle,
  },
  expired: {
    label: 'Expired',
    description: 'The upload grant expired before the scan was sealed.',
    icon: TimerOff,
  },
};

const terminalTone: Record<TerminalScanState, string> = {
  complete: 'border-emerald-300/20 bg-emerald-300/[0.06]',
  rejected: 'border-amber-300/20 bg-amber-300/[0.06]',
  inconclusive: 'border-amber-300/20 bg-amber-300/[0.06]',
  failed: 'border-rose-300/20 bg-rose-300/[0.06]',
  cancelled: 'border-slate-300/15 bg-white/[0.035]',
  expired: 'border-slate-300/15 bg-white/[0.035]',
};

export function lifecycleLabel(status: ScanLifecycleState) {
  return lifecycleMetadata[status].label;
}

export function lifecycleDescription(status: ScanLifecycleState) {
  return lifecycleMetadata[status].description;
}

export function LifecycleStatusBadge({ status }: { status: ScanLifecycleState }) {
  const tone =
    status === 'complete'
      ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
      : status === 'failed'
        ? 'border-rose-300/20 bg-rose-300/10 text-rose-200'
        : status === 'rejected' || status === 'inconclusive'
          ? 'border-amber-300/20 bg-amber-300/10 text-amber-200'
          : status === 'cancelled' || status === 'expired'
            ? 'border-white/10 bg-white/[0.04] text-slate-300'
            : 'border-cyan-300/20 bg-cyan-300/10 text-cyan-200';
  return <Badge className={`border ${tone}`}>{lifecycleLabel(status)}</Badge>;
}

export function ScanLifecyclePanel({ scan }: { scan: ScanJob }) {
  const currentIndex = currentPipelineIndex(scan);
  const inferredProgress =
    currentIndex === null
      ? null
      : (currentIndex / (scanLifecycleStates.length - 1)) * 100;
  const progress = scan.progress_percent ?? inferredProgress;
  const terminal = isTerminalScanState(scan.status);

  return (
    <Card className="glass-card overflow-hidden border-cyan-300/10">
      <CardHeader className="border-b border-white/8 pb-4">
        <CardTitle className="flex items-center gap-2 text-white">
          <Clock3 className="size-4 text-cyan-300" />
          Analysis lifecycle
        </CardTitle>
        <CardDescription className="break-all sm:break-normal">
          {scan.filename}
        </CardDescription>
        <CardAction>
          <LifecycleStatusBadge status={scan.status} />
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-5 pt-5">
        <output aria-live="polite" className="block">
          <div className="flex flex-col gap-3 rounded-xl border border-white/8 bg-black/10 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-cyan-300/8 text-cyan-200">
                {(() => {
                  const StatusIcon = lifecycleMetadata[scan.status].icon;
                  return (
                    <StatusIcon
                      className={
                        terminal || scan.status === 'queued'
                          ? 'size-4'
                          : 'size-4 animate-pulse'
                      }
                    />
                  );
                })()}
              </div>
              <div>
                <p className="text-sm font-medium text-slate-200">
                  {lifecycleLabel(scan.status)}
                </p>
                <p className="mt-1 text-xs leading-5 text-slate-500">
                  {lifecycleDescription(scan.status)}
                </p>
              </div>
            </div>
            <Badge
              variant="outline"
              className={
                scan.transport === 'direct_quarantine'
                  ? 'w-fit border-violet-300/20 text-violet-200'
                  : 'w-fit border-amber-300/20 text-amber-200'
              }
            >
              {scan.transport === 'direct_quarantine'
                ? 'Direct quarantine upload'
                : 'Local compatibility mode'}
            </Badge>
          </div>
        </output>

        {scan.transport === 'direct_quarantine' && (
          <section aria-label="Scan processing progress">
            <div className="mb-3 flex items-center justify-between gap-4">
              <p className="text-xs font-medium uppercase tracking-[0.14em] text-slate-500">
                Processing stages
              </p>
              {progress !== null && (
                <span className="font-mono text-[10px] text-slate-600">
                  Stage {Math.min((currentIndex ?? 0) + 1, scanLifecycleStates.length)} of{' '}
                  {scanLifecycleStates.length}
                </span>
              )}
            </div>
            {progress !== null && (
              <Progress
                value={progress}
                aria-label={`${lifecycleLabel(scan.status)} lifecycle progress`}
                className="mb-4 [&_[data-slot=progress-indicator]]:bg-cyan-300"
              />
            )}
            <ol className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
              {scanLifecycleStates.map((status, index) => {
                const isCurrent = scan.status === status;
                const isComplete = currentIndex !== null && index < currentIndex;
                return (
                  <li
                    key={status}
                    aria-current={isCurrent ? 'step' : undefined}
                    className={`flex min-w-0 items-center gap-2 rounded-lg border px-3 py-2 text-[11px] ${
                      isCurrent
                        ? 'border-cyan-300/25 bg-cyan-300/[0.07] text-cyan-100'
                        : isComplete
                          ? 'border-emerald-300/12 bg-emerald-300/[0.035] text-emerald-200/80'
                          : 'border-white/6 bg-white/[0.018] text-slate-600'
                    }`}
                  >
                    {isComplete ? (
                      <Check className="size-3.5 shrink-0" />
                    ) : isCurrent && !terminal ? (
                      <LoaderCircle className="size-3.5 shrink-0 animate-spin" />
                    ) : (
                      <Circle className="size-3 shrink-0" />
                    )}
                    <span className="truncate">{lifecycleLabel(status)}</span>
                  </li>
                );
              })}
            </ol>
          </section>
        )}

        {scan.analysis_release_id && (
          <div className="rounded-xl border border-violet-300/12 bg-violet-300/[0.04] p-4">
            <p className="text-[10px] uppercase tracking-[0.14em] text-violet-200">
              Pinned analysis release
            </p>
            <p className="mt-2 break-all font-mono text-xs leading-5 text-slate-300">
              {scan.analysis_release_id}
            </p>
            <p className="mt-2 text-[11px] leading-4 text-slate-500">
              Extractor, feature schema, model, calibration and policy stay fixed for this run.
            </p>
          </div>
        )}

        {isTerminalScanState(scan.status) && (
          <TerminalExplanation scan={scan} status={scan.status} />
        )}
      </CardContent>
    </Card>
  );
}

function TerminalExplanation({
  scan,
  status,
}: {
  scan: ScanJob;
  status: TerminalScanState;
}) {
  const Icon = lifecycleMetadata[status].icon;
  return (
    <Alert className={terminalTone[status]}>
      <Icon
        className={
          status === 'complete' ? 'text-emerald-300' : 'text-amber-300'
        }
      />
      <AlertTitle className="text-slate-200">
        {status === 'complete'
          ? 'Result manifest committed'
          : lifecycleLabel(status)}
      </AlertTitle>
      <AlertDescription className="text-slate-500">
        {scan.terminal_detail?.message ?? lifecycleDescription(status)}
        {status === 'inconclusive' && (
          <span className="mt-1 block font-medium text-amber-200/80">
            No safety claim should be inferred from this outcome.
          </span>
        )}
        {scan.terminal_detail?.code && (
          <span className="mt-2 block font-mono text-[10px] text-slate-600">
            {scan.terminal_detail.code}
          </span>
        )}
      </AlertDescription>
    </Alert>
  );
}

function currentPipelineIndex(scan: ScanJob) {
  const current = scanLifecycleStates.indexOf(
    scan.status as (typeof scanLifecycleStates)[number],
  );
  if (current >= 0) return current;
  if (!scan.last_completed_status) return null;
  const last = scanLifecycleStates.indexOf(
    scan.last_completed_status as (typeof scanLifecycleStates)[number],
  );
  return last >= 0 ? last : null;
}
