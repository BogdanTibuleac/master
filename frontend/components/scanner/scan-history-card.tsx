'use client';

import {
  AlertTriangle,
  Clock3,
  Eye,
  FileSearch,
  RefreshCw,
} from 'lucide-react';
import { useState } from 'react';

import {
  formatBytes,
  formatDate,
  formatPercent,
} from '@/components/scanner/formatters';
import {
  LifecycleStatusBadge,
  ScanLifecyclePanel,
} from '@/components/scanner/scan-lifecycle';
import { ScanResultDetails } from '@/components/scanner/scan-result';
import type { HistoryState, ScanJob } from '@/components/scanner/types';
import { VerdictBadge } from '@/components/scanner/verdict-badge';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

type ScanHistoryCardProps = {
  error: string | null;
  history: ScanJob[];
  state: HistoryState;
  onRefresh: () => void;
};

export function ScanHistoryCard({
  error,
  history,
  state,
  onRefresh,
}: ScanHistoryCardProps) {
  const [selected, setSelected] = useState<ScanJob | null>(null);
  const loadingWithoutData = state === 'loading' && history.length === 0;
  const failedWithoutData = state === 'error' && history.length === 0;

  return (
    <>
      <Card className="glass-card">
        <CardHeader className="border-b border-white/8 pb-4">
          <CardTitle className="flex items-center gap-2 text-white">
            <Clock3 className="size-4 text-violet-300" />
            Recent scans
          </CardTitle>
          <CardDescription>
            Lifecycle, provenance and decisions; quarantine retention follows policy
          </CardDescription>
          <CardAction className="flex items-center gap-2">
            {history.length > 0 && (
              <Badge
                variant="outline"
                className="hidden border-white/10 text-slate-500 sm:inline-flex"
              >
                {history.length} shown
              </Badge>
            )}
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-slate-400 hover:text-white"
              onClick={onRefresh}
              disabled={state === 'loading'}
            >
              <RefreshCw
                className={state === 'loading' ? 'animate-spin' : ''}
              />
              Refresh
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="pt-4">
          {loadingWithoutData ? (
            <HistorySkeleton />
          ) : failedWithoutData ? (
            <HistoryError error={error} onRetry={onRefresh} />
          ) : history.length ? (
            <>
              {state === 'error' && (
                <Alert
                  aria-live="polite"
                  className="mb-4 border-amber-300/20 bg-amber-300/[0.06]"
                >
                  <AlertTriangle className="text-amber-300" />
                  <AlertTitle className="text-slate-200">
                    Could not refresh scan history
                  </AlertTitle>
                  <AlertDescription className="text-slate-500">
                    {error ?? 'Showing the most recently loaded scan records.'}
                  </AlertDescription>
                </Alert>
              )}
              <div className="space-y-3 md:hidden">
                {history.map((item) => (
                  <HistoryCard
                    key={item.id}
                    item={item}
                    onSelect={setSelected}
                  />
                ))}
              </div>
              <div className="hidden overflow-x-auto md:block">
                <Table>
                  <TableHeader>
                    <TableRow className="border-white/8 hover:bg-transparent">
                      <TableHead className="text-slate-500">File</TableHead>
                      <TableHead className="text-slate-500">State / decision</TableHead>
                      <TableHead className="text-right text-slate-500">
                        Risk
                      </TableHead>
                      <TableHead className="text-right text-slate-500">
                        Updated
                      </TableHead>
                      <TableHead>
                        <span className="sr-only">Details</span>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {history.map((item) => (
                      <TableRow
                        key={item.id}
                        className="border-white/6 hover:bg-white/[0.025]"
                      >
                        <TableCell>
                          <p className="max-w-[260px] truncate font-medium text-slate-200">
                            {item.filename}
                          </p>
                          <p className="mt-1 font-mono text-[10px] text-slate-600">
                            {shortDigest(item.sha256)}
                          </p>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap items-center gap-2">
                            <LifecycleStatusBadge status={item.status} />
                            {item.result && (
                              <VerdictBadge verdict={item.result.verdict} />
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right font-mono text-slate-200">
                          {riskLabel(item)}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-right text-xs text-slate-500">
                          {formatDate(item.updated_at_utc)}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon-sm"
                            className="text-slate-400 hover:text-cyan-100"
                            aria-label={`View lifecycle details for ${item.filename}`}
                            onClick={() => setSelected(item)}
                          >
                            <Eye />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          ) : (
            <Empty className="border border-white/10 py-9">
              <EmptyHeader>
                <EmptyMedia
                  variant="icon"
                  className="bg-white/[0.035] text-slate-500"
                >
                  <FileSearch />
                </EmptyMedia>
                <EmptyTitle className="text-slate-300">
                  No scans recorded yet
                </EmptyTitle>
                <EmptyDescription className="text-slate-600">
                  Created scans will appear here while they move through upload, extraction and decision stages.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto border-white/10 bg-[#111725] p-0 text-slate-200 shadow-2xl sm:max-w-6xl">
          {selected && (
            <>
              <DialogHeader className="border-b border-white/8 px-5 py-5 pr-14 sm:px-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <DialogTitle className="break-all text-lg text-white sm:break-normal">
                      {selected.filename}
                    </DialogTitle>
                    <DialogDescription className="mt-2 text-slate-500">
                      Updated {formatDate(selected.updated_at_utc, true)} ·{' '}
                      {formatBytes(selected.size_bytes)}
                    </DialogDescription>
                  </div>
                  <LifecycleStatusBadge status={selected.status} />
                </div>
              </DialogHeader>
              <div className="space-y-4 px-5 pb-6 sm:px-6">
                <ScanLifecyclePanel scan={selected} />
                {selected.result && (
                  <div className="rounded-2xl border border-white/8 bg-black/10 p-5 sm:p-6">
                    <ScanResultDetails result={selected.result} />
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function HistoryCard({
  item,
  onSelect,
}: {
  item: ScanJob;
  onSelect: (item: ScanJob) => void;
}) {
  return (
    <article className="rounded-xl border border-white/8 bg-white/[0.022] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="break-all text-sm font-medium text-slate-200">
            {item.filename}
          </p>
          <p className="mt-1 font-mono text-[10px] text-slate-600">
            {shortDigest(item.sha256)}
          </p>
        </div>
        <LifecycleStatusBadge status={item.status} />
      </div>
      {item.result && (
        <div className="mt-3">
          <VerdictBadge verdict={item.result.verdict} />
        </div>
      )}
      <div className="mt-4 flex items-end justify-between gap-4 border-t border-white/6 pt-3">
        <div>
          <p className="font-mono text-sm text-slate-200">
            {riskLabel(item)}
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {formatDate(item.updated_at_utc)}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="border-white/10 bg-white/[0.035] text-slate-200"
          onClick={() => onSelect(item)}
          aria-label={`View lifecycle details for ${item.filename}`}
        >
          <Eye />
          View details
        </Button>
      </div>
    </article>
  );
}

function HistorySkeleton() {
  return (
    <output aria-label="Loading scan history" className="block space-y-3 py-2">
      {[0, 1, 2].map((item) => (
        <div
          key={item}
          className="grid grid-cols-[1fr_90px] items-center gap-4 rounded-xl border border-white/6 p-4 md:grid-cols-[1fr_220px_70px_120px_36px]"
        >
          <div className="space-y-2">
            <Skeleton className="h-4 w-40 bg-white/[0.06]" />
            <Skeleton className="h-2.5 w-28 bg-white/[0.04]" />
          </div>
          <Skeleton className="h-6 w-full bg-white/[0.05]" />
          <Skeleton className="hidden h-4 bg-white/[0.05] md:block" />
          <Skeleton className="hidden h-4 bg-white/[0.05] md:block" />
          <Skeleton className="hidden size-7 bg-white/[0.05] md:block" />
        </div>
      ))}
      <span className="sr-only">Loading scan history</span>
    </output>
  );
}

function HistoryError({
  error,
  onRetry,
}: {
  error: string | null;
  onRetry: () => void;
}) {
  return (
    <Empty className="border border-amber-300/15 bg-amber-300/[0.035] py-9">
      <EmptyHeader>
        <EmptyMedia variant="icon" className="bg-amber-300/10 text-amber-300">
          <AlertTriangle />
        </EmptyMedia>
        <EmptyTitle className="text-slate-200">
          Scan history is unavailable
        </EmptyTitle>
        <EmptyDescription className="text-slate-500">
          {error ?? 'The scanner API did not return recent scan records.'}
        </EmptyDescription>
      </EmptyHeader>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="border-white/10 bg-white/[0.035] text-slate-200"
        onClick={onRetry}
      >
        <RefreshCw />
        Try again
      </Button>
    </Empty>
  );
}

function riskLabel(item: ScanJob) {
  const risk =
    item.result?.calibrated_risk_score ?? item.result?.malware_probability;
  if (risk === null || risk === undefined) return '—';
  return `${formatPercent(risk)}${
    item.result?.calibrated_risk_score === null ? ' model' : ''
  }`;
}

function shortDigest(value: string | null) {
  return value ? `${value.slice(0, 16)}…` : 'Digest pending';
}
