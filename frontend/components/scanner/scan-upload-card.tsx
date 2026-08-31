'use client';

import {
  AlertTriangle,
  CheckCircle2,
  FileSearch,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UploadCloud,
} from 'lucide-react';
import { useState } from 'react';
import type { ChangeEvent, DragEvent } from 'react';

import { formatBytes } from '@/components/scanner/formatters';
import type { ConnectionState } from '@/components/scanner/types';
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
import { Spinner } from '@/components/ui/spinner';

export const maximumScanBytes = 25 * 1024 * 1024;
export const supportedScanExtensions = [
  '.exe',
  '.dll',
  '.sys',
  '.scr',
  '.cpl',
  '.ocx',
];

type ScanUploadCardProps = {
  connection: ConnectionState;
  error: string | null;
  file: File | null;
  busy: boolean;
  phaseLabel: string | null;
  modeNotice: string | null;
  onClear: () => void;
  onFileSelect: (file: File | null) => void;
  onRetryConnection: () => void;
  onSubmit: () => void;
};

export function ScanUploadCard({
  connection,
  error,
  file,
  busy,
  phaseLabel,
  modeNotice,
  onClear,
  onFileSelect,
  onRetryConnection,
  onSubmit,
}: ScanUploadCardProps) {
  const [dragActive, setDragActive] = useState(false);

  function handleInput(event: ChangeEvent<HTMLInputElement>) {
    onFileSelect(event.target.files?.[0] ?? null);
    event.target.value = '';
  }

  function handleDrop(event: DragEvent<HTMLButtonElement>) {
    event.preventDefault();
    setDragActive(false);
    onFileSelect(event.dataTransfer.files?.[0] ?? null);
  }

  return (
    <Card className="glass-card overflow-hidden border-cyan-300/10">
      <CardHeader className="border-b border-white/8 pb-4">
        <CardTitle className="flex items-center gap-2 text-white">
          <FileSearch className="size-4 text-cyan-300" />
          Upload suspicious file
        </CardTitle>
        <CardDescription>
          Create a scan, upload directly to quarantine, then seal it for static analysis.
        </CardDescription>
        <CardAction>
          <Badge className="border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
            25 MB max
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-4 pt-5">
        <input
          id="suspicious-file"
          data-testid="scan-file-input"
          type="file"
          accept={supportedScanExtensions.join(',')}
          className="sr-only"
          onChange={handleInput}
          disabled={busy}
        />
        <button
          type="button"
          data-testid="scan-dropzone"
          aria-describedby="scan-file-requirements"
          disabled={busy}
          onClick={() => document.getElementById('suspicious-file')?.click()}
          onDragEnter={(event) => {
            event.preventDefault();
            setDragActive(true);
          }}
          onDragOver={(event) => event.preventDefault()}
          onDragLeave={(event) => {
            if (
              !event.currentTarget.contains(event.relatedTarget as Node | null)
            ) {
              setDragActive(false);
            }
          }}
          onDrop={handleDrop}
          className={`w-full rounded-2xl border border-dashed px-6 py-8 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-wait disabled:opacity-70 ${
            dragActive
              ? 'border-cyan-300/60 bg-cyan-300/10'
              : file
                ? 'border-emerald-300/30 bg-emerald-300/[0.06]'
                : 'border-white/12 bg-black/10 hover:border-cyan-300/30 hover:bg-cyan-300/[0.035]'
          }`}
        >
          <span
            className={`mx-auto grid size-14 place-items-center rounded-2xl border ${
              file
                ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200'
                : 'border-cyan-300/15 bg-cyan-300/8 text-cyan-200'
            }`}
          >
            {file ? (
              <CheckCircle2 className="size-6" />
            ) : (
              <UploadCloud className="size-6" />
            )}
          </span>
          {file ? (
            <>
              <span className="mt-4 block break-all text-sm font-medium text-white sm:truncate">
                {file.name}
              </span>
              <span className="mt-1 block font-mono text-xs text-slate-500">
                {formatBytes(file.size)} · press to choose another file
              </span>
            </>
          ) : (
            <>
              <span className="mt-4 block text-sm font-medium text-slate-200">
                Drop a PE file here or browse
              </span>
              <span
                id="scan-file-requirements"
                className="mt-1 block text-xs text-slate-500"
              >
                EXE, DLL, SYS, SCR, CPL or OCX
              </span>
            </>
          )}
        </button>

        {file && !busy && (
          <div className="flex justify-end">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-slate-500 hover:text-slate-200"
              onClick={onClear}
            >
              <Trash2 />
              Clear selection
            </Button>
          </div>
        )}

        {connection !== 'online' && (
          <Alert
            aria-live="polite"
            className={
              connection === 'offline'
                ? 'border-amber-300/20 bg-amber-300/[0.06]'
                : 'border-cyan-300/15 bg-cyan-300/[0.045]'
            }
          >
            {connection === 'offline' ? (
              <AlertTriangle className="text-amber-300" />
            ) : (
              <RefreshCw className="animate-spin text-cyan-300" />
            )}
            <AlertTitle className="text-slate-200">
              {connection === 'offline'
                ? 'Scanner API is offline'
                : 'Checking scanner availability'}
            </AlertTitle>
            <AlertDescription className="text-slate-500">
              {connection === 'offline'
                ? 'Offline state: your file has not been uploaded. Reconnect the scanner API before starting a scan.'
                : 'Scanning will be available as soon as the local API responds.'}
            </AlertDescription>
            {connection === 'offline' && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-3 border-white/10 bg-white/[0.035] text-slate-200"
                onClick={onRetryConnection}
              >
                <RefreshCw />
                Retry connection
              </Button>
            )}
          </Alert>
        )}

        {modeNotice && (
          <Alert
            aria-live="polite"
            className="border-amber-300/20 bg-amber-300/[0.06]"
          >
            <AlertTriangle className="text-amber-300" />
            <AlertTitle className="text-amber-200">
              Local compatibility mode
            </AlertTitle>
            <AlertDescription className="text-slate-500">
              {modeNotice}
            </AlertDescription>
          </Alert>
        )}

        {error && (
          <Alert
            role="alert"
            variant="destructive"
            className="border-rose-300/20 bg-rose-300/[0.06]"
          >
            <AlertTriangle />
            <AlertTitle>Scan could not start</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Button
          data-testid="start-scan"
          className="h-11 w-full bg-cyan-300 text-slate-950 shadow-[0_0_28px_rgba(103,232,249,.14)] hover:bg-cyan-200"
          disabled={!file || busy || connection !== 'online'}
          onClick={onSubmit}
          aria-describedby={busy ? 'scan-progress-status' : undefined}
        >
          {busy ? <Spinner /> : <ShieldCheck />}
          {busy ? (phaseLabel ?? 'Starting secure scan…') : 'Start secure scan'}
        </Button>
        {busy && (
          <output
            id="scan-progress-status"
            className="block text-center text-xs text-slate-500"
          >
            {phaseLabel ?? 'The hostile-content workflow is in progress.'} Do not close this page.
          </output>
        )}
      </CardContent>
    </Card>
  );
}
