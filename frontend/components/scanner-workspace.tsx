'use client';

import { CheckCircle2 } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

import {
  maximumScanBytes,
  ScanUploadCard,
  supportedScanExtensions,
} from '@/components/scanner/scan-upload-card';
import { ScanHistoryCard } from '@/components/scanner/scan-history-card';
import { ScanResultPanel } from '@/components/scanner/scan-result';
import { SafetyBoundaryCard } from '@/components/scanner/safety-boundary-card';
import type {
  ConnectionState,
  HistoryState,
  ScanHistory,
  ScanResult,
} from '@/components/scanner/types';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

export function ScannerWorkspace({
  apiUrl,
  connection,
  onRetryConnection,
}: {
  apiUrl: string;
  connection: ConnectionState;
  onRetryConnection: () => void;
}) {
  const resultRef = useRef<HTMLDivElement>(null);
  const historyRequestRef = useRef<AbortController | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [historyState, setHistoryState] = useState<HistoryState>('loading');
  const [historyError, setHistoryError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    historyRequestRef.current?.abort();
    const controller = new AbortController();
    historyRequestRef.current = controller;
    setHistoryState('loading');
    setHistoryError(null);

    try {
      const response = await fetch(`${apiUrl}/api/v1/scans?limit=12`, {
        signal: controller.signal,
      });
      if (!response.ok)
        throw new Error('The scanner API did not return recent results.');
      const payload = (await response.json()) as ScanHistory;
      setHistory(payload.items);
      setHistoryState('ready');
    } catch (historyLoadError) {
      if (controller.signal.aborted) return;
      setHistoryError(
        historyLoadError instanceof Error
          ? historyLoadError.message
          : 'Recent scan results could not be loaded.',
      );
      setHistoryState('error');
    } finally {
      if (historyRequestRef.current === controller)
        historyRequestRef.current = null;
    }
  }, [apiUrl]);

  useEffect(() => {
    if (connection !== 'online') {
      historyRequestRef.current?.abort();
      return;
    }

    const timer = window.setTimeout(() => void loadHistory(), 0);
    return () => {
      window.clearTimeout(timer);
      historyRequestRef.current?.abort();
    };
  }, [connection, loadHistory]);

  useEffect(() => {
    if (result) resultRef.current?.focus();
  }, [result]);

  function chooseFile(candidate: File | null) {
    setError(null);
    setResult(null);
    if (!candidate) {
      setFile(null);
      return;
    }

    const extension = `.${candidate.name.split('.').pop()?.toLowerCase() ?? ''}`;
    if (!supportedScanExtensions.includes(extension)) {
      setFile(null);
      setError(
        `Unsupported file type. Choose ${supportedScanExtensions.join(', ')}.`,
      );
      return;
    }
    if (candidate.size > maximumScanBytes) {
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

  async function submitScan() {
    if (!file) {
      setError('Choose a Windows PE file before starting the scan.');
      return;
    }
    if (connection !== 'online') {
      setError('Reconnect the local scanner API before starting the scan.');
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
        const payload = (await response.json().catch(() => null)) as {
          detail?: string;
        } | null;
        throw new Error(payload?.detail ?? 'The file could not be scanned.');
      }
      const payload = (await response.json()) as ScanResult;
      setResult(payload);
      setFile(null);
      await loadHistory();
    } catch (scanError) {
      setError(
        scanError instanceof Error
          ? scanError.message
          : 'The file could not be scanned.',
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1.1fr_.9fr]">
        <ScanUploadCard
          connection={connection}
          error={error}
          file={file}
          submitting={submitting}
          onClear={() => chooseFile(null)}
          onFileSelect={chooseFile}
          onRetryConnection={onRetryConnection}
          onSubmit={() => void submitScan()}
        />
        <SafetyBoundaryCard />
      </div>

      {result && (
        <div
          ref={resultRef}
          tabIndex={-1}
          aria-label={`Scan completed for ${result.filename}`}
          className="space-y-4 outline-none"
        >
          <Alert
            aria-live="polite"
            className="border-emerald-300/20 bg-emerald-300/[0.06]"
          >
            <CheckCircle2 className="text-emerald-300" />
            <AlertTitle className="text-emerald-200">
              Static scan completed
            </AlertTitle>
            <AlertDescription className="text-slate-400">
              The uploaded binary was discarded. Review the verdict and model
              evidence below.
            </AlertDescription>
          </Alert>
          <ScanResultPanel result={result} />
        </div>
      )}

      <ScanHistoryCard
        error={
          connection === 'offline'
            ? 'Reconnect the local API to load persisted scan results.'
            : historyError
        }
        history={history}
        state={connection === 'offline' ? 'error' : historyState}
        onRefresh={() =>
          connection === 'offline' ? onRetryConnection() : void loadHistory()
        }
      />
    </div>
  );
}
