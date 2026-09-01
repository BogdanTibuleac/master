'use client';

import { AlertTriangle } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  lifecycleLabel,
  ScanLifecyclePanel,
} from '@/components/scanner/scan-lifecycle';
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
  ScanJob,
} from '@/components/scanner/types';
import { isTerminalScanState } from '@/components/scanner/types';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  createIdempotencyKey,
  createScannerApi,
  ScannerApiError,
  sha256File,
} from '@/lib/scanner-api';

type WorkflowPhase =
  | 'idle'
  | 'creating'
  | 'hashing'
  | 'uploading'
  | 'sealing'
  | 'polling';

const pollingIntervalMs = 1_250;
const maximumTransientPollingErrors = 5;

export function ScannerWorkspace({
  apiUrl,
  connection,
  onRetryConnection,
}: {
  apiUrl: string;
  connection: ConnectionState;
  onRetryConnection: () => void;
}) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const historyRequestRef = useRef<AbortController | null>(null);
  const workflowRequestRef = useRef<AbortController | null>(null);
  const client = useMemo(() => createScannerApi(apiUrl), [apiUrl]);
  const [file, setFile] = useState<File | null>(null);
  const [phase, setPhase] = useState<WorkflowPhase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<ScanJob | null>(null);
  const [history, setHistory] = useState<ScanJob[]>([]);
  const [historyState, setHistoryState] = useState<HistoryState>('loading');
  const [historyError, setHistoryError] = useState<string | null>(null);
  const busy = phase !== 'idle';

  const loadHistory = useCallback(async () => {
    historyRequestRef.current?.abort();
    const controller = new AbortController();
    historyRequestRef.current = controller;
    setHistoryState('loading');
    setHistoryError(null);

    try {
      const payload = await client.listScans(12, controller.signal);
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
      if (historyRequestRef.current === controller) {
        historyRequestRef.current = null;
      }
    }
  }, [client]);

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

  useEffect(
    () => () => {
      workflowRequestRef.current?.abort();
      historyRequestRef.current?.abort();
    },
    [],
  );

  useEffect(() => {
    if (activeScan && isTerminalScanState(activeScan.status)) {
      terminalRef.current?.focus();
    }
  }, [activeScan]);

  function chooseFile(candidate: File | null) {
    setError(null);
    setActiveScan(null);
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
      setError('Reconnect the scanner API before starting the scan.');
      return;
    }

    workflowRequestRef.current?.abort();
    const controller = new AbortController();
    workflowRequestRef.current = controller;
    setError(null);
    setActiveScan(null);
    setPhase('creating');

    try {
      const created = await client.createScan(
        {
          filename: file.name,
          size_bytes: file.size,
          content_type: file.type || 'application/octet-stream',
        },
        createIdempotencyKey(),
        controller.signal,
      );
      setActiveScan(created.scan);

      setPhase('hashing');
      const sha256 = await sha256File(file);

      setPhase('uploading');
      const receipt = await client.uploadFile(
        created.upload,
        file,
        controller.signal,
      );
      setActiveScan((current) =>
        current
          ? {
              ...current,
              status: 'upload_received',
              sha256,
              updated_at_utc: new Date().toISOString(),
            }
          : current,
      );

      setPhase('sealing');
      const sealed = await client.sealScan(
        created.scan.id,
        { sha256, size_bytes: file.size, ...receipt },
        controller.signal,
      );
      setActiveScan(sealed);
      setFile(null);

      if (!isTerminalScanState(sealed.status)) {
        setPhase('polling');
        const completed = await pollUntilTerminal(
          client.getScan,
          sealed,
          setActiveScan,
          controller.signal,
        );
        setActiveScan(completed);
      }
      await loadHistory();
    } catch (scanError) {
      if (controller.signal.aborted) return;
      setError(scanErrorMessage(scanError));
    } finally {
      if (workflowRequestRef.current === controller) {
        workflowRequestRef.current = null;
        setPhase('idle');
      }
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1.1fr_.9fr]">
        <ScanUploadCard
          connection={connection}
          error={error}
          file={file}
          busy={busy}
          phaseLabel={phaseLabel(phase, activeScan)}
          onClear={() => chooseFile(null)}
          onFileSelect={chooseFile}
          onRetryConnection={onRetryConnection}
          onSubmit={() => void submitScan()}
        />
        <SafetyBoundaryCard />
      </div>

      {activeScan && (
        <div
          ref={terminalRef}
          tabIndex={-1}
          aria-label={`Scan ${lifecycleLabel(activeScan.status)} for ${activeScan.filename}`}
          className="space-y-4 outline-none"
        >
          <ScanLifecyclePanel scan={activeScan} />
          {activeScan.result && <ScanResultPanel result={activeScan.result} />}
          {activeScan.status === 'complete' && !activeScan.result && (
            <Alert
              role="alert"
              className="border-amber-300/20 bg-amber-300/[0.06]"
            >
              <AlertTriangle className="text-amber-300" />
              <AlertTitle className="text-amber-200">
                Result manifest unavailable
              </AlertTitle>
              <AlertDescription className="text-slate-500">
                The workflow reported completion without a readable decision manifest. Refresh history or contact the scanner operator; no verdict is being inferred.
              </AlertDescription>
            </Alert>
          )}
        </div>
      )}

      <ScanHistoryCard
        error={
          connection === 'offline'
            ? 'Offline state: reconnect the scanner API to load persisted scan records.'
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

async function pollUntilTerminal(
  getScan: (scanId: string, signal?: AbortSignal) => Promise<ScanJob>,
  initial: ScanJob,
  onUpdate: (scan: ScanJob) => void,
  signal: AbortSignal,
) {
  let current = initial;
  let transientErrors = 0;
  while (!isTerminalScanState(current.status)) {
    await abortableDelay(pollingIntervalMs, signal);
    try {
      current = await getScan(current.id, signal);
      transientErrors = 0;
      onUpdate(current);
    } catch (error) {
      if (signal.aborted) throw error;
      transientErrors += 1;
      if (
        !(error instanceof ScannerApiError) ||
        error.status < 500 ||
        transientErrors >= maximumTransientPollingErrors
      ) {
        throw error;
      }
    }
  }
  return current;
}

function abortableDelay(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(resolve, milliseconds);
    signal.addEventListener(
      'abort',
      () => {
        window.clearTimeout(timer);
        reject(new DOMException('Polling aborted.', 'AbortError'));
      },
      { once: true },
    );
  });
}

function phaseLabel(phase: WorkflowPhase, scan: ScanJob | null) {
  return {
    idle: null,
    creating: 'Creating secure scan…',
    hashing: 'Calculating SHA-256…',
    uploading: 'Uploading directly to quarantine…',
    sealing: 'Sealing immutable upload…',
    polling: scan ? `${lifecycleLabel(scan.status)}…` : 'Waiting for analysis…',
  }[phase];
}

function scanErrorMessage(error: unknown) {
  return error instanceof Error
    ? error.message
    : 'The hostile-content workflow could not be completed.';
}
