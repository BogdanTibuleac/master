'use client';

import { Activity, ArrowUpRight, Binary, Box, Check, ChevronRight, CircleDot, Database, FlaskConical, Gauge, GitBranch, HardDrive, Menu, RefreshCw, ScanSearch, ServerCog, ShieldCheck, Sparkles, TerminalSquare } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

type DatasetStatus = { name: string; raw_directory: string; archive_available: boolean; manifest_available: boolean; extracted_files_available: boolean; ready: boolean };
type MetricSet = { accuracy: number; precision: number; recall: number; f1: number; roc_auc: number; average_precision: number; samples: number };
type BaselineStatus = { available: boolean; metrics: { test: MetricSet; validation: MetricSet; features: number; best_iteration: number; created_at_utc: string } | null };
type ConnectionState = 'checking' | 'online' | 'offline';

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://127.0.0.1:8000';
const stages = [
  { label: 'Project foundation', detail: 'Configuration & quality tooling', state: 'complete' },
  { label: 'Data pipeline', detail: 'Validated, streamed & reproducible', state: 'complete' },
  { label: 'Baseline model', detail: 'LightGBM training & evaluation', state: 'complete' },
  { label: 'Robustness study', detail: 'Controlled feature perturbations', state: 'next' },
];

export default function Home() {
  const [dataset, setDataset] = useState<DatasetStatus | null>(null);
  const [baseline, setBaseline] = useState<BaselineStatus | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('checking');
  const [action, setAction] = useState<'verify' | 'smoke-test' | null>(null);
  const [notice, setNotice] = useState('Ready for the baseline model workflow.');

  const refreshStatus = useCallback(async () => {
    setConnection('checking');
    try {
      const [datasetResponse, baselineResponse] = await Promise.all([
        fetch(`${apiUrl}/api/v1/datasets/ember2018/status`),
        fetch(`${apiUrl}/api/v1/experiments/baseline`),
      ]);
      if (!datasetResponse.ok || !baselineResponse.ok) throw new Error('Backend returned an error');
      setDataset((await datasetResponse.json()) as DatasetStatus);
      setBaseline((await baselineResponse.json()) as BaselineStatus);
      setConnection('online');
    } catch {
      setConnection('offline');
    }
  }, []);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);

  async function runAction(nextAction: 'verify' | 'smoke-test') {
    setAction(nextAction);
    try {
      const response = await fetch(`${apiUrl}/api/v1/datasets/ember2018/${nextAction}`, { method: 'POST' });
      if (!response.ok) throw new Error('The operation could not be completed.');
      const result = await response.json();
      setNotice(nextAction === 'verify' ? 'Dataset provenance and extracted files verified.' : `Real sample vectorized: ${result.feature_count.toLocaleString()} finite features.`);
      await refreshStatus();
    } catch {
      setNotice('Connect the local backend on port 8000 to run this check.');
    } finally {
      setAction(null);
    }
  }

  const ready = dataset?.ready ?? true;
  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="noise-layer" aria-hidden="true" />
      <div className="mx-auto grid min-h-screen max-w-[1600px] lg:grid-cols-[248px_1fr]">
        <aside className="hidden border-r border-white/8 bg-sidebar/75 px-5 py-6 backdrop-blur-xl lg:flex lg:flex-col">
          <Brand />
          <nav className="mt-10 space-y-1" aria-label="Main navigation">
            <NavItem icon={Gauge} label="Overview" active />
            <NavItem icon={Database} label="Datasets" />
            <NavItem icon={FlaskConical} label="Experiments" />
            <NavItem icon={ScanSearch} label="Robustness" />
            <NavItem icon={GitBranch} label="Runs" />
          </nav>
          <div className="mt-auto rounded-2xl border border-cyan-300/15 bg-cyan-300/[0.045] p-4">
            <div className="flex items-center gap-2 text-xs font-medium text-cyan-200"><Sparkles className="size-3.5" />MVP progress</div>
            <div className="mt-3 flex items-end justify-between"><span className="font-mono text-2xl font-semibold text-white">60%</span><span className="text-xs text-slate-400">3 of 5 phases</span></div>
            <Progress value={60} className="mt-3 [&_[data-slot=progress-indicator]]:bg-cyan-300" />
          </div>
        </aside>

        <section className="relative min-w-0 overflow-hidden">
          <div className="orb orb-one" aria-hidden="true" /><div className="orb orb-two" aria-hidden="true" />
          <header className="relative z-10 flex h-20 items-center justify-between border-b border-white/8 px-5 sm:px-8 xl:px-12">
            <div className="flex items-center gap-3 lg:hidden"><Button variant="ghost" size="icon" aria-label="Open navigation"><Menu /></Button><Brand compact /></div>
            <div className="hidden lg:block"><p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Research workspace</p><p className="mt-1 text-sm text-slate-300">Static malware classifier robustness</p></div>
            <div className="flex items-center gap-3">
              <ConnectionPill state={connection} />
              <Button variant="outline" size="sm" onClick={() => void refreshStatus()} aria-label="Refresh backend status" className="border-white/10 bg-white/[0.035] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className={connection === 'checking' ? 'animate-spin' : ''} /><span className="hidden sm:inline">Refresh</span></Button>
            </div>
          </header>

          <div className="relative z-10 px-5 py-8 sm:px-8 xl:px-12 xl:py-10">
            <div className="flex flex-col justify-between gap-6 xl:flex-row xl:items-end">
              <div>
                <div className="mb-3 flex items-center gap-2"><Badge className="border border-violet-300/20 bg-violet-300/10 text-violet-200">LAB / 01</Badge><span className="font-mono text-xs text-slate-500">EMBER2018 · FEATURE V2</span></div>
                <h1 className="max-w-3xl text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl xl:text-[46px] xl:leading-[1.05]">Build a classifier that stays reliable <span className="text-gradient">under pressure.</span></h1>
                <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">One surface for dataset integrity, baseline performance, and safe feature-space robustness experiments.</p>
              </div>
              <div className="flex gap-3">
                <Button variant="outline" className="h-10 border-white/10 bg-white/[0.035] px-4 text-slate-200 hover:bg-white/[0.07]" onClick={() => void runAction('verify')} disabled={action !== null}><ShieldCheck />{action === 'verify' ? 'Verifying…' : 'Verify dataset'}</Button>
                <Button className="h-10 bg-cyan-300 px-4 text-slate-950 shadow-[0_0_28px_rgba(103,232,249,.16)] hover:bg-cyan-200" onClick={() => void runAction('smoke-test')} disabled={action !== null}><TerminalSquare />Smoke test</Button>
              </div>
            </div>

            <div className="mt-9 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard icon={Database} eyebrow="Dataset" value={ready ? 'Ready' : 'Attention'} detail="1M PE feature records" tone="cyan" />
              <MetricCard icon={Binary} eyebrow="Feature contract" value="2,381" detail="Finite float32 inputs" tone="violet" />
              <MetricCard icon={HardDrive} eyebrow="Local footprint" value="8.4 GiB" detail="Verified & Git-ignored" tone="emerald" />
              <MetricCard icon={Activity} eyebrow="Baseline ROC-AUC" value={baseline?.available ? formatScore(baseline.metrics?.test.roc_auc) : 'Pending'} detail={baseline?.available ? `${baseline.metrics?.test.samples.toLocaleString()} held-out samples` : 'Run malware-train to populate'} tone="cyan" />
            </div>

            <div className="mt-4 grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
              <Card className="glass-card min-h-[350px]">
                <CardHeader className="border-b border-white/8 pb-4"><CardTitle className="flex items-center gap-2 text-white"><Activity className="size-4 text-cyan-300" />Development path</CardTitle><CardDescription>Fastest route to a defensible local MVP</CardDescription><CardAction><Badge variant="outline" className="border-white/10 text-slate-400">Active</Badge></CardAction></CardHeader>
                <CardContent className="pt-5"><div className="space-y-1">{stages.map((stage, index) => <PipelineStage key={stage.label} {...stage} index={index + 1} />)}</div></CardContent>
              </Card>
              <Card className="glass-card">
                <CardHeader className="border-b border-white/8 pb-4"><CardTitle className="flex items-center gap-2 text-white"><ServerCog className="size-4 text-violet-300" />Runtime</CardTitle><CardDescription>Local backend and data boundary</CardDescription></CardHeader>
                <CardContent className="space-y-4 pt-5">
                  <RuntimeRow label="API" value={connection === 'online' ? 'Online' : 'Awaiting local API'} /><RuntimeRow label="Archive" value={dataset?.archive_available === false ? 'Missing' : 'Verified'} /><RuntimeRow label="Manifest" value={dataset?.manifest_available === false ? 'Missing' : 'SHA-256'} /><RuntimeRow label="Model" value={baseline?.available ? 'Trained' : 'LightGBM ready'} />
                  <div className="rounded-xl border border-white/8 bg-black/15 p-4"><div className="flex items-center gap-2 text-xs text-slate-400"><CircleDot className="size-3.5 text-emerald-300" />Latest signal</div><p className="mt-2 text-sm leading-5 text-slate-200">{notice}</p></div>
                </CardContent>
              </Card>
            </div>

            <div className="mt-4 flex flex-col gap-3 rounded-2xl border border-white/8 bg-white/[0.025] p-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl bg-violet-300/10 text-violet-200"><Box className="size-4" /></div><div><p className="text-sm font-medium text-slate-200">Next milestone</p><p className="text-xs text-slate-500">Measure resilience under controlled feature perturbations</p></div></div>
              <Button variant="ghost" className="justify-start text-cyan-200 hover:bg-cyan-300/8 hover:text-cyan-100">View implementation path <ArrowUpRight /></Button>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className="flex items-center gap-3"><div className="relative grid size-9 place-items-center overflow-hidden rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><ShieldCheck className="size-[18px]" /><span className="absolute inset-x-1 bottom-0 h-px bg-cyan-200/60" /></div>{!compact && <div><p className="text-sm font-semibold tracking-[-0.02em] text-white">Aegis Lab</p><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">ML robustness</p></div>}</div>;
}

function NavItem({ icon: Icon, label, active = false }: { icon: typeof Gauge; label: string; active?: boolean }) {
  return <button type="button" className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors ${active ? 'bg-cyan-300/10 text-cyan-100' : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-300'}`}><Icon className="size-4" />{label}{active && <ChevronRight className="ml-auto size-3.5" />}</button>;
}

function ConnectionPill({ state }: { state: ConnectionState }) {
  const label = state === 'online' ? 'API online' : state === 'checking' ? 'Checking API' : 'Local API offline';
  return <div className="flex items-center gap-2 rounded-full border border-white/8 bg-white/[0.035] px-3 py-1.5 text-xs text-slate-400"><span className={`size-1.5 rounded-full ${state === 'online' ? 'bg-emerald-300 shadow-[0_0_8px_#6ee7b7]' : state === 'checking' ? 'animate-pulse bg-amber-300' : 'bg-slate-600'}`} />{label}</div>;
}

function MetricCard({ icon: Icon, eyebrow, value, detail, tone }: { icon: typeof Database; eyebrow: string; value: string; detail: string; tone: 'cyan' | 'violet' | 'emerald' }) {
  const tones = { cyan: 'bg-cyan-300/10 text-cyan-200 border-cyan-300/15', violet: 'bg-violet-300/10 text-violet-200 border-violet-300/15', emerald: 'bg-emerald-300/10 text-emerald-200 border-emerald-300/15' };
  return <Card className="glass-card group min-h-[150px] transition-transform duration-300 hover:-translate-y-0.5"><CardContent className="flex h-full items-start justify-between pt-1"><div><p className="text-xs font-medium uppercase tracking-[0.15em] text-slate-500">{eyebrow}</p><p className="mt-4 font-mono text-3xl font-semibold tracking-[-0.05em] text-white">{value}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></div><div className={`grid size-10 place-items-center rounded-xl border ${tones[tone]}`}><Icon className="size-4" /></div></CardContent></Card>;
}

function PipelineStage({ label, detail, state, index }: { label: string; detail: string; state: string; index: number }) {
  const complete = state === 'complete'; const next = state === 'next';
  return <div className="group flex items-center gap-4 rounded-xl px-2 py-3 transition-colors hover:bg-white/[0.025]"><div className={`grid size-8 shrink-0 place-items-center rounded-full border font-mono text-xs ${complete ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200' : next ? 'border-cyan-300/30 bg-cyan-300/10 text-cyan-100 shadow-[0_0_18px_rgba(103,232,249,.12)]' : 'border-white/8 bg-white/[0.025] text-slate-600'}`}>{complete ? <Check className="size-3.5" /> : index.toString().padStart(2, '0')}</div><div className="min-w-0 flex-1"><p className={`text-sm font-medium ${next ? 'text-cyan-100' : complete ? 'text-slate-200' : 'text-slate-500'}`}>{label}</p><p className="mt-0.5 truncate text-xs text-slate-600">{detail}</p></div><Badge variant="outline" className={`border-white/8 text-[10px] uppercase tracking-wider ${complete ? 'text-emerald-300' : next ? 'text-cyan-200' : 'text-slate-600'}`}>{complete ? 'Done' : next ? 'Next' : 'Queued'}</Badge></div>;
}

function RuntimeRow({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between border-b border-white/6 pb-3 text-sm last:border-0"><span className="text-slate-500">{label}</span><span className="font-mono text-xs text-slate-200">{value}</span></div>;
}

function formatScore(value?: number) {
  return value === undefined ? '—' : value.toFixed(3);
}
