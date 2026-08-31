'use client';

import { Activity, ArrowUpRight, Binary, Box, Check, ChevronRight, CircleDot, Database, FlaskConical, Gauge, GitBranch, HardDrive, Menu, RefreshCw, ScanSearch, ServerCog, ShieldCheck, Sparkles, TerminalSquare } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

type DatasetStatus = { name: string; raw_directory: string; archive_available: boolean; manifest_available: boolean; extracted_files_available: boolean; ready: boolean };
type MetricSet = { accuracy: number; precision: number; recall: number; f1: number; roc_auc: number; average_precision: number; samples: number; true_negatives: number; false_positives: number; false_negatives: number; true_positives: number };
type BaselineStatus = { available: boolean; metrics: { test: MetricSet; validation: MetricSet; features: number; best_iteration: number; created_at_utc: string } | null };
type RobustnessScenario = { scenario: string; intensity: number; malware_samples: number; baseline_detection_rate: number; perturbed_detection_rate: number; evasion_rate: number; mean_probability_drop: number };
type RobustnessStatus = { available: boolean; metrics: { malware_samples: number; baseline_detection_rate: number; scenarios: RobustnessScenario[]; worst_case: RobustnessScenario } | null };
type ComparisonStatus = { available: boolean; metrics: { baseline: { metrics: { test: MetricSet }; robustness: { worst_case: RobustnessScenario } }; hardened: { metrics: { test: MetricSet }; robustness: { worst_case: RobustnessScenario } }; deltas: { clean_accuracy: number; clean_roc_auc: number; worst_detection_rate: number; worst_evasion_rate: number } } | null };
type ConnectionState = 'checking' | 'online' | 'offline';
type View = 'overview' | 'datasets' | 'experiments' | 'robustness' | 'runs';

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://127.0.0.1:8000';
const stages = [
  { label: 'Project foundation', detail: 'Configuration & quality tooling', state: 'complete' },
  { label: 'Data pipeline', detail: 'Validated, streamed & reproducible', state: 'complete' },
  { label: 'Baseline model', detail: 'LightGBM training & evaluation', state: 'complete' },
  { label: 'Robustness study', detail: 'Controlled feature perturbations', state: 'complete' },
  { label: 'Robust retraining', detail: 'Augmented training & comparison', state: 'complete' },
];
const viewLabels: Record<View, string> = { overview: 'Overview', datasets: 'Datasets', experiments: 'Experiments', robustness: 'Robustness', runs: 'Runs' };

export default function Home() {
  const [dataset, setDataset] = useState<DatasetStatus | null>(null);
  const [baseline, setBaseline] = useState<BaselineStatus | null>(null);
  const [robustness, setRobustness] = useState<RobustnessStatus | null>(null);
  const [comparison, setComparison] = useState<ComparisonStatus | null>(null);
  const [connection, setConnection] = useState<ConnectionState>('checking');
  const [action, setAction] = useState<'verify' | 'smoke-test' | null>(null);
  const [notice, setNotice] = useState('Ready for the baseline model workflow.');
  const [activeView, setActiveView] = useState<View>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const refreshStatus = useCallback(async () => {
    setConnection('checking');
    try {
      const [datasetResponse, baselineResponse, robustnessResponse, comparisonResponse] = await Promise.all([
        fetch(`${apiUrl}/api/v1/datasets/ember2018/status`),
        fetch(`${apiUrl}/api/v1/experiments/baseline`),
        fetch(`${apiUrl}/api/v1/experiments/robustness`),
        fetch(`${apiUrl}/api/v1/experiments/comparison`),
      ]);
      if (!datasetResponse.ok || !baselineResponse.ok || !robustnessResponse.ok || !comparisonResponse.ok) throw new Error('Backend returned an error');
      setDataset((await datasetResponse.json()) as DatasetStatus);
      setBaseline((await baselineResponse.json()) as BaselineStatus);
      setRobustness((await robustnessResponse.json()) as RobustnessStatus);
      setComparison((await comparisonResponse.json()) as ComparisonStatus);
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
  const selectView = (view: View) => { setActiveView(view); setMobileMenuOpen(false); };
  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="noise-layer" aria-hidden="true" />
      <div className="mx-auto grid min-h-screen max-w-[1600px] lg:grid-cols-[248px_1fr]">
        <aside className="hidden border-r border-white/8 bg-sidebar/75 px-5 py-6 backdrop-blur-xl lg:flex lg:flex-col">
          <Brand />
          <nav className="mt-10 space-y-1" aria-label="Main navigation">
            <NavItem icon={Gauge} label="Overview" active={activeView === 'overview'} onSelect={() => selectView('overview')} />
            <NavItem icon={Database} label="Datasets" active={activeView === 'datasets'} onSelect={() => selectView('datasets')} />
            <NavItem icon={FlaskConical} label="Experiments" active={activeView === 'experiments'} onSelect={() => selectView('experiments')} />
            <NavItem icon={ScanSearch} label="Robustness" active={activeView === 'robustness'} onSelect={() => selectView('robustness')} />
            <NavItem icon={GitBranch} label="Runs" active={activeView === 'runs'} onSelect={() => selectView('runs')} />
          </nav>
          <div className="mt-auto rounded-2xl border border-cyan-300/15 bg-cyan-300/[0.045] p-4">
            <div className="flex items-center gap-2 text-xs font-medium text-cyan-200"><Sparkles className="size-3.5" />MVP progress</div>
            <div className="mt-3 flex items-end justify-between"><span className="font-mono text-2xl font-semibold text-white">100%</span><span className="text-xs text-slate-400">5 of 5 phases</span></div>
            <Progress value={100} className="mt-3 [&_[data-slot=progress-indicator]]:bg-cyan-300" />
          </div>
        </aside>

        <section className="relative min-w-0 overflow-hidden">
          <div className="orb orb-one" aria-hidden="true" /><div className="orb orb-two" aria-hidden="true" />
          <header className="relative z-10 flex h-20 items-center justify-between border-b border-white/8 px-5 sm:px-8 xl:px-12">
            <div className="flex items-center gap-3 lg:hidden"><Button variant="ghost" size="icon" aria-label="Open navigation" onClick={() => setMobileMenuOpen(true)}><Menu /></Button><Brand compact /></div>
            <div className="hidden lg:block"><p className="text-xs font-medium uppercase tracking-[0.18em] text-slate-500">Research workspace / {viewLabels[activeView]}</p><p className="mt-1 text-sm text-slate-300">Static malware classifier robustness</p></div>
            <div className="flex items-center gap-3">
              <ConnectionPill state={connection} />
              <Button variant="outline" size="sm" onClick={() => void refreshStatus()} aria-label="Refresh backend status" className="border-white/10 bg-white/[0.035] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className={connection === 'checking' ? 'animate-spin' : ''} /><span className="hidden sm:inline">Refresh</span></Button>
            </div>
          </header>

          <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
            <SheetContent side="left" className="w-[290px] border-white/10 bg-sidebar/95 p-5 backdrop-blur-xl">
              <SheetHeader className="px-0 pt-1"><SheetTitle><Brand /></SheetTitle><SheetDescription className="pt-3 text-slate-500">Navigate the research workspace</SheetDescription></SheetHeader>
              <nav className="mt-3 space-y-1" aria-label="Mobile navigation">
                <NavItem icon={Gauge} label="Overview" active={activeView === 'overview'} onSelect={() => selectView('overview')} />
                <NavItem icon={Database} label="Datasets" active={activeView === 'datasets'} onSelect={() => selectView('datasets')} />
                <NavItem icon={FlaskConical} label="Experiments" active={activeView === 'experiments'} onSelect={() => selectView('experiments')} />
                <NavItem icon={ScanSearch} label="Robustness" active={activeView === 'robustness'} onSelect={() => selectView('robustness')} />
                <NavItem icon={GitBranch} label="Runs" active={activeView === 'runs'} onSelect={() => selectView('runs')} />
              </nav>
            </SheetContent>
          </Sheet>

          {activeView === 'overview' && <div className="relative z-10 px-5 py-8 sm:px-8 xl:px-12 xl:py-10">
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

            <BaselineResults baseline={baseline} />

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
              <div className="flex items-center gap-3"><div className="grid size-10 place-items-center rounded-xl bg-emerald-300/10 text-emerald-200"><Check className="size-4" /></div><div><p className="text-sm font-medium text-slate-200">Scientific MVP complete</p><p className="text-xs text-slate-500">Baseline, robustness study, and hardened comparison are reproducible</p></div></div>
              <Button variant="ghost" className="justify-start text-cyan-200 hover:bg-cyan-300/8 hover:text-cyan-100">View implementation path <ArrowUpRight /></Button>
            </div>
          </div>}

          {activeView === 'datasets' && <WorkspaceView title="EMBER2018 dataset" description="Inspect local data readiness and validate the real feature pipeline." badge="DATA / 01">
            <div className="grid gap-4 md:grid-cols-3"><MetricCard icon={Database} eyebrow="Status" value={ready ? 'Ready' : 'Attention'} detail="Official Elastic feature archive" tone="cyan" /><MetricCard icon={Binary} eyebrow="Features" value="2,381" detail="Static PE feature vector" tone="violet" /><MetricCard icon={HardDrive} eyebrow="Storage" value="8.4 GiB" detail="Local and Git-ignored" tone="emerald" /></div>
            <Card className="glass-card mt-4"><CardHeader><CardTitle className="text-white">Dataset controls</CardTitle><CardDescription>Run checks against the local archive and extracted records.</CardDescription></CardHeader><CardContent className="flex flex-wrap gap-3"><Button variant="outline" className="border-white/10 bg-white/[0.035]" onClick={() => void runAction('verify')} disabled={action !== null}><ShieldCheck />{action === 'verify' ? 'Verifying…' : 'Verify dataset'}</Button><Button className="bg-cyan-300 text-slate-950 hover:bg-cyan-200" onClick={() => void runAction('smoke-test')} disabled={action !== null}><TerminalSquare />{action === 'smoke-test' ? 'Testing…' : 'Vectorization smoke test'}</Button><p className="w-full pt-2 text-sm text-slate-400">{notice}</p></CardContent></Card>
          </WorkspaceView>}

          {activeView === 'experiments' && <WorkspaceView title="Baseline experiment" description="Review model quality on held-out real EMBER2018 records." badge="MODEL / 01"><BaselineResults baseline={baseline} /></WorkspaceView>}

          {activeView === 'robustness' && <WorkspaceView title="Robustness evaluation" description="Measure how performance changes under safe feature-space perturbations." badge="ROBUST / 01">
            <RobustnessResults robustness={robustness} comparison={comparison} />
          </WorkspaceView>}

          {activeView === 'runs' && <WorkspaceView title="Experiment runs" description="Track persisted model artifacts and the latest evaluation signal." badge="RUNS / 01">
            <Card className="glass-card"><CardHeader><CardTitle className="text-white">baseline_lightgbm</CardTitle><CardDescription>Latest real-data sample run</CardDescription><CardAction><Badge className="border border-emerald-300/20 bg-emerald-300/10 text-emerald-200">Complete</Badge></CardAction></CardHeader><CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><StatusTile label="Model" value="LightGBM" state="ready" /><StatusTile label="Test records" value={baseline?.metrics?.test.samples.toLocaleString() ?? '—'} state="ready" /><StatusTile label="Best iteration" value={baseline?.metrics?.best_iteration.toString() ?? '—'} state="ready" /><StatusTile label="ROC-AUC" value={formatScore(baseline?.metrics?.test.roc_auc)} state="ready" /></CardContent></Card>
          </WorkspaceView>}
        </section>
      </div>
    </main>
  );
}

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className="flex items-center gap-3"><div className="relative grid size-9 place-items-center overflow-hidden rounded-xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><ShieldCheck className="size-[18px]" /><span className="absolute inset-x-1 bottom-0 h-px bg-cyan-200/60" /></div>{!compact && <div><p className="text-sm font-semibold tracking-[-0.02em] text-white">Aegis Lab</p><p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">ML robustness</p></div>}</div>;
}

function NavItem({ icon: Icon, label, active = false, onSelect }: { icon: typeof Gauge; label: string; active?: boolean; onSelect: () => void }) {
  return <button type="button" onClick={onSelect} aria-current={active ? 'page' : undefined} className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors ${active ? 'bg-cyan-300/10 text-cyan-100' : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-300'}`}><Icon className="size-4" />{label}{active && <ChevronRight className="ml-auto size-3.5" />}</button>;
}

function WorkspaceView({ title, description, badge, children }: { title: string; description: string; badge: string; children: ReactNode }) {
  return <div className="relative z-10 px-5 py-8 sm:px-8 xl:px-12 xl:py-10"><div className="mb-8"><Badge className="border border-violet-300/20 bg-violet-300/10 text-violet-200">{badge}</Badge><h1 className="mt-4 text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">{title}</h1><p className="mt-3 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">{description}</p></div>{children}</div>;
}

function StatusTile({ label, value, state }: { label: string; value: string; state: 'ready' | 'next' | 'queued' }) {
  const tone = state === 'ready' ? 'text-emerald-300' : state === 'next' ? 'text-cyan-300' : 'text-slate-500';
  return <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4"><p className="text-xs text-slate-500">{label}</p><p className={`mt-2 font-mono text-sm font-medium ${tone}`}>{value}</p></div>;
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

function BaselineResults({ baseline }: { baseline: BaselineStatus | null }) {
  const metrics = baseline?.metrics?.test;
  return <Card className="glass-card mt-4">
    <CardHeader className="border-b border-white/8 pb-4">
      <CardTitle className="flex items-center gap-2 text-white"><FlaskConical className="size-4 text-violet-300" />Baseline test results</CardTitle>
      <CardDescription>{metrics ? `LightGBM · ${metrics.samples.toLocaleString()} real EMBER2018 held-out records` : 'Results appear automatically after the first training run'}</CardDescription>
      <CardAction><Badge variant="outline" className={metrics ? 'border-emerald-300/20 text-emerald-300' : 'border-white/10 text-slate-500'}>{metrics ? 'Real run' : 'Pending'}</Badge></CardAction>
    </CardHeader>
    <CardContent className="pt-5">
      {metrics ? <div className="grid gap-6 xl:grid-cols-[1.35fr_.65fr]">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <ResultMetric label="Accuracy" value={formatPercent(metrics.accuracy)} />
          <ResultMetric label="Precision" value={formatPercent(metrics.precision)} />
          <ResultMetric label="Recall" value={formatPercent(metrics.recall)} highlight />
          <ResultMetric label="F1 score" value={formatPercent(metrics.f1)} />
          <ResultMetric label="ROC-AUC" value={formatScore(metrics.roc_auc)} highlight />
          <ResultMetric label="Avg. precision" value={formatPercent(metrics.average_precision)} />
        </div>
        <ConfusionMatrix metrics={metrics} />
      </div> : <div className="rounded-xl border border-dashed border-white/10 px-5 py-8 text-center text-sm text-slate-500">Prepare the EMBER partitions and run the baseline model to populate this panel.</div>}
    </CardContent>
  </Card>;
}

function RobustnessResults({ robustness, comparison }: { robustness: RobustnessStatus | null; comparison: ComparisonStatus | null }) {
  const metrics = robustness?.metrics;
  const worst = metrics?.worst_case;
  if (!metrics || !worst) return <Card className="glass-card"><CardContent className="py-10 text-center text-sm text-slate-500">Run the controlled robustness workflow to populate this view.</CardContent></Card>;
  return <div className="space-y-4">
    {comparison?.metrics && <ModelComparison comparison={comparison.metrics} />}
    <div className="grid gap-4 sm:grid-cols-3">
      <MetricCard icon={ShieldCheck} eyebrow="Baseline detection" value={formatPercent(metrics.baseline_detection_rate)} detail={`${metrics.malware_samples.toLocaleString()} held-out malware records`} tone="emerald" />
      <MetricCard icon={ScanSearch} eyebrow="Worst detection" value={formatPercent(worst.perturbed_detection_rate)} detail={`${scenarioLabel(worst.scenario)} · ${formatPercent(worst.intensity)}`} tone="violet" />
      <MetricCard icon={Activity} eyebrow="Worst evasion" value={formatPercent(worst.evasion_rate)} detail={`${formatPercent(worst.mean_probability_drop)} confidence drop`} tone="cyan" />
    </div>
    <Card className="glass-card">
      <CardHeader className="border-b border-white/8 pb-4"><CardTitle className="text-white">Detection-rate matrix</CardTitle><CardDescription>Rows are perturbation types; columns are perturbation intensity</CardDescription></CardHeader>
      <CardContent className="pt-5"><RobustnessMatrix scenarios={metrics.scenarios} /></CardContent>
    </Card>
    <Card className="glass-card">
      <CardHeader className="border-b border-white/8 pb-4"><CardTitle className="flex items-center gap-2 text-white"><ScanSearch className="size-4 text-violet-300" />Scenario matrix</CardTitle><CardDescription>Detection impact by feature group and perturbation intensity</CardDescription><CardAction><Badge className="border border-emerald-300/20 bg-emerald-300/10 text-emerald-200">Complete</Badge></CardAction></CardHeader>
      <CardContent className="pt-4"><Table><TableHeader><TableRow className="border-white/8 hover:bg-transparent"><TableHead className="text-slate-500">Scenario</TableHead><TableHead className="text-right text-slate-500">Intensity</TableHead><TableHead className="text-right text-slate-500">Detection</TableHead><TableHead className="text-right text-slate-500">Evasion</TableHead><TableHead className="text-right text-slate-500">Confidence drop</TableHead></TableRow></TableHeader><TableBody>{metrics.scenarios.map((scenario) => <TableRow key={`${scenario.scenario}-${scenario.intensity}`} className="border-white/6 hover:bg-white/[0.025]"><TableCell className="font-medium text-slate-300">{scenarioLabel(scenario.scenario)}</TableCell><TableCell className="text-right font-mono text-slate-400">{formatPercent(scenario.intensity)}</TableCell><TableCell className="text-right font-mono text-cyan-200">{formatPercent(scenario.perturbed_detection_rate)}</TableCell><TableCell className="text-right font-mono text-amber-300">{formatPercent(scenario.evasion_rate)}</TableCell><TableCell className="text-right font-mono text-rose-300">{formatPercent(scenario.mean_probability_drop)}</TableCell></TableRow>)}</TableBody></Table></CardContent>
    </Card>
  </div>;
}

function ModelComparison({ comparison }: { comparison: NonNullable<ComparisonStatus['metrics']> }) {
  const baseline = comparison.baseline;
  const hardened = comparison.hardened;
  const rows = [
    { label: 'Clean accuracy', before: baseline.metrics.test.accuracy, after: hardened.metrics.test.accuracy, delta: comparison.deltas.clean_accuracy, positive: true },
    { label: 'Clean ROC-AUC', before: baseline.metrics.test.roc_auc, after: hardened.metrics.test.roc_auc, delta: comparison.deltas.clean_roc_auc, positive: true },
    { label: 'Worst-case detection', before: baseline.robustness.worst_case.perturbed_detection_rate, after: hardened.robustness.worst_case.perturbed_detection_rate, delta: comparison.deltas.worst_detection_rate, positive: true },
    { label: 'Worst-case evasion', before: baseline.robustness.worst_case.evasion_rate, after: hardened.robustness.worst_case.evasion_rate, delta: comparison.deltas.worst_evasion_rate, positive: false },
  ];
  return <Card className="glass-card overflow-hidden border-emerald-300/10"><CardHeader className="border-b border-white/8 pb-4"><CardTitle className="flex items-center gap-2 text-white"><ShieldCheck className="size-4 text-emerald-300" />Baseline vs hardened model</CardTitle><CardDescription>Clean performance is preserved while worst-case resilience improves</CardDescription><CardAction><Badge className="border border-emerald-300/20 bg-emerald-300/10 text-emerald-200">Hardened</Badge></CardAction></CardHeader><CardContent className="pt-4"><Table><TableHeader><TableRow className="border-white/8 hover:bg-transparent"><TableHead className="text-slate-500">Metric</TableHead><TableHead className="text-right text-slate-500">Baseline</TableHead><TableHead className="text-right text-slate-500">Hardened</TableHead><TableHead className="text-right text-slate-500">Change</TableHead></TableRow></TableHeader><TableBody>{rows.map((row) => { const improved = row.positive ? row.delta >= 0 : row.delta <= 0; return <TableRow key={row.label} className="border-white/6 hover:bg-white/[0.025]"><TableCell className="font-medium text-slate-300">{row.label}</TableCell><TableCell className="text-right font-mono text-slate-500">{formatPercent(row.before)}</TableCell><TableCell className="text-right font-mono text-white">{formatPercent(row.after)}</TableCell><TableCell className={`text-right font-mono ${improved ? 'text-emerald-300' : 'text-rose-300'}`}>{formatSignedPercent(row.delta)}</TableCell></TableRow>; })}</TableBody></Table></CardContent></Card>;
}

function ResultMetric({ label, value, highlight = false }: { label: string; value: string; highlight?: boolean }) {
  return <div className="rounded-xl border border-white/8 bg-white/[0.025] p-4"><p className="text-xs text-slate-500">{label}</p><p className={`mt-2 font-mono text-xl font-semibold ${highlight ? 'text-cyan-200' : 'text-white'}`}>{value}</p></div>;
}

function ConfusionMatrix({ metrics }: { metrics: MetricSet }) {
  const cells = [
    { label: 'True negative', value: metrics.true_negatives, tone: 'border-cyan-300/15 bg-cyan-300/8 text-cyan-200' },
    { label: 'False positive', value: metrics.false_positives, tone: 'border-amber-300/15 bg-amber-300/8 text-amber-200' },
    { label: 'False negative', value: metrics.false_negatives, tone: 'border-rose-300/15 bg-rose-300/8 text-rose-200' },
    { label: 'True positive', value: metrics.true_positives, tone: 'border-emerald-300/15 bg-emerald-300/8 text-emerald-200' },
  ];
  return <div><p className="mb-3 text-xs font-medium uppercase tracking-[0.14em] text-slate-500">Confusion matrix</p><div className="grid grid-cols-[auto_1fr_1fr] gap-2"><div /><p className="pb-1 text-center text-[10px] uppercase tracking-wider text-slate-600">Predicted benign</p><p className="pb-1 text-center text-[10px] uppercase tracking-wider text-slate-600">Predicted malware</p><p className="flex items-center pr-2 text-[10px] uppercase tracking-wider text-slate-600">Actual benign</p>{cells.slice(0, 2).map((cell) => <MatrixCell key={cell.label} {...cell} />)}<p className="flex items-center pr-2 text-[10px] uppercase tracking-wider text-slate-600">Actual malware</p>{cells.slice(2).map((cell) => <MatrixCell key={cell.label} {...cell} />)}</div></div>;
}

function MatrixCell({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <div className={`rounded-xl border p-3 text-center ${tone}`}><p className="font-mono text-xl font-semibold">{value.toLocaleString()}</p><p className="mt-1 text-[10px] uppercase tracking-wider opacity-65">{label}</p></div>;
}

function RobustnessMatrix({ scenarios }: { scenarios: RobustnessScenario[] }) {
  const names = [...new Set(scenarios.map((item) => item.scenario))];
  const intensities = [...new Set(scenarios.map((item) => item.intensity))].sort((a, b) => a - b);
  return <div className="overflow-x-auto"><div className="grid min-w-[620px] gap-2" style={{ gridTemplateColumns: `minmax(190px, 1.3fr) repeat(${intensities.length}, 1fr)` }}><div /><>{intensities.map((intensity) => <p key={intensity} className="pb-1 text-center text-xs font-medium text-slate-500">{formatPercent(intensity)} intensity</p>)}</>{names.map((name) => <div key={name} className="contents"><p className="flex items-center text-sm font-medium text-slate-300">{scenarioLabel(name)}</p>{intensities.map((intensity) => { const item = scenarios.find((scenario) => scenario.scenario === name && scenario.intensity === intensity)!; const tone = item.perturbed_detection_rate >= 0.9 ? 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200' : item.perturbed_detection_rate >= 0.8 ? 'border-amber-300/20 bg-amber-300/10 text-amber-200' : 'border-rose-300/20 bg-rose-300/10 text-rose-200'; return <div key={intensity} className={`rounded-xl border px-3 py-4 text-center ${tone}`}><p className="font-mono text-lg font-semibold">{formatPercent(item.perturbed_detection_rate)}</p><p className="mt-1 text-[10px] uppercase tracking-wider opacity-65">{formatPercent(item.evasion_rate)} evasion</p></div>; })}</div>)}</div></div>;
}

function formatScore(value?: number) {
  return value === undefined ? '—' : value.toFixed(3);
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

function formatSignedPercent(value: number) {
  return `${value >= 0 ? '+' : ''}${(value * 100).toFixed(1)} pp`;
}

function scenarioLabel(value: string) {
  return value.split('_').map((part) => part[0].toUpperCase() + part.slice(1)).join(' ');
}
