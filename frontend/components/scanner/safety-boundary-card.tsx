import {
  Binary,
  FileKey2,
  Fingerprint,
  LockKeyhole,
  ShieldAlert,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

export function SafetyBoundaryCard() {
  return (
    <Card className="glass-card">
      <CardHeader className="border-b border-white/8 pb-4">
        <CardTitle className="flex items-center gap-2 text-white">
          <LockKeyhole className="size-4 text-violet-300" />
          Safe analysis boundary
        </CardTitle>
        <CardDescription>
          Designed for unknown and untrusted binaries
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 pt-5">
        <SafetyRow
          icon={ShieldAlert}
          title="Never executed"
          detail="Static extraction inspects PE structures without launching the sample."
        />
        <SafetyRow
          icon={Binary}
          title="Direct quarantine upload"
          detail="The primary API receives metadata; file bytes go to a short-lived private object grant."
        />
        <SafetyRow
          icon={Fingerprint}
          title="Metadata-only orchestration"
          detail="Queues carry opaque scan IDs and immutable digests, never file bytes or feature vectors."
        />
        <SafetyRow
          icon={FileKey2}
          title="Pinned analysis release"
          detail="Extractor, schema, model, calibration and policy remain fixed for each scan."
        />
        <div className="mt-5 rounded-xl border border-violet-300/12 bg-violet-300/[0.045] p-4">
          <p className="text-xs font-medium uppercase tracking-[0.14em] text-violet-200">
            What this scan does not do
          </p>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            It does not run the file, contact embedded URLs, or guarantee that a
            file is safe. Quarantine retention is controlled by server policy,
            and an inconclusive result is never presented as benign.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function SafetyRow({
  icon: Icon,
  title,
  detail,
}: {
  icon: LucideIcon;
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
