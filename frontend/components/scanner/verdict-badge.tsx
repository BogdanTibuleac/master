import { Badge } from '@/components/ui/badge';
import { verdictLabel } from '@/components/scanner/formatters';
import type { Verdict } from '@/components/scanner/types';

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const tones: Record<Verdict, string> = {
    likely_benign: 'border-emerald-300/20 bg-emerald-300/10 text-emerald-200',
    needs_review: 'border-amber-300/20 bg-amber-300/10 text-amber-200',
    likely_malicious: 'border-rose-300/20 bg-rose-300/10 text-rose-200',
    high_risk: 'border-rose-300/30 bg-rose-300/15 text-rose-100',
  };

  return (
    <Badge className={`border ${tones[verdict]}`}>
      {verdictLabel(verdict)}
    </Badge>
  );
}
