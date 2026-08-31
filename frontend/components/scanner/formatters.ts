import type { Verdict } from '@/components/scanner/types';

export function verdictLabel(verdict: Verdict) {
  return {
    likely_benign: 'Likely benign',
    needs_review: 'Needs review',
    likely_malicious: 'Likely malicious',
    high_risk: 'High risk',
  }[verdict];
}

export function formatPercent(value: number) {
  return `${(value * 100).toFixed(1)}%`;
}

export function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatDate(value: string, includeYear = false) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, {
        ...(includeYear ? { year: 'numeric' as const } : {}),
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
}
