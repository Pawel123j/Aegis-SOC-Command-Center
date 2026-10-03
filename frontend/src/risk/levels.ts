export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export const riskLevelNames: Record<RiskLevel, string> = {
  low: 'Niskie',
  medium: 'Średnie',
  high: 'Wysokie',
  critical: 'Krytyczne',
};

export function riskLevel(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}
