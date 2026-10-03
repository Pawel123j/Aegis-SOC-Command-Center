import { Badge } from '../components';
import { riskLevel, riskLevelNames } from './levels';
import type { RiskLevel } from './levels';
import './risk.css';

export function RiskScore({ score, level }: { score: number | null; level?: RiskLevel | null }) {
  if (score === null) return <span className="muted">Nie obliczono</span>;
  const tone = level ?? riskLevel(score);
  return (
    <span className="risk-score" aria-label={`Ryzyko: ${score} z 100, ${riskLevelNames[tone]}`}>
      <strong>
        {score}
        <span className="muted"> / 100</span>
      </strong>
      <Badge tone={tone}>{riskLevelNames[tone]}</Badge>
    </span>
  );
}
