import type { Json } from '../types';
import type { RiskLevel } from './levels';

export type RiskSubject = 'alert' | 'incident';
export interface RiskComponent {
  code: string;
  label: string;
  points: number;
  maximum: number;
  status: 'known' | 'unknown' | 'not_applicable';
  reason: string;
  evidence_ids: string[];
  details: Record<string, Json>;
}
export interface RiskCalculation {
  id: string;
  subject_type: RiskSubject;
  subject_id: string;
  subject_revision: number;
  created_at: string;
  actor_id: string | null;
  trigger: string;
  previous_id: string | null;
  policy_version: string;
  policy_hash: string;
  input_sha256: string;
  input_snapshot: Record<string, Json>;
  score: number;
  level: RiskLevel;
  raw_score: number;
  clipping: number;
  components: RiskComponent[];
  signal_units: { family: string; evidence_ids: string[]; alert_ids: string[] }[];
  missing_contexts: string[];
  confidence_status: 'known' | 'unknown' | 'mixed' | 'not_applicable';
  excluded_alert_ids: string[];
}
export interface RiskHistory {
  current: RiskCalculation | null;
  history: RiskCalculation[];
  history_truncated: boolean;
}
export interface RiskPolicy {
  version: string;
  hash: string;
  level_thresholds: Record<RiskLevel, [number, number]>;
  severity_points: Record<string, number>;
  components: { code: string; label: string; maximum: number }[];
  production_unknown_contexts: string[];
  description: string;
}
