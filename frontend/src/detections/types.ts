import type { Json, Rule } from '../types';

export interface CorrelationCondition {
  all?: CorrelationCondition[];
  any?: CorrelationCondition[];
  field?: string;
  operator?: 'equals' | 'contains' | 'endswith';
  value?: string;
}
export interface CorrelationPattern {
  kind: 'sequence' | 'threshold';
  window_seconds: number;
  group_by: ('same_user' | 'same_host' | 'same_ip' | 'same_process')[];
  stages: { name: string; count: number; condition: CorrelationCondition }[];
}
export interface CorrelationRule extends Rule {
  type: 'correlation';
  pattern: CorrelationPattern;
  allowed_lateness_seconds: number;
  max_candidates: number;
  evaluator_version: string;
  mitre?: string[];
  false_positive_guidance?: string[];
}
export interface CorrelationTestResult {
  rule_id: string;
  rule_version: string;
  evaluator_version: string;
  matches: { event_ids: string[]; event_timestamp: string; reason: Json }[];
  complete: boolean;
}
export interface CorrelationCoverage {
  counts: Record<string, number>;
  scopes: {
    namespace: string;
    watermark: string | null;
    sealed_at: string | null;
    manifest_sha256: string | null;
    event_count: number;
  }[];
  scopes_truncated: boolean;
}
