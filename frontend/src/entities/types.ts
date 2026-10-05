import type { RiskLevel } from '../risk/levels';

export type EntityKind = 'host' | 'user' | 'ip' | 'process';
export interface EntityScope {
  mode: 'live' | 'replay';
  dataset_id: string | null;
  run_id: string | null;
  from: string;
  to: string;
  time_basis: 'contributing_event.timestamp';
  interval: '[from,to)';
}
export interface IndexStatus {
  pending_events: number;
  pending_alerts: number;
  complete: boolean;
}
export interface EntityCounts {
  events: number;
  observations: number;
  alerts: number;
  eligible_alerts: number;
  false_positive_alerts: number;
  incidents: number;
  failed_logins: number;
}
export interface EntitySummary {
  id: string;
  kind: EntityKind;
  label: string;
  identity_policy: string;
  identity_basis: string;
  inventory_verified: false;
  source_id: string | null;
  first_seen: string;
  last_seen: string;
  counts: EntityCounts;
  risk_score: number | null;
  risk_level: RiskLevel | null;
}
export interface EntityDetail extends EntitySummary {
  scope: EntityScope;
  canonical_identity: Record<string, unknown>;
  risk: {
    strategy: 'maximum_current_eligible_alert';
    entity_calculation: false;
    score: number | null;
    level: RiskLevel | null;
    alert_id: string | null;
    calculation_id: string | null;
    policy_version: string | null;
    explanation: Record<string, unknown> | null;
    eligible_alerts: number;
    assessed_alerts: number;
    excluded_false_positive_alerts: number;
    reason: string;
  };
  mitre: {
    claim: 'candidate_association';
    confirmed_attack: false;
    techniques: {
      id: string;
      name: string;
      url: string;
      catalogue_version: string;
      catalogue_hash: string;
      alert_count: number;
    }[];
    mapped_alerts: number;
    unmapped_alerts: number;
    legacy_alerts: number;
    other_catalogue_alerts: number;
    excluded_false_positive_alerts: number;
  };
  roles: Record<string, number>;
  related_host_count: number;
  index_status: IndexStatus;
}
export interface EventActivity {
  event_id: string;
  timestamp: string;
  source_id: string;
  source_name: string;
  source_type: string;
  event_category: string | null;
  event_action: string | null;
  event_outcome: string | null;
  roles: string[];
}
export interface EntityAlert {
  id: string;
  title: string;
  rule_id: string;
  severity: string;
  status: string;
  event_timestamp: string;
  contributing_event_count: number;
  matched_entity_event_count: number;
  risk_score: number | null;
  risk_level: RiskLevel | null;
}
export interface EntityIncident {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
  matched_alert_count: number;
  risk_score: number | null;
  risk_level: RiskLevel | null;
}
export interface EntityPage<T> {
  scope: EntityScope;
  items: T[];
  total: number;
  next_cursor: string | null;
  index_status: IndexStatus;
}
export interface BackfillResult {
  events: number;
  alerts: number;
  observations: number;
  index_status: IndexStatus;
  identity_policy: string;
}
