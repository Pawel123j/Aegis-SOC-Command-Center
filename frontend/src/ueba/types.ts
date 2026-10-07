export type UebaIndicatorId =
  | 'unusual_login_hour'
  | 'new_login_ip'
  | 'new_login_host'
  | 'first_admin_tool'
  | 'failed_login_burst'
  | 'activity_burst'
  | 'admin_account_use';

export interface UebaEvidence {
  event_id: string;
  timestamp: string;
  document_sha256: string;
}
export interface UebaIndicator {
  id: UebaIndicatorId;
  status: 'anomaly' | 'normal' | 'insufficient_data' | 'unsupported';
  score: number;
  explanation: string;
  baseline_event_count: number;
  baseline_active_days: number;
  baseline_values: string[];
  observed_count: number;
  observed_values: string[];
  daily_mean: number | null;
  daily_stddev: number | null;
  threshold: number | null;
  evidence_total: number;
  evidence: UebaEvidence[];
}
interface UebaWindow {
  from: string;
  to: string;
  event_count: number;
  eligible_events: number;
  excluded_timestamp_events: number;
}
export interface UebaReport {
  policy_version: 'ueba-statistics-v1';
  as_of: string;
  entity: {
    id: string;
    kind: 'user' | 'host' | 'ip' | 'process';
    label: string;
    identity_basis: string;
  };
  scope: { mode: 'live' | 'replay'; dataset_id: string | null; run_id: string | null };
  observation: UebaWindow;
  baseline: UebaWindow & {
    days: 28;
    active_days: number;
    minimum_events: 20;
    minimum_active_days: 7;
  };
  status: 'ready' | 'cold_start' | 'index_pending' | 'unsupported';
  pending_events: number;
  score: number | null;
  indicators: UebaIndicator[];
}
