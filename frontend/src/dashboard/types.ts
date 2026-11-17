import type { Me } from '../types';

export const canReadDashboard = (user: Me) =>
  ['events:read', 'alerts:read', 'incidents:read', 'detections:read'].every((p) =>
    user.permissions.includes(p),
  );
export type Category = { id: string; label: string; count: number };
export type EntityRank = Category & { identity_basis: string };
export interface DashboardReport {
  generated_at: string;
  refresh_seconds: 10;
  scope: {
    mode: 'live' | 'replay';
    dataset_id: string | null;
    run_id: string | null;
    from: string;
    to: string;
    include_false_positives: boolean;
  };
  counts: {
    events_24h: number;
    alerts_24h: number;
    excluded_false_positives: number;
    open_incidents: number;
    critical_incidents: number;
    received_24h: number;
  };
  index_status: { pending_events: number; indexed_events: number; entities_partial: boolean };
  top: {
    users: EntityRank[];
    hosts: EntityRank[];
    source_ips: EntityRank[];
    destination_ips: EntityRank[];
  };
  rules: (Category & { version: string })[];
  severity: Category[];
  risk: Category[];
  tactics: Category[];
  mitre_status: {
    mapped_alerts: number;
    unmapped_alerts: number;
    missing_snapshots: number;
    other_catalogue_alerts: number;
  };
  ingestion: {
    accepted_events: number;
    average_eps: number;
    bucket_seconds: 60;
    buckets: { from: string; to: string; count: number; events_per_second: number }[];
  };
}
