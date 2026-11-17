import type { DashboardReport } from '../src/dashboard/types';

export const dashboardFixture: DashboardReport = {
  generated_at: '2026-10-08T12:00:00Z',
  refresh_seconds: 10,
  scope: {
    mode: 'live',
    dataset_id: null,
    run_id: null,
    from: '2026-10-07T12:00:00Z',
    to: '2026-10-08T12:00:00Z',
    include_false_positives: false,
  },
  counts: {
    events_24h: 12,
    alerts_24h: 3,
    excluded_false_positives: 1,
    open_incidents: 2,
    critical_incidents: 1,
    received_24h: 15,
  },
  index_status: { pending_events: 0, indexed_events: 12, entities_partial: false },
  top: { users: [], hosts: [], source_ips: [], destination_ips: [] },
  rules: [],
  tactics: [],
  severity: [{ id: 'medium', label: 'Średnia', count: 3 }],
  risk: [{ id: 'unassessed', label: 'Brak oceny', count: 3 }],
  mitre_status: {
    mapped_alerts: 0,
    unmapped_alerts: 3,
    missing_snapshots: 0,
    other_catalogue_alerts: 0,
  },
  ingestion: {
    accepted_events: 0,
    average_eps: 0,
    bucket_seconds: 60,
    buckets: Array.from({ length: 60 }, (_, index) => ({
      from: new Date(Date.UTC(2026, 9, 8, 11, index)).toISOString(),
      to: new Date(Date.UTC(2026, 9, 8, 11, index + 1)).toISOString(),
      count: 0,
      events_per_second: 0,
    })),
  },
};
