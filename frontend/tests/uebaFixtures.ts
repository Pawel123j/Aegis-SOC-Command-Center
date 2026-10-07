import type { UebaIndicator, UebaReport } from '../src/ueba/types';
import { entitySummary } from './entityFixtures';
import { original } from './incidentFixtures';

export const uebaIndicator: UebaIndicator = {
  id: 'first_admin_tool',
  status: 'anomaly',
  score: 20,
  explanation: 'Narzędzia powershell.exe nie obserwowano w poprzednich 28 dniach.',
  baseline_event_count: 42,
  baseline_active_days: 14,
  baseline_values: ['cmd.exe'],
  observed_count: 1,
  observed_values: ['powershell.exe'],
  daily_mean: null,
  daily_stddev: null,
  threshold: null,
  evidence_total: 1,
  evidence: [
    { event_id: original.event_id, timestamp: original.timestamp, document_sha256: 'c'.repeat(64) },
  ],
};
export const uebaFixture: UebaReport = {
  policy_version: 'ueba-statistics-v1',
  as_of: '2026-10-06T00:30:00Z',
  entity: {
    id: entitySummary.id,
    kind: 'user',
    label: entitySummary.label,
    identity_basis: entitySummary.identity_basis,
  },
  scope: { mode: 'live', dataset_id: null, run_id: null },
  observation: {
    from: '2026-10-01T00:00:00Z',
    to: '2026-10-02T00:00:00Z',
    event_count: 2,
    eligible_events: 1,
    excluded_timestamp_events: 1,
  },
  baseline: {
    from: '2026-09-03T00:00:00Z',
    to: '2026-10-01T00:00:00Z',
    days: 28,
    event_count: 43,
    eligible_events: 42,
    excluded_timestamp_events: 1,
    active_days: 14,
    minimum_events: 20,
    minimum_active_days: 7,
  },
  status: 'ready',
  pending_events: 0,
  score: 20,
  indicators: [uebaIndicator],
};
