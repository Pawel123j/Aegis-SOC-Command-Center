import type {
  EntityAlert,
  EntityDetail,
  EntityIncident,
  EntityPage,
  EntityScope,
  EntitySummary,
  EventActivity,
} from '../src/entities/types';
import { alert, original, reader } from './incidentFixtures';

export const entityReader = reader;
export const entityAdmin = {
  ...reader,
  role: 'admin' as const,
  permissions: [...reader.permissions, 'system:manage', 'alerts:manage'],
};
export const entityScope: EntityScope = {
  mode: 'live',
  dataset_id: null,
  run_id: null,
  from: '2026-09-01T00:00:00Z',
  to: '2026-10-02T00:00:00Z',
  time_basis: 'contributing_event.timestamp',
  interval: '[from,to)',
};
export const entitySummary: EntitySummary = {
  id: '70000000-0000-0000-0000-000000000001',
  kind: 'user',
  label: 'LAB\\Administrator',
  identity_policy: 'entity-identity-v1',
  identity_basis: 'source_scoped_sid',
  inventory_verified: false,
  source_id: original.source_id,
  first_seen: '2026-09-28T12:00:00Z',
  last_seen: original.timestamp,
  counts: {
    events: 431,
    observations: 500,
    failed_logins: 31,
    alerts: 8,
    eligible_alerts: 6,
    false_positive_alerts: 2,
    incidents: 3,
  },
  risk_score: 72,
  risk_level: 'high',
};
export const entityHost: EntitySummary = {
  ...entitySummary,
  id: '70000000-0000-0000-0000-000000000002',
  kind: 'host',
  label: 'WIN-DEMO',
  identity_basis: 'source_scoped_host_name',
};
export function entityPage<T>(items: T[], total = items.length): EntityPage<T> {
  return {
    items,
    total,
    next_cursor: null,
    scope: entityScope,
    index_status: { pending_events: 0, pending_alerts: 0, complete: true },
  };
}
export const entityDetail: EntityDetail = {
  ...entitySummary,
  scope: entityScope,
  canonical_identity: { source_id: original.source_id, sid: 'S-1-5-21-1-2-3-500' },
  risk: {
    strategy: 'maximum_current_eligible_alert',
    entity_calculation: false,
    score: 72,
    level: 'high',
    alert_id: alert.id,
    calculation_id: '80000000-0000-0000-0000-000000000001',
    policy_version: 'risk-policy-v3',
    explanation: { components: { D: 72, C: 0 } },
    eligible_alerts: 6,
    assessed_alerts: 5,
    excluded_false_positive_alerts: 2,
    reason: 'maximum_current_eligible_alert',
  },
  mitre: {
    claim: 'candidate_association',
    confirmed_attack: false,
    techniques: [
      {
        id: 'T1059.001',
        name: 'PowerShell',
        url: 'https://attack.mitre.org/techniques/T1059/001/',
        catalogue_version: '19.2',
        catalogue_hash: 'c'.repeat(64),
        alert_count: 2,
      },
    ],
    mapped_alerts: 2,
    unmapped_alerts: 1,
    legacy_alerts: 1,
    other_catalogue_alerts: 2,
    excluded_false_positive_alerts: 2,
  },
  roles: { actor: 200, target: 300 },
  related_host_count: 3,
  index_status: { pending_events: 0, pending_alerts: 0, complete: true },
};
export const entityActivity: EventActivity = {
  event_id: original.event_id,
  timestamp: original.timestamp,
  source_id: original.source_id,
  source_name: original.source.name,
  source_type: original.source.type,
  event_category: 'authentication',
  event_action: 'login',
  event_outcome: 'failure',
  roles: ['actor', 'target'],
};
export const entityAlert: EntityAlert = {
  id: alert.id,
  title: alert.title,
  rule_id: alert.rule_id,
  severity: alert.severity,
  status: 'false_positive',
  event_timestamp: alert.event_timestamp,
  contributing_event_count: 5,
  matched_entity_event_count: 2,
  risk_score: 99,
  risk_level: 'critical',
};
export const entityIncident: EntityIncident = {
  id: '60000000-0000-0000-0000-000000000001',
  title: 'Zamknięta sprawa profilu',
  severity: 'high',
  status: 'closed',
  created_at: original.timestamp,
  matched_alert_count: 2,
  risk_score: 60,
  risk_level: 'high',
};
