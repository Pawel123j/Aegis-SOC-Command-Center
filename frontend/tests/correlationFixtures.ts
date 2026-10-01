import type { CorrelationRule, CorrelationTestResult } from '../src/detections/types';
import type { AlertDetail, Me } from '../src/types';
import { alertDetail, analyst, original, timestamp } from './incidentFixtures';

export const correlationAnalyst: Me = {
  ...analyst,
  permissions: [...analyst.permissions, 'detections:read', 'detections:test'],
};
export const correlationManager: Me = {
  ...correlationAnalyst,
  role: 'soc_manager',
  permissions: [...correlationAnalyst.permissions, 'detections:publish'],
};
export const correlationRule: CorrelationRule = {
  id: 'possible-bruteforce-compromise',
  rule_version: '1.0.0',
  version: 3,
  title: 'Nieudane logowania, potem udane',
  description: 'Pięć nieudanych logowań przed sukcesem z tej samej encji.',
  severity: 'high',
  enabled: true,
  type: 'correlation',
  allowed_lateness_seconds: 120,
  max_candidates: 500,
  evaluator_version: 'correlation-v1',
  pattern: {
    kind: 'sequence',
    window_seconds: 600,
    group_by: ['same_user', 'same_host', 'same_ip'],
    stages: [
      {
        name: 'Nieudane logowania',
        count: 5,
        condition: {
          all: [
            { field: 'event.outcome', operator: 'equals', value: 'failure' },
            {
              any: [
                { field: 'source.type', operator: 'equals', value: 'linux_auth' },
                { field: 'source.type', operator: 'equals', value: 'windows_auth' },
              ],
            },
          ],
        },
      },
      {
        name: 'Udane logowanie',
        count: 1,
        condition: { field: 'event.outcome', operator: 'equals', value: 'success' },
      },
    ],
  },
};
export const contributors = Array.from({ length: 6 }, (_, index) => ({
  ...original,
  event_id: `20000000-0000-0000-0000-${String(index + 1).padStart(12, '0')}`,
  timestamp: new Date(Date.parse(timestamp) + index * 10000).toISOString(),
  event: {
    ...original.event,
    category: 'authentication',
    action: index === 5 ? 'login_success' : 'login_failed',
    outcome: index === 5 ? 'success' : 'failure',
  },
}));
export const correlationAlert: AlertDetail = {
  ...alertDetail,
  title: correlationRule.title,
  rule_id: correlationRule.id,
  detection_type: 'correlation',
  event_count: 6,
  reason: {
    kind: 'sequence',
    window_seconds: 600,
    group_by: { same_user: 'scoped-identity', same_host: 'scoped-host', same_ip: '192.0.2.10' },
    stages: [
      {
        name: 'failed_logins',
        required_count: 5,
        event_ids: contributors.slice(0, 5).map((event) => event.event_id),
      },
      { name: 'successful_login', required_count: 1, event_ids: [contributors[5].event_id] },
    ],
    assessment: 'potential_activity_requires_analyst_review',
  },
  event_id: contributors[5].event_id,
  event_snapshot: contributors[5],
  event_snapshots: contributors.map((event, index) => ({
    event_id: event.event_id,
    event_sha256: String(index + 1).repeat(64),
    event_snapshot: event,
  })),
};
export const correlationResult: CorrelationTestResult = {
  rule_id: correlationRule.id,
  rule_version: correlationRule.rule_version!,
  evaluator_version: correlationRule.evaluator_version,
  complete: true,
  matches: [
    {
      event_ids: contributors.map((event) => event.event_id),
      event_timestamp: contributors[5].timestamp,
      reason: { summary: 'Pięć niepowodzeń i późniejszy sukces w oknie 10 minut.' },
    },
  ],
};
