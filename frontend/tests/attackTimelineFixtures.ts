import type { AttackTimelinePage } from '../src/incidents/types';
import { alert, incidentFixture, original, timestamp } from './incidentFixtures';

export const attackTimelineFixture: AttackTimelinePage = {
  incident_id: incidentFixture.id,
  incident_version: incidentFixture.version,
  mode: 'live',
  dataset_id: null,
  run_id: original.run_id,
  projection_version: 'attack-timeline-v1',
  view_fingerprint: 'b'.repeat(64),
  total: 1,
  index_status: { eligible_alerts: 1, indexed_alerts: 1, pending_alerts: 0, complete: true },
  items: [
    {
      event_id: original.event_id,
      event_sha256: 'c'.repeat(64),
      event_snapshot: original,
      alerts: [
        {
          id: alert.id,
          title: alert.title,
          severity: alert.severity,
          status: alert.status,
          detection_type: 'single_event',
          rule_id: alert.rule_id,
          rule_version: alert.rule_version,
          linked_at: timestamp,
        },
      ],
    },
  ],
  next_cursor: null,
};
