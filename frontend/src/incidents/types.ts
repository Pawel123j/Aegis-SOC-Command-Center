import type { Alert, EventSnapshot, Json, SecurityEvent } from '../types';
import type { incidentSeverities, incidentStatuses } from './labels';

export type IncidentStatus = keyof typeof incidentStatuses;
export type IncidentSeverity = keyof typeof incidentSeverities;
export interface IncidentActor {
  id: string;
  username: string;
  role: string;
}
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  risk_score: number | null;
  confidence: number | null;
  created_at: string;
  updated_at: string;
  first_seen: string | null;
  last_seen: string | null;
  owner_id: string | null;
  owner: IncidentActor | null;
  tags: string[];
  alert_count: number;
  mode: string;
  dataset_id: string | null;
  run_id: string;
  version: number;
}
export interface IncidentNote {
  id: string;
  body: string;
  created_at: string;
  author: IncidentActor | null;
}
export interface IncidentTimelineEntry {
  id: string;
  kind: string;
  occurred_at: string;
  actor: IncidentActor | null;
  data: Json;
}
export interface IncidentEvidence {
  id: string;
  alert_id: string;
  event_id: string;
  event_timestamp: string;
  linked_at: string;
  active: boolean;
  detached_at: string | null;
  event_sha256: string;
  rule_snapshot: Json;
  event_snapshot: SecurityEvent;
  event_snapshots?: EventSnapshot[];
  reason: Json;
}
export interface IncidentDetail extends Incident {
  dataset_ids: string[];
  related_alerts: Alert[];
  related_users: string[];
  related_hosts: string[];
  related_ip_addresses: string[];
  mitre_techniques: string[];
  evidence_count: number;
  notes: IncidentNote[];
  timeline: IncidentTimelineEntry[];
}
export interface IncidentCreate {
  title: string;
  description: string;
  severity: IncidentSeverity;
  alert_ids: string[];
  tags: string[];
}
export interface IncidentPatch {
  title?: string;
  description?: string;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  status_reason?: string;
  owner_id?: string | null;
  tags?: string[];
}
