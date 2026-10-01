export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Me {
  id: string;
  username: string;
  role: 'admin' | 'soc_manager' | 'soc_analyst' | 'read_only';
  permissions: string[];
}
export interface SecurityEvent {
  event_id: string;
  source_id: string;
  dataset_id: string;
  run_id: string;
  mode: string;
  schema_version: string;
  parser_version: string;
  timestamp: string;
  received_at: string;
  processed_at: string;
  source_event_id: string | null;
  source: { name: string; type: string; ip: string | null; port: number | null };
  destination: { ip: string | null; port: number | null };
  host: { id: string | null; name: string | null; os: string | null };
  user: {
    id: string | null;
    name: string | null;
    realm: string | null;
    target: { id: string | null; name: string | null; realm: string | null };
  };
  process: {
    name: string | null;
    executable: string | null;
    command_line: string | null;
    pid: number | null;
    entity_id: string | null;
  };
  event: {
    category: string;
    type: string;
    action: string;
    severity: string;
    outcome: string;
    code: string | null;
  };
  raw_event: Json;
  raw_sha256: string;
  quality: string[];
  extensions: Record<string, Json>;
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  total?: number;
}
export interface SearchResult extends Page<SecurityEvent> {
  total: number;
  from: string;
  to: string;
}
export interface SearchInput {
  from?: string;
  to?: string;
  q?: string;
  limit?: number;
  cursor?: string;
  mode?: string;
  source_id?: string;
}
export interface Source {
  id: string;
  name: string;
  dataset_id: string;
  mode: string;
  run_id: string;
  source_types: string[];
  timezone: string;
  enabled: boolean;
  version: number;
  created_at: string;
}
export interface Credential {
  id: string;
  token?: string;
  scopes: string[];
  expires_at: string;
  revoked_at: string | null;
}
export interface Enrollment {
  source: Source;
  credential: Credential;
}
export interface Pipeline {
  event_id: string;
  state: string;
  normalization_attempts: number;
  projection_attempts: number;
  error_code: string | null;
  version: number;
}
export interface BatchStatus {
  batch_id: string;
  accepted_count: number;
  created_count: number;
  duplicate_count: number;
  counts: Record<string, number>;
  records: {
    position: number;
    event_id: string;
    state: string;
    pipeline_state: string | null;
    error_code: string | null;
    pipeline_error_code: string | null;
    pipeline_version: number | null;
    detection_state: string | null;
  }[];
}
export interface Alert {
  id: string;
  title: string;
  severity: string;
  status: string;
  event_id: string;
  event_timestamp: string;
  created_at: string;
  updated_at: string;
  version: number;
  rule_id: string;
  rule_version: string;
  source_id: string;
  dataset_id: string;
  mode: string;
  run_id: string;
  risk_score: null;
}
export interface AlertDetail extends Alert {
  rule_snapshot: Json;
  event_snapshot: SecurityEvent;
  reason: Json;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}
export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: string;
  enabled: boolean;
  version: number;
  rule_version?: string;
  [key: string]: unknown;
}
