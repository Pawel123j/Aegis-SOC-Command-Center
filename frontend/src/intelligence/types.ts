export type IocType = 'ip' | 'domain' | 'url' | 'hash';
export type Reputation = 'unknown' | 'clean' | 'suspicious' | 'malicious';
export interface IocMetadata {
  reputation: Reputation;
  confidence: number | null;
  source: string;
  first_seen: string | null;
  last_seen: string | null;
  tags: string[];
  description: string;
  active: boolean;
}
export interface IocInput extends IocMetadata {
  type: IocType;
  value: string;
}
export interface Ioc extends IocInput {
  id: string;
  canonical_value: string;
  normalization_version: string;
  revision: number;
  revision_id: string;
  document_sha256: string;
  version: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}
export interface IocPage {
  items: Ioc[];
  total: number;
  next_cursor: string | null;
  normalization_version: string;
  limits: { max_iocs: number; max_revisions: number; max_import: number };
}
export interface IocRevision {
  id: string;
  ioc_id: string;
  revision: number;
  document: Record<string, unknown>;
  document_sha256: string;
  created_at: string;
  created_by: string;
}
export interface IocHistory {
  items: IocRevision[];
  total: number;
  next_cursor: string | null;
}
export interface IocLookupResult {
  type: IocType;
  canonical_value: string;
  normalization_version: string;
  found: boolean;
  item: Ioc | null;
}
export interface IocImportResult {
  items: Ioc[];
  created: number;
  unchanged: number;
}
export interface IntelligenceProviders {
  items: {
    id: string;
    name: string;
    kind: 'local';
    enabled: boolean;
    network_access: false;
    status: string;
    description: string;
  }[];
  normalization_version: string;
}
export interface EventIntelligenceProof {
  event_id: string;
  status: 'evaluated' | 'pending';
  normalization_version: string;
  evaluator_version: string;
  document_sha256: string;
  evaluated_at: string | null;
  matches: {
    id: string;
    event_id: string;
    ioc_id: string;
    revision_id: string;
    field: string;
    observed_value: string;
    canonical_value: string;
    revision_snapshot: IocInput & {
      ioc_id: string;
      revision_id: string;
      revision: number;
      canonical_value: string;
      normalization_version: string;
    };
    revision_snapshot_sha256: string;
  }[];
  match_count: number;
  reputation_origin: 'source_assertion';
  confirmed_attack: false;
}
export interface IntelligenceBackfillResult {
  events: number;
  matches: number;
  remaining: number;
  alerts_created: 0;
  evaluator_version: string;
}
