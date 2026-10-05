import type {
  EventIntelligenceProof,
  IntelligenceProviders,
  Ioc,
  IocHistory,
  IocLookupResult,
  IocPage,
} from '../src/intelligence/types';
import { original, reader, timestamp } from './incidentFixtures';

export const intelligenceReader = {
  ...reader,
  permissions: [...reader.permissions, 'intelligence:read'],
};
export const intelligenceManager = {
  ...intelligenceReader,
  role: 'soc_manager' as const,
  permissions: [...intelligenceReader.permissions, 'intelligence:manage'],
};
export const intelligenceAdmin = {
  ...intelligenceManager,
  role: 'admin' as const,
  permissions: [...intelligenceManager.permissions, 'system:manage'],
};
export const ioc: Ioc = {
  id: '90000000-0000-0000-0000-000000000001',
  type: 'ip',
  value: '192.0.2.10',
  canonical_value: '192.0.2.10',
  normalization_version: 'ioc-normalization-v1',
  reputation: 'suspicious',
  confidence: null,
  source: 'Własna analiza',
  first_seen: null,
  last_seen: timestamp,
  tags: ['lab'],
  description: 'Wskaźnik do analizy.',
  active: true,
  revision: 1,
  revision_id: '91000000-0000-0000-0000-000000000001',
  document_sha256: 'a'.repeat(64),
  version: 1,
  created_at: timestamp,
  created_by: intelligenceManager.id,
  updated_at: timestamp,
  updated_by: intelligenceManager.id,
};
export const iocPage: IocPage = {
  items: [ioc],
  total: 275,
  next_cursor: null,
  normalization_version: ioc.normalization_version,
  limits: { max_iocs: 1000, max_revisions: 50, max_import: 100 },
};
export const iocProviders: IntelligenceProviders = {
  items: [
    {
      id: 'local',
      name: 'Local IOC catalogue',
      kind: 'local',
      enabled: true,
      network_access: false,
      status: 'available',
      description: 'Własny lokalny katalog, bez zewnętrznych połączeń.',
    },
  ],
  normalization_version: ioc.normalization_version,
};
export const iocLookup: IocLookupResult = {
  type: 'ip',
  canonical_value: ioc.value,
  normalization_version: ioc.normalization_version,
  found: true,
  item: ioc,
};
export const iocHistory: IocHistory = {
  total: 2,
  next_cursor: null,
  items: [
    {
      id: '91000000-0000-0000-0000-000000000002',
      ioc_id: ioc.id,
      revision: 2,
      document: { type: 'ip', value: ioc.value, active: false, source: 'Późniejsza analiza' },
      document_sha256: 'b'.repeat(64),
      created_at: timestamp,
      created_by: intelligenceManager.id,
    },
    {
      id: ioc.revision_id,
      ioc_id: ioc.id,
      revision: 1,
      document: { type: 'ip', value: ioc.value, active: true, source: ioc.source },
      document_sha256: ioc.document_sha256,
      created_at: timestamp,
      created_by: intelligenceManager.id,
    },
  ],
};
export const eventIocProof: EventIntelligenceProof = {
  event_id: original.event_id,
  status: 'evaluated',
  normalization_version: ioc.normalization_version,
  evaluator_version: 'intelligence-match-v1',
  document_sha256: 'e'.repeat(64),
  evaluated_at: timestamp,
  reputation_origin: 'source_assertion',
  confirmed_attack: false,
  match_count: 1,
  matches: [
    {
      id: '92000000-0000-0000-0000-000000000001',
      event_id: original.event_id,
      ioc_id: ioc.id,
      revision_id: ioc.revision_id,
      field: 'source.ip',
      observed_value: ioc.value,
      canonical_value: ioc.value,
      revision_snapshot_sha256: ioc.document_sha256,
      revision_snapshot: {
        ioc_id: ioc.id,
        revision_id: ioc.revision_id,
        revision: 1,
        type: ioc.type,
        value: ioc.value,
        canonical_value: ioc.value,
        normalization_version: ioc.normalization_version,
        reputation: 'unknown',
        confidence: null,
        source: 'Dawna deklaracja źródła',
        first_seen: ioc.first_seen,
        last_seen: ioc.last_seen,
        description: ioc.description,
        tags: ioc.tags,
        active: true,
      },
    },
  ],
};
