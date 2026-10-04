import type {
  SigmaCapabilities,
  SigmaRuleDetail,
  SigmaTestResult,
  SigmaValidation,
} from '../src/sigma/types';
import type { Me } from '../src/types';
import { original, reader, timestamp } from './incidentFixtures';
import { mitreMapping } from './mitreFixtures';

export const sigmaReader: Me = {
  ...reader,
  permissions: [...reader.permissions, 'detections:read'],
};
export const sigmaAnalyst: Me = {
  ...sigmaReader,
  role: 'soc_analyst',
  permissions: [...sigmaReader.permissions, 'detections:test'],
};
export const sigmaManager: Me = {
  ...sigmaAnalyst,
  role: 'soc_manager',
  permissions: [...sigmaAnalyst.permissions, 'detections:import', 'detections:publish'],
};
export const sigmaYaml = `title: PowerShell sample
id: 70000000-0000-0000-0000-000000000001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: powershell.exe
  condition: selection
level: high
tags:
  - attack.t1059.001
`;
export const sigmaCapabilities: SigmaCapabilities = {
  evaluator_version: 'sigma-subset-v1',
  max_yaml_bytes: 65536,
  max_rules: 100,
  max_revisions: 20,
  max_test_events: 25,
  max_test_body_bytes: 1048576,
  max_import_body_bytes: 262144,
  operators: ['equals', 'contains', 'startswith', 'endswith'],
  boolean_operators: ['AND', 'OR', 'NOT'],
  fields: ['process.name', 'process.executable', 'process.command_line', 'event.code'],
  integer_fields: ['process.pid'],
  logsources: [
    {
      logsource: { category: 'process_creation', product: 'windows' },
      source_type: 'windows_process',
      aliases: { Image: 'process.executable' },
    },
  ],
  limitations: ['Wildcards, regex, correlation and YAML aliases are unsupported.'],
  risk_policy: 'risk-policy-v3',
  risk_contribution: 'declared-severity-only',
  imported_rules_enabled_by_default: false,
};
export const sigmaRule: SigmaRuleDetail = {
  id: '70000000-0000-0000-0000-000000000001',
  sigma_id: '70000000-0000-0000-0000-000000000001',
  title: 'PowerShell sample',
  description: 'Sample rule for review.',
  severity: 'high',
  mitre: ['T1059.001'],
  false_positive_guidance: ['Review administrator activity.'],
  references: ['https://example.test/sigma'],
  evaluator_version: 'sigma-subset-v1',
  source_types: ['windows_process'],
  source_sha256: 'a'.repeat(64),
  compiled_sha256: 'b'.repeat(64),
  mitre_mapping: mitreMapping,
  revision: 1,
  revision_id: '80000000-0000-0000-0000-000000000001',
  enabled: false,
  version: 1,
  updated_at: timestamp,
  updated_by: sigmaManager.id,
  definition_yaml: sigmaYaml,
  compiled: { condition: { selection: 'selection' } },
  versions: [
    {
      revision: 1,
      id: '80000000-0000-0000-0000-000000000001',
      source_sha256: 'a'.repeat(64),
      compiled_sha256: 'b'.repeat(64),
      created_at: timestamp,
      created_by: sigmaManager.id,
    },
  ],
};
export const sigmaValidation: SigmaValidation = {
  valid: true,
  definition: sigmaRule,
  warnings: ['Review source before enabling.'],
};
export const sigmaResult: SigmaTestResult = {
  definition: sigmaRule,
  tested_events: 1,
  matches: [{ event_id: original.event_id, reason: { matched_selectors: ['selection'] } }],
};
