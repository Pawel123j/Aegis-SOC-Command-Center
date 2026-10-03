import type { IncidentMitreMapping, MitreCoverage, MitreMapping } from '../src/mitre/types';
import type { Me } from '../src/types';
import { reader } from './incidentFixtures';

export const mitreReader: Me = {
  ...reader,
  permissions: [...reader.permissions, 'detections:read'],
};

export const mitreMapping: MitreMapping = {
  status: 'mapped',
  claim: 'candidate_association',
  confirmed_attack: false,
  catalogue_version: '19.2',
  catalogue_hash: 'a'.repeat(64),
  mapping_version: 'mitre-mapping-v1',
  mapping_hash: 'b'.repeat(64),
  reason: 'Powiązanie z zachowaną regułą i katalogiem.',
  techniques: [
    {
      id: 'T1059.001',
      name: 'PowerShell',
      url: 'https://attack.mitre.org/techniques/T1059/001/',
      tactics: [
        { id: 'TA0002', name: 'Execution', url: 'https://attack.mitre.org/tactics/TA0002/' },
      ],
    },
  ],
};

export const incidentMitreMapping: IncidentMitreMapping = {
  claim: 'candidate_association',
  confirmed_attack: false,
  techniques: mitreMapping.techniques.map((technique) => ({
    ...technique,
    catalogue_version: '19.2',
    catalogue_hash: 'a'.repeat(64),
  })),
  mapped_alerts: 1,
  unmapped_alerts: 1,
  legacy_alerts: 1,
  excluded_false_positive_alerts: 1,
};

export const mitreCoverage: MitreCoverage = {
  catalogue: {
    domain: 'enterprise-attack',
    version: '19.2',
    sha256: 'a'.repeat(64),
    source_url:
      'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/release/enterprise-attack/enterprise-attack.json',
    source_sha256: 'c'.repeat(64),
    source_commit: 'd'.repeat(40),
    tactics_count: 15,
    techniques_count: 697,
    attribution: 'MITRE ATT&CK® is a registered trademark of The MITRE Corporation.',
    license_url: 'https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt',
  },
  scope: {
    mode: 'live',
    from: '2026-01-01T00:00:00Z',
    to: '2026-01-31T00:00:00Z',
    dataset_id: null,
    run_id: null,
    include_false_positives: false,
    time_basis: 'alert.event_timestamp',
    interval: '[from,to)',
  },
  claim: 'candidate_association',
  confirmed_attack: false,
  tactics: [
    {
      id: 'TA0002',
      name: 'Execution',
      url: 'https://attack.mitre.org/tactics/TA0002/',
      configured_rule_count: 2,
      enabled_rule_count: 1,
      alert_count: 3,
      incident_count: 2,
    },
    {
      id: 'TA0001',
      name: 'Initial Access',
      url: 'https://attack.mitre.org/tactics/TA0001/',
      configured_rule_count: 0,
      enabled_rule_count: 0,
      alert_count: 0,
      incident_count: 0,
    },
  ],
  techniques: [
    {
      id: 'T1059.001',
      name: 'PowerShell',
      url: 'https://attack.mitre.org/techniques/T1059/001/',
      parent_id: 'T1059',
      is_subtechnique: true,
      tactic_ids: ['TA0002'],
      configured_rule_count: 2,
      enabled_rule_count: 1,
      alert_count: 3,
      incident_count: 2,
    },
    {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      url: 'https://attack.mitre.org/techniques/T1059/',
      parent_id: null,
      is_subtechnique: false,
      tactic_ids: ['TA0002'],
      configured_rule_count: 0,
      enabled_rule_count: 0,
      alert_count: 0,
      incident_count: 0,
    },
  ],
  summary: {
    eligible_alerts: 9,
    mapped_alerts: 3,
    unmapped_alerts: 2,
    legacy_alerts: 2,
    other_catalogue_alerts: 2,
    excluded_false_positive_alerts: 1,
    incidents: 2,
    observed_techniques: 1,
    observed_tactics: 1,
    configured_techniques: 1,
    enabled_techniques: 1,
    configured_tactics: 1,
    enabled_tactics: 1,
  },
};
