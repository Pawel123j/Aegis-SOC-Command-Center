import type { MitreMapping } from '../mitre/types';
import type { Json } from '../types';

export interface SigmaCapabilities {
  evaluator_version: string;
  max_yaml_bytes: number;
  max_rules: number;
  max_revisions: number;
  max_test_events: number;
  max_test_body_bytes: number;
  max_import_body_bytes: number;
  operators: string[];
  boolean_operators: string[];
  fields: string[];
  integer_fields: string[];
  logsources: {
    logsource: Record<string, string>;
    source_type: string;
    aliases: Record<string, string>;
  }[];
  limitations: string[];
  risk_policy: string;
  risk_contribution: 'declared-severity-only';
  imported_rules_enabled_by_default: false;
}

export interface SigmaDefinition {
  sigma_id: string;
  title: string;
  description: string;
  severity: string;
  mitre: string[];
  false_positive_guidance: string[];
  references: string[];
  evaluator_version: string;
  source_types: string[];
  source_sha256: string;
  compiled_sha256: string;
  mitre_mapping: MitreMapping;
}

export interface SigmaRule extends SigmaDefinition {
  id: string;
  revision: number;
  revision_id: string;
  enabled: boolean;
  version: number;
  updated_at: string;
  updated_by: string | null;
}

export interface SigmaVersion {
  revision: number;
  id: string;
  source_sha256: string;
  compiled_sha256: string;
  created_at: string;
  created_by: string;
}

export interface SigmaRuleDetail extends SigmaRule {
  definition_yaml: string;
  compiled: Json;
  versions: SigmaVersion[];
}

export interface SigmaValidation {
  valid: true;
  definition: SigmaDefinition;
  warnings: string[];
}

export interface SigmaTestResult {
  definition: SigmaDefinition;
  matches: { event_id: string; reason: Json }[];
  tested_events: number;
}
