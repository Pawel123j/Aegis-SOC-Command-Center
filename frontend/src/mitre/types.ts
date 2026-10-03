export interface MitreCatalogue {
  domain: 'enterprise-attack';
  version: string;
  sha256: string;
  source_url: string;
  source_sha256: string;
  source_commit: string;
  tactics_count: number;
  techniques_count: number;
  attribution?: string;
  license_url?: string;
}

export interface MitreTactic {
  id: string;
  name: string;
  url: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
  tactics: MitreTactic[];
}

export interface MitreMapping {
  status: 'mapped' | 'unmapped' | 'legacy_unmapped';
  claim: 'candidate_association';
  confirmed_attack: false;
  catalogue_version: string | null;
  catalogue_hash: string | null;
  mapping_version: string | null;
  mapping_hash: string | null;
  techniques: MitreTechnique[];
  reason: string;
}

export interface IncidentMitreMapping {
  claim: 'candidate_association';
  confirmed_attack: false;
  techniques: (MitreTechnique & { catalogue_version: string; catalogue_hash: string })[];
  mapped_alerts: number;
  unmapped_alerts: number;
  legacy_alerts: number;
  excluded_false_positive_alerts: number;
}

export interface MitreScope {
  mode: 'live' | 'replay';
  from: string;
  to: string;
  dataset_id: string | null;
  run_id: string | null;
  include_false_positives: boolean;
  time_basis: 'alert.event_timestamp';
  interval: '[from,to)';
}

interface MitreCounts {
  configured_rule_count: number;
  enabled_rule_count: number;
  alert_count: number;
  incident_count: number;
}

export interface CoverageTechnique extends MitreTactic, MitreCounts {
  parent_id: string | null;
  tactic_ids: string[];
  is_subtechnique: boolean;
}

export interface MitreCoverage {
  catalogue: MitreCatalogue;
  scope: MitreScope;
  claim: 'candidate_association';
  confirmed_attack: false;
  tactics: (MitreTactic & MitreCounts)[];
  techniques: CoverageTechnique[];
  summary: {
    eligible_alerts: number;
    mapped_alerts: number;
    unmapped_alerts: number;
    legacy_alerts: number;
    other_catalogue_alerts: number;
    excluded_false_positive_alerts: number;
    incidents: number;
    observed_techniques: number;
    observed_tactics: number;
    configured_techniques: number;
    enabled_techniques: number;
    configured_tactics: number;
    enabled_tactics: number;
  };
}
