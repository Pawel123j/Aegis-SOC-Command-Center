import type { Json } from '../types';

export interface Definition {
  schema_version: 1;
  title: string;
  description: string;
  steps: { id: string; action: string }[];
}
export interface Playbook {
  id: string;
  version: number;
  enabled: boolean;
  latest_revision: number;
  published_revision: number | null;
  definition: Definition;
  published_definition: Definition | null;
  required_permissions: string[];
}
export interface Actions {
  actions: { id: string; label: string; required_permission: string }[];
}
export interface Targets {
  alert_id: string;
  title: string;
  anchor_event_id: string;
  mode: string;
  dataset_id: string;
  data_run_id: string;
  items: {
    event_id: string;
    timestamp: string;
    source_ip: string | null;
    destination_ip: string | null;
    host: string | null;
  }[];
}
export interface RunSummary {
  id: string;
  alert_id: string;
  state: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  deadline_at: string;
  next_attempt_at: string;
  requested_by: string;
  mode: string;
  dataset_id: string;
  data_run_id: string;
  replay_of: string | null;
  error_code: string | null;
}
export interface Run extends RunSummary {
  playbook_id: string;
  revision: number;
  definition: Definition;
  context: {
    event_id: string;
    ip_field: 'source' | 'destination';
    ip: string | null;
    host: string | null;
    alert_title: string;
  };
  steps: {
    id: string;
    position: number;
    action: string;
    state: string;
    attempts: number;
    error_code: string | null;
    not_executed_reason: string | null;
    started_at: string | null;
    finished_at: string | null;
    output: {
      reason?: string;
      simulated?: boolean;
      local_effect?: boolean;
      [key: string]: Json | undefined;
    } | null;
    history: {
      number: number;
      outcome: string;
      error_code: string | null;
      started_at: string;
      finished_at: string;
    }[];
  }[];
}
export interface Notification {
  id: string;
  run_id: string;
  message: string;
  created_at: string;
  read_at: string | null;
}
export const stateLabel: Record<string, string> = {
  queued: 'W kolejce',
  running: 'W trakcie',
  completed: 'Zakończono',
  failed: 'Zatrzymano z błędem',
  cancelled: 'Anulowano',
  waiting: 'Oczekuje',
  expired: 'Przerwana próba',
};
export const actionLabel: Record<string, string> = {
  enrich_ip: 'Sprawdzenie IP',
  check_threat_intelligence: 'Zachowany dowód TI',
  calculate_risk: 'Wyjaśniona ocena ryzyka',
  create_incident: 'Utworzenie lub powiązanie incydentu',
  add_ioc: 'Nieaktywny IOC do przeglądu',
  notify_analyst: 'Powiadomienie w aplikacji',
  simulate_block_ip: 'Symulacja blokady IP',
  simulate_isolate_host: 'Symulacja izolacji komputera',
  simulate_webhook: 'Symulacja webhooka',
};
export const canReadSoar = (permissions: string[]) =>
  ['playbooks:read', 'alerts:read', 'incidents:read', 'events:read', 'intelligence:read'].every(
    (p) => permissions.includes(p),
  );
