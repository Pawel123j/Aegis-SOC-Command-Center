import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Badge, Panel } from '../components';
import { MitreMapping } from '../mitre/MitreMapping';
import { checkBody, checkYaml } from './limits';
import { SigmaFailure } from './SigmaFailure';
import type { SigmaCapabilities, SigmaRuleDetail, SigmaValidation } from './types';
import type { SigmaScope } from './useSigmaScope';

export function SigmaEditor({
  scope,
  capabilities,
  rule,
  canSave = true,
  onSaved,
  onClose,
}: {
  scope: SigmaScope;
  capabilities: SigmaCapabilities;
  rule?: SigmaRuleDetail;
  canSave?: boolean;
  onSaved: (rule: SigmaRuleDetail) => void;
  onClose: () => void;
}) {
  const [yaml, setYaml] = useState(rule?.definition_yaml ?? '');
  const [baseRule, setBaseRule] = useState(rule);
  const [validation, setValidation] = useState<{
    epoch: number;
    yaml: string;
    value: SigmaValidation;
  } | null>(null);
  const [failure, setFailure] = useState<{ epoch: number; value: unknown } | null>(null);
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
  const [blockedEpoch, setBlockedEpoch] = useState<number | null>(null);
  const fileGeneration = useRef(0);
  const active = useRef(true);
  useEffect(() => {
    const counter = fileGeneration;
    active.current = true;
    return () => {
      active.current = false;
      counter.current++;
    };
  }, []);
  function current(epoch: number) {
    return active.current && scope.isCurrent(epoch);
  }
  const pending = pendingEpoch === scope.epoch;
  const blocked = blockedEpoch === scope.epoch;
  const preview =
    validation?.epoch === scope.epoch && validation.yaml === yaml ? validation.value : null;
  async function validate() {
    if (pending || scope.expired) return;
    const epoch = scope.capture();
    setPendingEpoch(epoch);
    setFailure(null);
    setValidation(null);
    try {
      checkYaml(yaml, capabilities.max_yaml_bytes);
      checkBody({ yaml }, capabilities.max_import_body_bytes);
      const value = await api.post<SigmaValidation>('/sigma/validate', { yaml });
      if (current(epoch)) setValidation({ epoch, yaml, value });
    } catch (value) {
      if (current(epoch)) setFailure({ epoch, value });
    } finally {
      if (current(epoch)) setPendingEpoch(null);
    }
  }
  async function save() {
    if (!canSave || !preview || pending || blocked || scope.expired) return;
    const epoch = scope.capture();
    setPendingEpoch(epoch);
    setFailure(null);
    try {
      const saved = await api.post<SigmaRuleDetail>(
        baseRule ? `/sigma/rules/${encodeURIComponent(baseRule.id)}/versions` : '/sigma/rules',
        { yaml },
        baseRule ? { 'If-Match': `"${baseRule.version}"` } : {},
      );
      if (current(epoch)) onSaved(saved);
    } catch (value) {
      if (current(epoch)) {
        setFailure({ epoch, value });
        if (rule) setBlockedEpoch(epoch);
      }
    } finally {
      if (current(epoch)) setPendingEpoch(null);
    }
  }
  async function refreshVersion() {
    if (!baseRule || pending || scope.expired) return;
    const epoch = scope.capture();
    setPendingEpoch(epoch);
    setFailure(null);
    try {
      const latest = await api.get<SigmaRuleDetail>(
        `/sigma/rules/${encodeURIComponent(baseRule.id)}`,
      );
      if (current(epoch)) {
        setBaseRule(latest);
        setBlockedEpoch(null);
        setValidation(null);
      }
    } catch (value) {
      if (current(epoch)) setFailure({ epoch, value });
    } finally {
      if (current(epoch)) setPendingEpoch(null);
    }
  }
  async function readFile(file: File | undefined) {
    const generation = ++fileGeneration.current;
    if (!file || pending || scope.expired) return;
    const epoch = scope.capture();
    setFailure(null);
    setValidation(null);
    try {
      if (file.size > capabilities.max_yaml_bytes)
        throw new Error(`Plik YAML może mieć najwyżej ${capabilities.max_yaml_bytes / 1024} KiB.`);
      const bytes = await file.arrayBuffer();
      if (!current(epoch) || fileGeneration.current !== generation) return;
      let value: string;
      try {
        value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        throw new Error('Plik YAML musi być poprawnie zakodowany w UTF-8.');
      }
      if (current(epoch) && fileGeneration.current === generation) {
        checkYaml(value, capabilities.max_yaml_bytes);
        setYaml(value);
      }
    } catch (value) {
      if (current(epoch) && fileGeneration.current === generation) setFailure({ epoch, value });
    }
  }
  return (
    <Panel
      title={
        rule ? `Nowa wersja: ${rule.title}` : canSave ? 'Import Sigma Rule' : 'Walidacja Sigma YAML'
      }
      aside={
        <button className="quiet" disabled={pending} onClick={onClose}>
          Zamknij import
        </button>
      }
    >
      <p>
        {!canSave
          ? 'Wklej YAML lub wybierz plik, aby sprawdzić warunki i mapowanie. Sprawdzenie nie zapisuje reguły.'
          : rule
            ? 'Zachowaj id reguły. Zapis dodaje niezmienną wersję i wyłącza regułę; jej aktywacja wymaga osobnej decyzji.'
            : 'Wklej YAML lub wybierz plik. Sprawdzenie pokazuje mapowanie przed zapisem. Nowa reguła jest wyłączona; ponowny import tej samej definicji nie zmienia stanu istniejącej reguły.'}
      </p>
      <label>
        Plik Sigma YAML
        <input
          type="file"
          accept=".yaml,.yml"
          disabled={pending || scope.expired}
          onChange={(event) => void readFile(event.target.files?.[0])}
        />
      </label>
      <label>
        Definicja Sigma (YAML)
        <textarea
          className="code-input"
          rows={14}
          value={yaml}
          disabled={pending || scope.expired}
          onChange={(event) => {
            fileGeneration.current++;
            setYaml(event.target.value);
            setValidation(null);
            setFailure(null);
          }}
        />
      </label>
      <div className="button-row sigma-actions">
        <button disabled={pending || scope.expired || blocked} onClick={() => void validate()}>
          Waliduj YAML
        </button>
        {canSave && (
          <button
            className="primary"
            disabled={pending || scope.expired || blocked || !preview}
            onClick={() => void save()}
          >
            {rule ? 'Zapisz nową wersję Sigma' : 'Importuj wyłączoną regułę'}
          </button>
        )}
        {blocked && (
          <button disabled={pending || scope.expired} onClick={() => void refreshVersion()}>
            Odśwież wersję do zapisu
          </button>
        )}
      </div>
      <SigmaFailure error={failure?.epoch === scope.epoch ? failure.value : null} />
      {blocked && (
        <p className="notice">
          Odśwież szczegóły reguły przed kolejną zmianą. Szkic pozostaje w tym formularzu.
        </p>
      )}
      {baseRule && (
        <p className="muted">
          Zmiana użyje wersji stanu {baseRule.version}. Ostatnia definicja: {baseRule.revision}.
        </p>
      )}
      {pending && <p role="status">Sprawdzanie reguły Sigma…</p>}
      {preview && !scope.expired && (
        <section aria-label="Podgląd zweryfikowanej reguły" className="sigma-preview">
          <h3>{preview.definition.title}</h3>
          <Badge tone={preview.definition.severity}>{preview.definition.severity}</Badge>
          <p>{preview.definition.description}</p>
          <p>
            Priorytet pochodzi z poziomu zadeklarowanego w regule. Nie oznacza potwierdzonej
            pewności detekcji.
          </p>
          <p>Źródła: {preview.definition.source_types.join(', ')}</p>
          {preview.warnings.map((warning, index) => (
            <p className="notice" key={index}>
              {warning}
            </p>
          ))}
          <MitreMapping mapping={preview.definition.mitre_mapping} />
          <dl className="facts">
            <dt>Sigma ID</dt>
            <dd className="mono">{preview.definition.sigma_id}</dd>
            <dt>SHA-256 YAML</dt>
            <dd className="mono">{preview.definition.source_sha256}</dd>
            <dt>SHA-256 warunków</dt>
            <dd className="mono">{preview.definition.compiled_sha256}</dd>
            <dt>Wersja silnika</dt>
            <dd>{preview.definition.evaluator_version}</dd>
          </dl>
        </section>
      )}
    </Panel>
  );
}
