import { useState } from 'react';
import { Empty, JsonView, Loading, Panel } from '../components';
import { MitreMapping } from '../mitre/MitreMapping';
import type { Me, SecurityEvent } from '../types';
import { time } from '../utilities';
import { SigmaEditor } from './SigmaEditor';
import { SigmaFailure } from './SigmaFailure';
import { SigmaTest } from './SigmaTest';
import type { SigmaCapabilities, SigmaRuleDetail } from './types';
import { useSigmaResource } from './useSigmaResource';
import type { SigmaScope } from './useSigmaScope';

export function SigmaDetails({
  id,
  user,
  capabilities,
  scope,
  onClose,
  onSaved,
  onEvent,
}: {
  id: string;
  user: Me;
  capabilities: SigmaCapabilities;
  scope: SigmaScope;
  onClose: () => void;
  onSaved: (rule: SigmaRuleDetail) => void;
  onEvent: (event: SecurityEvent) => void;
}) {
  const resource = useSigmaResource<SigmaRuleDetail>(
    `/sigma/rules/${encodeURIComponent(id)}`,
    scope,
  );
  const [editingRule, setEditingRule] = useState<SigmaRuleDetail | null>(null);
  const [testPayload, setTestPayload] = useState('[]');
  const rule = resource.data;
  return (
    <Panel
      title={rule?.title ?? 'Szczegóły reguły Sigma'}
      aside={
        <button className="quiet" onClick={onClose}>
          Zamknij regułę Sigma
        </button>
      }
    >
      <SigmaFailure error={resource.error} />
      {resource.pending && <Loading />}
      <div className="button-row sigma-actions">
        <button
          disabled={resource.pending || scope.expired || Boolean(editingRule)}
          onClick={resource.reload}
        >
          Odśwież szczegóły Sigma
        </button>
      </div>
      {rule && (
        <>
          <p>{rule.description}</p>
          <p>
            Wersja definicji {rule.revision} · wersja stanu {rule.version} ·{' '}
            {rule.enabled ? 'Aktywna' : 'Wyłączona'}
          </p>
          <p>
            Priorytet jest zadeklarowany w regule. Powiązania ATT&CK nie potwierdzają pewności ani
            udanego ataku.
          </p>
          <MitreMapping mapping={rule.mitre_mapping} />
          {rule.false_positive_guidance.length > 0 && (
            <>
              <h3>Co sprawdzić podczas analizy</h3>
              <ul>
                {rule.false_positive_guidance.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </>
          )}
          <details>
            <summary>Definicja YAML</summary>
            <JsonView value={rule.definition_yaml} />
          </details>
          <details>
            <summary>Warunki wewnętrznego silnika</summary>
            <JsonView value={rule.compiled} />
          </details>
          <details>
            <summary>Historia definicji Sigma ({rule.versions.length})</summary>
            <p>
              Każdy zapis zachowuje poprzednią definicję. Włączenie reguły zmienia wersję stanu, nie
              wersję definicji.
            </p>
            {rule.versions.length ? (
              <ol className="sigma-history">
                {rule.versions.map((version) => (
                  <li key={version.id}>
                    <h3>
                      Definicja {version.revision}
                      {version.revision === rule.revision ? ' · bieżąca' : ''}
                    </h3>
                    <p>
                      {time(version.created_at)} · autor {version.created_by}
                    </p>
                    <dl className="facts">
                      <dt>ID wersji</dt>
                      <dd className="mono">{version.id}</dd>
                      <dt>SHA-256 YAML</dt>
                      <dd className="mono">{version.source_sha256}</dd>
                      <dt>SHA-256 warunków</dt>
                      <dd className="mono">{version.compiled_sha256}</dd>
                    </dl>
                  </li>
                ))}
              </ol>
            ) : (
              <Empty title="Historia definicji jest niedostępna" />
            )}
          </details>
          <details>
            <summary>Pochodzenie reguły Sigma</summary>
            <dl className="facts">
              <dt>Sigma ID</dt>
              <dd className="mono">{rule.id}</dd>
              <dt>SHA-256 YAML</dt>
              <dd className="mono">{rule.source_sha256}</dd>
              <dt>SHA-256 warunków</dt>
              <dd className="mono">{rule.compiled_sha256}</dd>
              <dt>Wersja silnika</dt>
              <dd>{rule.evaluator_version}</dd>
              <dt>Źródła logów</dt>
              <dd>{rule.source_types.join(', ')}</dd>
            </dl>
            <h3>Referencje autora reguły</h3>
            <ul>
              {rule.references.map((reference, index) => (
                <li className="mono" key={index}>
                  {reference}
                </li>
              ))}
            </ul>
          </details>
          {user.permissions.includes('detections:import') && !editingRule && (
            <button disabled={scope.expired} onClick={() => setEditingRule(rule)}>
              Dodaj wersję Sigma
            </button>
          )}
          {user.permissions.includes('detections:test') && (
            <SigmaTest
              key={rule.revision_id}
              rule={rule}
              capabilities={capabilities}
              scope={scope}
              onEvent={onEvent}
              payload={testPayload}
              onPayloadChange={setTestPayload}
            />
          )}
        </>
      )}
      {editingRule && (
        <SigmaEditor
          key={editingRule.id}
          scope={scope}
          capabilities={capabilities}
          rule={editingRule}
          onClose={() => setEditingRule(null)}
          onSaved={(saved) => {
            setEditingRule(null);
            resource.reload();
            onSaved(saved);
          }}
        />
      )}
    </Panel>
  );
}
