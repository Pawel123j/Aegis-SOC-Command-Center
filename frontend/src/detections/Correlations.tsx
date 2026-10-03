import { useCallback, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from '../components';
import type { Me, Page, SecurityEvent } from '../types';
import { useResource } from '../utilities';
import { CorrelationPattern } from './CorrelationPattern';
import { CorrelationTest } from './CorrelationTest';
import { CorrelationStatus } from './CorrelationStatus';
import type { CorrelationRule } from './types';
import { MitreMapping } from '../mitre/MitreMapping';

export function Correlations({
  user,
  onEvent,
}: {
  user: Me;
  onEvent: (event: SecurityEvent) => void;
}) {
  const loader = useCallback(() => api.get<Page<CorrelationRule>>('/correlations'), []);
  const resource = useResource(loader);
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [blocked, setBlocked] = useState(false);
  const [statusRevision, setStatusRevision] = useState(0);
  async function toggle(rule: CorrelationRule) {
    if (pending || blocked) return;
    setPending(true);
    setError(null);
    try {
      await api.patch(
        `/correlations/${encodeURIComponent(rule.id)}`,
        { enabled: !rule.enabled },
        rule.version,
      );
      await resource.reload();
    } catch (failure) {
      setError(failure);
      setBlocked(true);
    } finally {
      setPending(false);
    }
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Korelacja zdarzeń</h2>
          <p>Wykrywaj powiązane sekwencje i progi aktywności na podstawie zachowanych logów.</p>
        </div>
        <button
          disabled={resource.pending || pending}
          onClick={() => {
            setError(null);
            setBlocked(false);
            setStatusRevision((value) => value + 1);
            void resource.reload();
          }}
        >
          Odśwież korelacje
        </button>
      </div>
      <p className="notice">
        Reguły live czekają na bufor opóźnionych logów i zaległe przetwarzanie. Test sprawdza od
        razu wyłącznie przesłany zestaw zdarzeń.
      </p>
      <ErrorNotice error={resource.error ?? error} />
      {blocked && (
        <p className="muted">
          Odśwież korelacje, aby sprawdzić aktualny stan reguł przed kolejną zmianą.
        </p>
      )}
      {resource.pending && <Loading />}
      <CorrelationStatus revision={statusRevision} />
      <div className="rule-grid">
        {resource.data?.items.map((rule) => (
          <article className="panel rule-card" key={rule.id}>
            <div className="panel-heading">
              <Badge tone={rule.severity}>{rule.severity}</Badge>
              <Badge tone={rule.enabled ? 'success' : undefined}>
                {rule.enabled ? 'Aktywna' : 'Wyłączona'}
              </Badge>
            </div>
            <h2>{rule.title}</h2>
            <p>{rule.description}</p>
            <small className="mono">
              {rule.id} · {rule.rule_version}
            </small>
            <p>
              {rule.pattern.kind === 'sequence' ? 'Sekwencja' : 'Próg'} ·{' '}
              {rule.pattern.stages.length} {rule.pattern.stages.length === 1 ? 'etap' : 'etapy'} ·
              okno {rule.pattern.window_seconds / 60} min
            </p>
            <div className="button-row">
              <button
                aria-label={`Przejrzyj regułę: ${rule.title}`}
                onClick={() => setSelected(rule.id)}
              >
                Warunki reguły
              </button>
              {user.permissions.includes('detections:publish') && (
                <button
                  disabled={pending || resource.pending || blocked || Boolean(resource.error)}
                  onClick={() => void toggle(rule)}
                >
                  {rule.enabled ? 'Wyłącz regułę' : 'Włącz regułę'}
                </button>
              )}
            </div>
          </article>
        ))}
      </div>
      {resource.data?.items.length === 0 && <Empty title="Brak reguł korelacji" />}
      {selected && (
        <CorrelationDetails
          key={selected}
          id={selected}
          user={user}
          onClose={() => setSelected(null)}
          onEvent={onEvent}
        />
      )}
    </>
  );
}

function CorrelationDetails({
  id,
  user,
  onClose,
  onEvent,
}: {
  id: string;
  user: Me;
  onClose: () => void;
  onEvent: (event: SecurityEvent) => void;
}) {
  const loader = useCallback(
    () => api.get<CorrelationRule>(`/correlations/${encodeURIComponent(id)}`),
    [id],
  );
  const resource = useResource(loader);
  return (
    <Panel
      title={resource.data?.title ?? 'Warunki korelacji'}
      aside={
        <button className="quiet" onClick={onClose}>
          Zamknij regułę
        </button>
      }
    >
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data && (
        <>
          <CorrelationPattern pattern={resource.data.pattern} />
          <MitreMapping mapping={resource.data.mitre_mapping} />
          {resource.data.false_positive_guidance?.length ? (
            <>
              <h3>Co sprawdzić podczas analizy</h3>
              <ul>
                {resource.data.false_positive_guidance.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </>
          ) : null}
          <p className="muted">
            Bufor opóźnionych zdarzeń: {resource.data.allowed_lateness_seconds} s. Limit kandydatów:{' '}
            {resource.data.max_candidates}. Zbyt duży zbiór wymaga sprawdzenia stanu przetwarzania.
          </p>
          <details>
            <summary>Pełna reguła i ograniczenia</summary>
            <JsonView value={resource.data} />
          </details>
          {user.permissions.includes('detections:test') && (
            <CorrelationTest rule={resource.data} onEvent={onEvent} />
          )}
        </>
      )}
    </Panel>
  );
}
