import { useCallback, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from '../components';
import type { Json, Me, Page, Rule } from '../types';
import { useResource } from '../utilities';
import { MitreMapping } from '../mitre/MitreMapping';

export function SingleEventRules({ user }: { user: Me }) {
  const loader = useCallback(() => api.get<Page<Rule>>('/detections'), []);
  const resource = useResource(loader);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [selected, setSelected] = useState<Rule | null>(null);
  const [payload, setPayload] = useState('[]');
  const [result, setResult] = useState<Json | null>(null);
  async function toggle(rule: Rule) {
    setPending(true);
    setError(null);
    try {
      await api.patch(
        `/detections/${encodeURIComponent(rule.id)}`,
        { enabled: !rule.enabled },
        rule.version,
      );
      await resource.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  async function test() {
    if (!selected) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const events = JSON.parse(payload) as unknown;
      if (!Array.isArray(events) || events.length < 1 || events.length > 100)
        throw new Error('Podaj listę maksymalnie 100 pełnych znormalizowanych rekordów.');
      if (new TextEncoder().encode(JSON.stringify({ id: selected.id, events })).length > 65536)
        throw new Error(
          'Test może zawierać najwyżej 64 KiB danych. Podziel rekordy na mniejsze grupy.',
        );
      setResult(await api.post<Json>('/detections/test', { id: selected.id, events }));
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Reguły detekcji</h2>
          <p>Wbudowane, wersjonowane detekcje pojedynczych zdarzeń. Test nie tworzy alertów.</p>
        </div>
        <button
          disabled={resource.pending}
          onClick={() => {
            void resource.reload();
          }}
        >
          Odśwież
        </button>
      </div>
      <ErrorNotice error={resource.error ?? error} />
      {resource.pending && <Loading />}
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
            <MitreMapping mapping={rule.mitre_mapping} />
            <small className="mono">
              {rule.id} · {rule.rule_version}
            </small>
            <div className="button-row">
              {user.permissions.includes('detections:test') && (
                <button
                  onClick={() => {
                    setSelected(rule);
                    setResult(null);
                  }}
                >
                  Testuj regułę
                </button>
              )}
              {user.permissions.includes('detections:publish') && (
                <button
                  disabled={pending || resource.pending}
                  onClick={() => {
                    void toggle(rule);
                  }}
                >
                  {rule.enabled ? 'Wyłącz regułę' : 'Włącz regułę'}
                </button>
              )}
            </div>
            <details>
              <summary>Warunki i ograniczenia</summary>
              <JsonView value={rule} />
            </details>
          </article>
        ))}
      </div>
      {resource.data?.items.length === 0 && <Empty title="Brak reguł" />}
      {selected && (
        <Panel
          title={`Test: ${selected.title}`}
          aside={
            <button className="quiet" onClick={() => setSelected(null)}>
              Zamknij test
            </button>
          }
        >
          <p className="muted">
            Wklej listę pełnych rekordów JSON z Event Explorer → Pełny rekord i pochodzenie. Test
            jest izolowany: nie zapisuje alertów ani nie zmienia włączenia reguły.
          </p>
          <label>
            Znormalizowane zdarzenia (JSON array)
            <textarea
              className="code-input"
              rows={9}
              maxLength={60000}
              value={payload}
              onChange={(event) => setPayload(event.target.value)}
            />
          </label>
          <button
            className="primary"
            disabled={pending}
            onClick={() => {
              void test();
            }}
          >
            {pending ? 'Sprawdzanie…' : 'Uruchom test'}
          </button>
          <ErrorNotice error={error} />
          {result !== null && (
            <>
              <h3>Wynik testu</h3>
              <JsonView value={result} />
            </>
          )}
        </Panel>
      )}
    </>
  );
}
