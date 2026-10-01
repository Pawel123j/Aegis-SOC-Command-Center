import { useCallback } from 'react';
import { api } from '../api';
import { ErrorNotice, Loading, Metric, Panel } from '../components';
import { time, useResource } from '../utilities';
import type { CorrelationCoverage } from './types';

const states = [
  ['pending', 'Oczekujące', 'Czekają na domknięcie okna lub zestawu replay'],
  ['processed', 'Przetworzone', 'Sprawdzone przez aktywne korelacje'],
  ['late', 'Spóźnione', 'Po zamknięciu okna lub poza zestawem replay'],
  ['clock_skew', 'Nieprawidłowy czas', 'Czas logu wyprzedza przyjęcie'],
  ['quarantined', 'Kwarantanna', 'Nie można potwierdzić integralności rekordu'],
  ['incomplete', 'Niekompletne', 'Przekroczony limit kandydatów lub kontekstu'],
];

export function CorrelationStatus({ revision }: { revision: number }) {
  const loader = useCallback(() => {
    void revision;
    return api.get<CorrelationCoverage>('/correlations/status');
  }, [revision]);
  const resource = useResource(loader);
  return (
    <Panel title="Pokrycie przetwarzania korelacji">
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data?.counts && !resource.error && (
        <>
          <div className="correlation-coverage">
            {states.map(([state, label, note]) => (
              <Metric
                key={state}
                label={label}
                value={resource.data!.counts[state] ?? 0}
                note={note}
              />
            ))}
          </div>
          <p className="muted">
            Spóźnione, niekompletne i odrzucone rekordy nie potwierdzają braku zagrożeń. Sprawdź
            zakres danych przed oceną wyników.
          </p>
          <details>
            <summary>Granice przetwarzania live i replay</summary>
            {resource.data.scopes.length ? (
              resource.data.scopes.map((scope) => (
                <dl className="facts" key={scope.namespace}>
                  <dt>Zakres</dt>
                  <dd className="mono">
                    {scope.namespace === 'live' ? 'Live · wszystkie źródła' : scope.namespace}
                  </dd>
                  <dt>Domknięto czas do</dt>
                  <dd>{time(scope.watermark)}</dd>
                  {scope.namespace !== 'live' && (
                    <>
                      <dt>Zamknięto zestaw replay</dt>
                      <dd>{scope.sealed_at ? time(scope.sealed_at) : 'Oczekuje na zamknięcie'}</dd>
                      <dt>Liczba zdarzeń w zestawie</dt>
                      <dd>{scope.event_count}</dd>
                      <dt>SHA-256 zestawu</dt>
                      <dd className="mono">{scope.manifest_sha256 ?? '—'}</dd>
                    </>
                  )}
                </dl>
              ))
            ) : (
              <p>Brak przyjętych zakresów korelacji.</p>
            )}
            {resource.data.scopes_truncated && (
              <p className="notice">
                Widok pokazuje pierwsze 100 zakresów. Lista zakresów jest niepełna.
              </p>
            )}
          </details>
        </>
      )}
    </Panel>
  );
}
