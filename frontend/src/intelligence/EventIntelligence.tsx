import { useState } from 'react';
import { api } from '../api';
import { Badge, ErrorNotice, JsonView, Loading } from '../components';
import type { Me } from '../types';
import { time } from '../utilities';
import { IntelligenceFailure } from './IntelligenceFailure';
import { iocTypes, reputations, reputationTone } from './labels';
import type { EventIntelligenceProof } from './types';
import { useIntelligenceResource } from './useIntelligenceResource';
import { useIntelligenceScope } from './useIntelligenceScope';
import './intelligence.css';

export function EventIntelligence({ eventId, user }: { eventId: string; user: Me }) {
  if (
    !['events:read', 'intelligence:read'].every((permission) =>
      user.permissions.includes(permission),
    )
  )
    return null;
  return (
    <EventIntelligenceState
      key={`${eventId}/${user.id}/${user.role}/${[...user.permissions].sort().join(',')}`}
      eventId={eventId}
      user={user}
    />
  );
}
function EventIntelligenceState({ eventId, user }: { eventId: string; user: Me }) {
  const scope = useIntelligenceScope();
  const resource = useIntelligenceResource<EventIntelligenceProof>(
    `/intelligence/events/${encodeURIComponent(eventId)}`,
    scope,
  );
  const [refreshing, setRefreshing] = useState<number | null>(null);
  const [error, setError] = useState<{ epoch: number; value: unknown } | null>(null);
  async function refresh() {
    if (refreshing === scope.epoch) return;
    if (!scope.expired) {
      resource.reload();
      return;
    }
    const epoch = scope.capture();
    setRefreshing(epoch);
    setError(null);
    try {
      const current = await api.get<Me>('/auth/me');
      if (!scope.isCurrent(epoch)) return;
      if (
        current.id !== user.id ||
        current.role !== user.role ||
        current.permissions.length !== user.permissions.length ||
        !user.permissions.every((permission) => current.permissions.includes(permission))
      )
        throw new Error(
          'Konto lub uprawnienia zmieniły się. Otwórz dowód ponownie w bieżącej sesji.',
        );
      scope.resume();
    } catch (value) {
      if (scope.isCurrent(epoch)) setError({ epoch, value });
    } finally {
      if (scope.isCurrent(epoch)) setRefreshing(null);
    }
  }
  return (
    <section aria-label="Utrwalone dopasowania IOC" className="intelligence-event-links">
      <div className="intro">
        <h3>Utrwalone dopasowania IOC</h3>
        <button
          disabled={resource.pending || refreshing === scope.epoch}
          onClick={() => void refresh()}
        >
          Odśwież dopasowania IOC
        </button>
      </div>
      <p className="muted">
        Reputacja i pewność pochodzą z zachowanej deklaracji źródła. Dopasowanie nie potwierdza
        ataku. Odczyt nie analizuje zdarzenia ponownie.
      </p>
      {scope.expired && (
        <ErrorNotice
          error={
            new Error('Sesja zmieniła się. Odśwież dopasowania po sprawdzeniu bieżącego konta.')
          }
        />
      )}
      <IntelligenceFailure
        error={resource.error ?? (error?.epoch === scope.epoch ? error.value : null)}
      />
      {resource.pending && <Loading />}
      {resource.data && (
        <>
          {resource.data.status === 'pending' ? (
            <p className="notice">
              Dopasowania jeszcze nie zostały utrwalone. Brak wyniku nie oznacza braku wskaźników;
              odświeżenie tylko odczytuje stan analizy.
            </p>
          ) : (
            <>
              <p>
                Zachowane dopasowania: {resource.data.match_count}. Analiza:{' '}
                {time(resource.data.evaluated_at)}.
              </p>
              {resource.data.matches.length ? (
                <ol className="intelligence-history">
                  {resource.data.matches.map((match) => (
                    <li key={match.id}>
                      <strong>
                        {iocTypes[match.revision_snapshot.type]} · {match.field}
                      </strong>
                      <p className="ioc-value mono">Wartość z dowodu: {match.observed_value}</p>
                      <p className="ioc-value mono">Wartość kanoniczna: {match.canonical_value}</p>
                      <Badge tone={reputationTone[match.revision_snapshot.reputation]}>
                        {reputations[match.revision_snapshot.reputation]}
                      </Badge>
                      <dl className="facts">
                        <dt>Źródło zachowanej deklaracji</dt>
                        <dd>{match.revision_snapshot.source}</dd>
                        <dt>Pewność deklarowana w rewizji</dt>
                        <dd>
                          {match.revision_snapshot.confidence === null
                            ? 'Nieznana'
                            : `${match.revision_snapshot.confidence}/100`}
                        </dd>
                        <dt>Zachowana rewizja IOC</dt>
                        <dd>{match.revision_snapshot.revision}</dd>
                      </dl>
                      <details>
                        <summary>Pochodzenie dopasowania {match.field}</summary>
                        <dl className="facts">
                          <dt>IOC ID</dt>
                          <dd className="mono">{match.ioc_id}</dd>
                          <dt>Revision ID</dt>
                          <dd className="mono">{match.revision_id}</dd>
                          <dt>SHA-256 rewizji</dt>
                          <dd className="mono">{match.revision_snapshot_sha256}</dd>
                        </dl>
                        <JsonView value={match.revision_snapshot} />
                      </details>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="muted">
                  Nie dopasowano aktywnych IOC z katalogu użytego podczas analizy. To nie potwierdza
                  bezpieczeństwa zdarzenia.
                </p>
              )}
            </>
          )}
          <details>
            <summary>Pochodzenie analizy IOC</summary>
            <dl className="facts">
              <dt>SHA-256 znormalizowanego zdarzenia</dt>
              <dd className="mono">{resource.data.document_sha256}</dd>
              <dt>Wersja analizy</dt>
              <dd>{resource.data.evaluator_version}</dd>
              <dt>Zasady normalizacji IOC</dt>
              <dd>{resource.data.normalization_version}</dd>
            </dl>
          </details>
        </>
      )}
    </section>
  );
}
