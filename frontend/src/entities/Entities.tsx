import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api';
import { Empty, ErrorNotice, Loading, Panel } from '../components';
import type { Alert, Me, SecurityEvent } from '../types';
import { EntityProfile } from './EntityProfile';
import { EntityTable, IndexNotice, ScopeNotice } from './presentation';
import { entityParams, initialEntityFilter, profileFilterForEvent } from './filters';
import type { EntityFilter } from './filters';
import { canReadEntities } from './permissions';
import type { BackfillResult, EntityPage, EntitySummary } from './types';
import { useEntityResource } from './useEntityResource';
import './entities.css';

export interface InitialEntityProfile {
  id: string;
  event: SecurityEvent;
}
export function Entities({
  user,
  initialProfile,
  onEvent,
  onCreateIncident,
}: {
  user: Me;
  initialProfile?: InitialEntityProfile | null;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
}) {
  if (!canReadEntities(user)) {
    return (
      <Empty title="Profile są niedostępne">
        Wymagają dostępu do zdarzeń, alertów i incydentów.
      </Empty>
    );
  }
  return (
    <EntityWorkspace
      key={`${user.id}/${user.role}/${[...user.permissions].sort().join(',')}/${initialProfile?.id ?? ''}/${initialProfile?.event.event_id ?? ''}`}
      user={user}
      initialProfile={initialProfile}
      onEvent={onEvent}
      onCreateIncident={onCreateIncident}
    />
  );
}

function EntityWorkspace({
  user,
  initialProfile,
  onEvent,
  onCreateIncident,
}: {
  user: Me;
  initialProfile?: InitialEntityProfile | null;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
}) {
  const [filter, setFilter] = useState<EntityFilter>(() =>
    initialProfile ? profileFilterForEvent(initialProfile.event) : initialEntityFilter(),
  );
  const [applied, setApplied] = useState(filter);
  const [params, setParams] = useState(() => entityParams(filter));
  const [selected, setSelected] = useState<string | null>(initialProfile?.id ?? null);
  const [formError, setFormError] = useState<unknown>(null);
  function field<K extends keyof EntityFilter>(name: K, value: EntityFilter[K]) {
    setFilter((current) => ({ ...current, [name]: value }));
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const next = entityParams(filter);
      setFormError(null);
      setApplied({ ...filter });
      setParams(next);
      setSelected(null);
    } catch (failure) {
      setFormError(failure);
    }
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Profile obserwowanych encji</h2>
          <p>Hosty, konta, adresy IP i procesy powiązane ze zdarzeniami.</p>
        </div>
      </div>
      <p className="notice">
        Profile opisują dane zaobserwowane w logach. Nazwa lub adres nie potwierdzają tożsamości
        osoby, właściciela urządzenia ani wpisu w ewidencji zasobów.
      </p>
      <Panel title="Zakres profili">
        <form onSubmit={submit}>
          <div className="form-row entity-filters">
            <label>
              Typ encji
              <select
                value={filter.kind}
                onChange={(event) => field('kind', event.target.value as EntityFilter['kind'])}
              >
                <option value="">Wszystkie typy</option>
                <option value="user">Konta</option>
                <option value="host">Hosty</option>
                <option value="ip">Adresy IP</option>
                <option value="process">Procesy</option>
              </select>
            </label>
            <label>
              Nazwa lub adres
              <input
                value={filter.q}
                maxLength={128}
                onChange={(event) => field('q', event.target.value)}
                placeholder="Fragment etykiety"
              />
            </label>
            <label>
              Tryb profili
              <select
                value={filter.mode}
                onChange={(event) => field('mode', event.target.value as 'live' | 'replay')}
              >
                <option value="live">Live</option>
                <option value="replay">Replay</option>
              </select>
            </label>
          </div>
          <div className="form-row entity-filters">
            <label>
              Od · czas lokalny
              <input
                type="datetime-local"
                step="0.001"
                required
                value={filter.from}
                onChange={(event) => field('from', event.target.value)}
              />
            </label>
            <label>
              Do · czas lokalny
              <input
                type="datetime-local"
                step="0.001"
                required
                value={filter.to}
                onChange={(event) => field('to', event.target.value)}
              />
            </label>
            <label>
              Profile na stronę
              <select
                value={filter.limit}
                onChange={(event) => field('limit', Number(event.target.value))}
              >
                {[25, 50, 100].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {filter.mode === 'replay' && (
            <div className="form-row entity-filters">
              <label>
                Dataset ID replay
                <input
                  required
                  maxLength={36}
                  value={filter.dataset_id}
                  onChange={(event) => field('dataset_id', event.target.value)}
                />
              </label>
              <label>
                Run ID replay
                <input
                  required
                  maxLength={36}
                  value={filter.run_id}
                  onChange={(event) => field('run_id', event.target.value)}
                />
              </label>
            </div>
          )}
          <div className="button-row">
            <button className="primary">Zastosuj zakres profili</button>
          </div>
          <p className="muted">
            Domyślnie ostatnie 30 dni, maksymalnie 366 dni. Liczy się czas każdego zdarzenia
            tworzącego dowód alertu: od początku włącznie do końca wyłącznie. Replay obejmuje jeden
            zestaw i jedną sesję.
          </p>
          <ErrorNotice error={formError} />
        </form>
      </Panel>
      {selected ? (
        <EntityProfile
          key={`${selected}/${params}`}
          id={selected}
          params={entityParams(applied, false)}
          user={user}
          onBack={() => setSelected(null)}
          onSelect={setSelected}
          onEvent={onEvent}
          onCreateIncident={onCreateIncident}
        />
      ) : (
        <EntityList key={params} params={params} user={user} onSelect={setSelected} />
      )}
    </>
  );
}

function EntityList({
  params,
  user,
  onSelect,
}: {
  params: string;
  user: Me;
  onSelect: (id: string) => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<(string | null)[]>([]);
  const query = new URLSearchParams(params);
  if (cursor) query.set('cursor', cursor);
  const resource = useEntityResource<EntityPage<EntitySummary>>(`/entities?${query}`);
  return (
    <Panel
      title="Lista profili"
      aside={
        <button disabled={resource.pending} onClick={() => void resource.reload()}>
          Odśwież profile
        </button>
      }
    >
      <div aria-busy={resource.pending} aria-live="polite">
        <ErrorNotice error={resource.error} />
        {resource.pending && <Loading />}
        <BackfillControl
          user={user}
          incomplete={resource.data ? !resource.data.index_status.complete : false}
          onChanged={() => {
            setCursor(null);
            setPrevious([]);
            if (!cursor) void resource.reload();
          }}
        />
        {resource.data && (
          <>
            <ScopeNotice scope={resource.data.scope} />
            <IndexNotice status={resource.data.index_status} />
            <p className="muted">
              Profile w zakresie: {resource.data.total}. Liczniki obejmują wszystkie pasujące
              rekordy, także na kolejnych stronach.
            </p>
            {resource.data.items.length ? (
              <EntityTable items={resource.data.items} onSelect={onSelect} />
            ) : (
              <Empty
                title={
                  resource.data.index_status.complete
                    ? 'Brak profili w wybranym zakresie'
                    : 'Profile oczekują na indeksowanie'
                }
              >
                {resource.data.index_status.complete
                  ? 'Zmień filtry lub prześlij logi. Pusty wynik nie potwierdza bezpieczeństwa środowiska.'
                  : 'Wynik jest niepełny. Administrator może uzupełnić indeks i odświeżyć widok.'}
              </Empty>
            )}
            <div className="pagination">
              <span>Strona {previous.length + 1}</span>
              <div>
                <button
                  disabled={!previous.length || resource.pending}
                  onClick={() => {
                    setCursor(previous.at(-1) ?? null);
                    setPrevious((items) => items.slice(0, -1));
                  }}
                >
                  Poprzednie profile
                </button>
                <button
                  disabled={!resource.data.next_cursor || resource.pending}
                  onClick={() => {
                    setPrevious((items) => [...items, cursor]);
                    setCursor(resource.data!.next_cursor);
                  }}
                >
                  Następne profile
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

function BackfillControl({
  user,
  incomplete,
  onChanged,
}: {
  user: Me;
  incomplete: boolean;
  onChanged: () => void;
}) {
  const [limit, setLimit] = useState(25);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<BackfillResult | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [authorityChanged, setAuthorityChanged] = useState(false);
  const revision = useRef(0);
  const blocked = useRef(false);
  useEffect(() => {
    const counter = revision;
    const authorityBlocked = blocked;
    const unsubscribe = api.subscribe(() => {
      counter.current++;
      authorityBlocked.current = true;
      setResult(null);
      setPending(false);
      setAuthorityChanged(true);
      setError(new Error('Sesja zmieniła się. Odśwież profile po sprawdzeniu bieżącego konta.'));
    });
    return () => {
      counter.current++;
      unsubscribe();
    };
  }, []);
  async function backfill() {
    if (pending || blocked.current) return;
    const generation = ++revision.current;
    setPending(true);
    setError(null);
    try {
      const next = await api.post<BackfillResult>('/entities/backfill', { limit });
      if (revision.current === generation) {
        setResult(next);
        onChanged();
      }
    } catch (failure) {
      if (revision.current === generation) setError(failure);
    } finally {
      if (revision.current === generation) setPending(false);
    }
  }
  if (!user.permissions.includes('system:manage') || (!incomplete && !result)) return null;
  return (
    <div className="entity-backfill">
      <p>
        Uzupełnij indeks istniejących dowodów jedną ograniczoną partią. Operacja nie przelicza
        ryzyka i nie uruchamia reguł ponownie. Partia obejmuje zaległe dowody całego systemu,
        również poza wybranymi filtrami.
      </p>
      <div className="button-row">
        <label>
          Limit partii indeksu
          <select
            value={limit}
            disabled={pending}
            onChange={(event) => setLimit(Number(event.target.value))}
          >
            {[25, 50, 100].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={pending || !incomplete || authorityChanged}
          onClick={() => void backfill()}
        >
          {pending ? 'Uzupełnianie indeksu…' : 'Uzupełnij indeks'}
        </button>
      </div>
      <ErrorNotice error={error} />
      {result && (
        <p role="status">
          Partia: {result.events} zdarzeń, {result.alerts} alertów, {result.observations}{' '}
          obserwacji. Odświeżony wynik dotyczy wybranego zakresu; partia obejmuje zaległe dowody
          całego systemu. Pozostało w całym systemie: {result.index_status.pending_events} zdarzeń i{' '}
          {result.index_status.pending_alerts} alertów.
        </p>
      )}
    </div>
  );
}
