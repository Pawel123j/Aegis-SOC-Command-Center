import { useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Loading, Panel } from '../components';
import type { Me } from '../types';
import { time } from '../utilities';
import { IntelligenceFailure } from './IntelligenceFailure';
import { IntelligenceBackfill } from './IntelligenceBackfill';
import { IocDetails } from './IocDetails';
import { IocEditor } from './IocEditor';
import { IocImport } from './IocImport';
import { IocLookup } from './IocLookup';
import { iocTypes, reputations, reputationTone } from './labels';
import type { IntelligenceProviders, IocPage } from './types';
import { useIntelligenceResource } from './useIntelligenceResource';
import { useIntelligenceScope } from './useIntelligenceScope';
import './intelligence.css';

export function Intelligence({ user }: { user: Me }) {
  if (!user.permissions.includes('intelligence:read'))
    return (
      <Empty title="Katalog IOC jest niedostępny">
        Twoja rola nie pozwala na odczyt wskaźników zagrożeń.
      </Empty>
    );
  return (
    <IntelligenceWorkspace
      key={`${user.id}/${user.role}/${[...user.permissions].sort().join(',')}`}
      user={user}
    />
  );
}

function IntelligenceWorkspace({ user }: { user: Me }) {
  const scope = useIntelligenceScope();
  const [filter, setFilter] = useState({
    q: '',
    kind: '',
    reputation: '',
    active: '',
    limit: '25',
  });
  const [params, setParams] = useState('limit=25');
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<(string | null)[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [editor, setEditor] = useState<'add' | 'import' | null>(null);
  const [refreshingEpoch, setRefreshingEpoch] = useState<number | null>(null);
  const [error, setError] = useState<{ epoch: number; value: unknown } | null>(null);
  const [notice, setNotice] = useState<{ epoch: number; value: string } | null>(null);
  const query = new URLSearchParams(params);
  if (cursor) query.set('cursor', cursor);
  const list = useIntelligenceResource<IocPage>(`/intelligence/iocs?${query}`, scope);
  const providers = useIntelligenceResource<IntelligenceProviders>(
    '/intelligence/providers',
    scope,
  );
  const manage = user.permissions.includes('intelligence:manage');
  async function refresh() {
    if (refreshingEpoch === scope.epoch) return;
    if (scope.expired) {
      const epoch = scope.capture();
      setRefreshingEpoch(epoch);
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
            'Konto lub uprawnienia zmieniły się. Otwórz katalog z menu bieżącej sesji.',
          );
        scope.resume();
      } catch (value) {
        if (scope.isCurrent(epoch)) setError({ epoch, value });
      } finally {
        if (scope.isCurrent(epoch)) setRefreshingEpoch(null);
      }
      return;
    }
    setError(null);
    setNotice(null);
    setCursor(null);
    setPrevious([]);
    if (!cursor) list.reload();
    providers.reload();
  }
  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (scope.expired) return;
    const next = new URLSearchParams({ limit: filter.limit });
    if (filter.q.trim()) next.set('q', filter.q.trim());
    for (const field of ['kind', 'reputation', 'active'] as const)
      if (filter[field]) next.set(field, filter[field]);
    setParams(next.toString());
    setCursor(null);
    setPrevious([]);
    setSelected(null);
  }
  function catalogChanged() {
    setCursor(null);
    setPrevious([]);
    if (!cursor) list.reload();
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Wskaźniki zagrożeń</h2>
          <p>Lokalny katalog adresów, domen, URL i hashy plików.</p>
        </div>
        <div className="button-row">
          {manage && (
            <>
              <button
                className="primary"
                disabled={scope.expired || editor !== null}
                onClick={() => {
                  setSelected(null);
                  setEditor('add');
                }}
              >
                Dodaj IOC
              </button>
              <button
                disabled={scope.expired || editor !== null}
                onClick={() => {
                  setSelected(null);
                  setEditor('import');
                }}
              >
                Importuj IOC
              </button>
            </>
          )}
          <button
            disabled={refreshingEpoch === scope.epoch || list.pending || providers.pending}
            onClick={() => void refresh()}
          >
            Odśwież katalog IOC
          </button>
        </div>
      </div>
      <p className="notice">
        IOC jest deklaracją źródła o konkretnym wskaźniku. Dopasowanie nie potwierdza ataku. Katalog
        nie otwiera adresów URL i nie odpytuje zewnętrznych usług.
      </p>
      {scope.expired && (
        <ErrorNotice
          error={
            new Error('Sesja zmieniła się. Odśwież katalog IOC po sprawdzeniu bieżącego konta.')
          }
        />
      )}
      <IntelligenceFailure error={error?.epoch === scope.epoch ? error.value : null} />
      {notice?.epoch === scope.epoch && !scope.expired && (
        <p className="notice" role="status">
          {notice.value}
        </p>
      )}
      <details>
        <summary>Dostawcy danych Threat Intelligence</summary>
        <IntelligenceFailure error={providers.error} />
        {providers.pending && <Loading />}
        {providers.data?.items.map((provider) => (
          <div key={provider.id}>
            <strong>{provider.kind === 'local' ? 'Lokalny katalog IOC' : provider.name}</strong>
            <p>{provider.description}</p>
            <p>
              {provider.enabled ? 'Włączony' : 'Wyłączony'} ·{' '}
              {provider.network_access === false
                ? 'Bez połączeń zewnętrznych'
                : 'Sprawdź ustawienia dostawcy'}
            </p>
          </div>
        ))}
      </details>
      {user.permissions.includes('system:manage') && <IntelligenceBackfill scope={scope} />}
      {editor === 'add' && (
        <IocEditor
          scope={scope}
          onClose={() => setEditor(null)}
          onSaved={(item) => {
            setEditor(null);
            setSelected(item.id);
            catalogChanged();
            setNotice({
              epoch: scope.epoch,
              value: `Zachowano IOC. Bieżąca rewizja: ${item.revision}.`,
            });
          }}
        />
      )}
      {editor === 'import' && (
        <IocImport
          scope={scope}
          onClose={() => setEditor(null)}
          onSaved={(result) => {
            setEditor(null);
            catalogChanged();
            setNotice({
              epoch: scope.epoch,
              value: `Partia przyjęta: ${result.created} nowych IOC; ${result.unchanged} bez zmian.`,
            });
          }}
        />
      )}
      {selected ? (
        <IocDetails
          key={selected}
          id={selected}
          user={user}
          scope={scope}
          onBack={() => setSelected(null)}
          onChanged={catalogChanged}
        />
      ) : (
        <>
          <IocLookup key={scope.epoch} scope={scope} onSelect={setSelected} />
          <Panel title="Filtry katalogu IOC">
            <form onSubmit={apply}>
              <fieldset disabled={scope.expired}>
                <div className="form-row intelligence-filters">
                  <label>
                    Szukaj wartości lub źródła
                    <input
                      value={filter.q}
                      maxLength={128}
                      onChange={(event) =>
                        setFilter((value) => ({ ...value, q: event.target.value }))
                      }
                    />
                  </label>
                  <label>
                    Rodzaj wskaźnika
                    <select
                      value={filter.kind}
                      onChange={(event) =>
                        setFilter((value) => ({ ...value, kind: event.target.value }))
                      }
                    >
                      <option value="">Wszystkie rodzaje</option>
                      {Object.entries(iocTypes).map(([value, label]) => (
                        <option key={value} value={value}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Reputacja w katalogu
                    <select
                      value={filter.reputation}
                      onChange={(event) =>
                        setFilter((value) => ({ ...value, reputation: event.target.value }))
                      }
                    >
                      <option value="">Wszystkie deklaracje</option>
                      {Object.entries(reputations).map(([value, label]) => (
                        <option key={value} value={value}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Stan wskaźnika
                    <select
                      value={filter.active}
                      onChange={(event) =>
                        setFilter((value) => ({ ...value, active: event.target.value }))
                      }
                    >
                      <option value="">Aktywne i wyłączone</option>
                      <option value="true">Aktywne</option>
                      <option value="false">Wyłączone</option>
                    </select>
                  </label>
                  <label>
                    IOC na stronę
                    <select
                      value={filter.limit}
                      onChange={(event) =>
                        setFilter((value) => ({ ...value, limit: event.target.value }))
                      }
                    >
                      {[25, 50, 100].map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button className="primary">Zastosuj filtry IOC</button>
                </div>
              </fieldset>
            </form>
          </Panel>
          <Panel title="Katalog IOC">
            <IntelligenceFailure error={list.error} />
            {list.pending && <Loading />}
            {list.data && (
              <>
                <p>
                  Wskaźniki w zakresie: {list.data.total}. Limit katalogu:{' '}
                  {list.data.limits.max_iocs}; rewizji na IOC: {list.data.limits.max_revisions}.
                </p>
                {list.data.items.length ? (
                  <div className="table-wrap">
                    <table aria-label="Wskaźniki IOC">
                      <thead>
                        <tr>
                          <th>Wskaźnik / typ</th>
                          <th>Reputacja / stan</th>
                          <th>Źródło / deklarowana pewność</th>
                          <th>Rewizja / zmiana</th>
                        </tr>
                      </thead>
                      <tbody>
                        {list.data.items.map((item) => (
                          <tr key={item.id}>
                            <th scope="row">
                              <button
                                className="inline-link ioc-value mono"
                                disabled={scope.expired}
                                onClick={() => {
                                  setSelected(item.id);
                                  setEditor(null);
                                }}
                              >
                                {item.value}
                              </button>
                              <small>{iocTypes[item.type]}</small>
                            </th>
                            <td>
                              <Badge tone={reputationTone[item.reputation]}>
                                {reputations[item.reputation]}
                              </Badge>
                              <small>{item.active ? 'Aktywny' : 'Wyłączony'}</small>
                            </td>
                            <td>
                              {item.source}
                              <small>
                                {item.confidence === null
                                  ? 'Pewność nieznana'
                                  : `Deklaracja źródła: ${item.confidence}/100`}
                              </small>
                            </td>
                            <td>
                              {item.revision}
                              <small>{time(item.updated_at)}</small>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty title="Brak wskaźników w tym zakresie">
                    Zmień filtry lub uzupełnij lokalny katalog. Pusty wynik nie potwierdza
                    bezpieczeństwa środowiska.
                  </Empty>
                )}
                <div className="pagination">
                  <span>Strona IOC {previous.length + 1}</span>
                  <div>
                    <button
                      disabled={!previous.length || list.pending || scope.expired}
                      onClick={() => {
                        setCursor(previous.at(-1) ?? null);
                        setPrevious((value) => value.slice(0, -1));
                      }}
                    >
                      Poprzednie IOC
                    </button>
                    <button
                      disabled={!list.data.next_cursor || list.pending || scope.expired}
                      onClick={() => {
                        setPrevious((value) => [...value, cursor]);
                        setCursor(list.data!.next_cursor);
                      }}
                    >
                      Następne IOC
                    </button>
                  </div>
                </div>
              </>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
