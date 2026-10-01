import { time, statusName, useResource } from './utilities';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from './components';
import type { SearchInput, SearchResult, SecurityEvent } from './types';

function localInput(date: Date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
export function Events({
  initialQuery,
  onEvent,
}: {
  initialQuery: string;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [search, setSearch] = useState<SearchInput>(() => ({
    q: initialQuery,
    limit: 50,
    from: new Date(Date.now() - 86400000).toISOString(),
    to: new Date().toISOString(),
  }));
  const [formError, setFormError] = useState<unknown>(null);
  const [cursorStack, setCursorStack] = useState<(string | undefined)[]>([]);
  const loader = useCallback(() => api.post<SearchResult>('/events/search', search), [search]);
  const resource = useResource(loader);
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const from = new Date(String(fields.get('from')));
    const to = new Date(String(fields.get('to')));
    if (
      Number.isNaN(from.getTime()) ||
      Number.isNaN(to.getTime()) ||
      from >= to ||
      to.getTime() - from.getTime() > 7 * 86400000
    ) {
      setFormError(new Error('Wybierz poprawny zakres czasu, maksymalnie 7 dni.'));
      return;
    }
    setFormError(null);
    setCursorStack([]);
    setSearch({
      q: String(fields.get('q')),
      from: from.toISOString(),
      to: to.toISOString(),
      limit: 50,
      ...(fields.get('mode') ? { mode: String(fields.get('mode')) } : {}),
    });
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Event Explorer</h2>
          <p>Przeszukuj znormalizowane logi i sprawdzaj oryginalne dowody.</p>
        </div>
      </div>
      <Panel title="Wyszukiwanie zdarzeń">
        <form className="search-form" onSubmit={submit}>
          <label className="query-label">
            Zapytanie
            <input
              name="q"
              defaultValue={initialQuery}
              key={initialQuery}
              placeholder={'np. result = "failed" AND source_type = "linux_auth"'}
              maxLength={4096}
            />
          </label>
          <div className="form-row">
            <label>
              Od · czas lokalny
              <input
                type="datetime-local"
                name="from"
                required
                defaultValue={localInput(new Date(search.from!))}
              />
            </label>
            <label>
              Do · czas lokalny
              <input
                type="datetime-local"
                name="to"
                required
                defaultValue={localInput(new Date(search.to!))}
              />
            </label>
            <label>
              Tryb
              <select name="mode">
                <option value="">Wszystkie</option>
                <option value="live">Live</option>
                <option value="replay">Replay</option>
              </select>
            </label>
            <button className="primary" disabled={resource.pending}>
              Szukaj
            </button>
          </div>
        </form>
        <details className="query-help">
          <summary>Jak zbudować zapytanie</summary>
          <p>
            Użyj =, !=, &gt;, &lt; oraz AND/OR i nawiasów. Tekst ujmij w podwójne cudzysłowy;
            CONTAINS dopasowuje fragment. Przykłady: <code>process_name CONTAINS "powershell"</code>
            , <code>user.target.name = "alice"</code> dla konta logowania Windows. Maksymalny
            zakres: 7 dni.
          </p>
        </details>
        <ErrorNotice error={formError} />
      </Panel>
      <Panel
        title="Wyniki"
        aside={
          <span className="muted">
            {resource.data && !resource.error
              ? `${resource.data.total.toLocaleString('pl-PL')} w całym zakresie`
              : '—'}
          </span>
        }
      >
        <ErrorNotice error={resource.error} />
        {resource.pending && <Loading />}
        {resource.data &&
          !resource.error &&
          (resource.data.items.length ? (
            <>
              <div className="table-wrap" aria-busy={resource.pending}>
                <table>
                  <thead>
                    <tr>
                      <th>Czas zdarzenia</th>
                      <th>Akcja / źródło</th>
                      <th>Użytkownik / host</th>
                      <th>IP źródłowe</th>
                      <th>Wynik</th>
                      <th>
                        <span className="sr-only">Szczegóły</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {resource.data.items.map((item) => (
                      <tr key={item.event_id}>
                        <td className="nowrap">{time(item.timestamp)}</td>
                        <td>
                          <strong>{item.event.action}</strong>
                          <small>
                            {item.source.name} · {item.source.type}
                          </small>
                        </td>
                        <td>
                          {item.user.target.name ?? item.user.name ?? '—'}
                          <small>{item.host.name ?? '—'}</small>
                        </td>
                        <td className="mono">{item.source.ip ?? '—'}</td>
                        <td>
                          <Badge tone={item.event.outcome}>
                            {statusName[item.event.outcome] ?? item.event.outcome}
                          </Badge>
                        </td>
                        <td>
                          <button className="quiet" onClick={() => onEvent(item)}>
                            Szczegóły
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="pagination">
                <span>
                  Strona {cursorStack.length + 1} · {resource.data.items.length} rekordów
                </span>
                <div>
                  <button
                    disabled={resource.pending || !cursorStack.length}
                    onClick={() => {
                      const cursor = cursorStack.at(-1);
                      setCursorStack((stack) => stack.slice(0, -1));
                      setSearch((value) => ({ ...value, cursor }));
                    }}
                  >
                    Poprzednia
                  </button>
                  <button
                    disabled={resource.pending || !resource.data.next_cursor}
                    onClick={() => {
                      setCursorStack((stack) => [...stack, search.cursor]);
                      setSearch((value) => ({ ...value, cursor: resource.data!.next_cursor! }));
                    }}
                  >
                    Następna
                  </button>
                </div>
              </div>
            </>
          ) : (
            <Empty title="Nie znaleziono zdarzeń">
              Zmień zapytanie lub zakres czasu. Nowe logi pojawiają się po zakończeniu archiwizacji.
            </Empty>
          ))}
      </Panel>
    </>
  );
}

export function EventDetail({
  event,
  onClose,
  onFilter,
}: {
  event: SecurityEvent;
  onClose: () => void;
  onFilter: (field: string, value: string) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => {
      element?.close();
    };
  }, []);
  return (
    <dialog
      ref={dialog}
      className="detail-dialog"
      onCancel={(action) => {
        action.preventDefault();
        onClose();
      }}
      aria-labelledby="event-title"
    >
      <header className="detail-header">
        <div>
          <span className="eyebrow">DOWÓD ZDARZENIA</span>
          <h2 id="event-title">{event.event.action}</h2>
        </div>
        <button onClick={onClose} aria-label="Zamknij szczegóły">
          ✕
        </button>
      </header>
      <div className="detail-body">
        <div className="detail-badges">
          <Badge tone={event.event.outcome}>{statusName[event.event.outcome]}</Badge>
          <Badge>{event.source.type}</Badge>
          <Badge>{event.mode}</Badge>
        </div>
        <dl className="facts">
          <dt>Czas zdarzenia</dt>
          <dd>{time(event.timestamp)}</dd>
          <dt>Przyjęto</dt>
          <dd>{time(event.received_at)}</dd>
          <dt>Przetworzono</dt>
          <dd>{time(event.processed_at)}</dd>
          <dt>Źródło</dt>
          <dd>{event.source.name}</dd>
          <dt>Kategoria</dt>
          <dd>{event.event.category}</dd>
          <dt>Wykonawca</dt>
          <dd>
            {event.user.name ? (
              <button
                className="inline-link"
                onClick={() => onFilter('user.name', event.user.name!)}
              >
                {event.user.realm ? `${event.user.realm}\\` : ''}
                {event.user.name}
              </button>
            ) : (
              '—'
            )}
          </dd>
          <dt>Konto docelowe</dt>
          <dd>
            {event.user.target.name ? (
              <button
                className="inline-link"
                onClick={() => onFilter('user.target.name', event.user.target.name!)}
              >
                {event.user.target.name}
              </button>
            ) : (
              '—'
            )}
          </dd>
          <dt>Host</dt>
          <dd>
            {event.host.name ? (
              <button
                className="inline-link"
                onClick={() => onFilter('host.name', event.host.name!)}
              >
                {event.host.name}
              </button>
            ) : (
              '—'
            )}
          </dd>
          <dt>IP źródłowe</dt>
          <dd>
            {event.source.ip ? (
              <button
                className="inline-link mono"
                onClick={() => onFilter('source.ip', event.source.ip!)}
              >
                {event.source.ip}
              </button>
            ) : (
              '—'
            )}
          </dd>
          <dt>Proces</dt>
          <dd>{event.process.executable ?? '—'}</dd>
        </dl>
        {event.quality.length > 0 && (
          <div className="notice">
            <strong>Jakość danych</strong>
            <p>
              {event.quality.includes('timestamp_from_received_at')
                ? 'Brak czasu źródłowego: czas zdarzenia pochodzi z obserwacji przez serwer.'
                : 'Parser oznaczył pochodzenie lub niepełność danych.'}
            </p>
            <div className="detail-badges">
              {event.quality.map((flag) => (
                <Badge key={flag}>{flag}</Badge>
              ))}
            </div>
          </div>
        )}
        {event.process.command_line && (
          <>
            <h3>Polecenie procesu</h3>
            <JsonView value={event.process.command_line} />
          </>
        )}
        <h3>Oryginalny log</h3>
        <JsonView value={event.raw_event} />
        <details>
          <summary>Pełny rekord i pochodzenie</summary>
          <dl className="facts">
            <dt>Event ID</dt>
            <dd className="mono">{event.event_id}</dd>
            <dt>Source ID</dt>
            <dd className="mono">{event.source_id}</dd>
            <dt>Dataset ID</dt>
            <dd className="mono">{event.dataset_id}</dd>
            <dt>Run ID</dt>
            <dd className="mono">{event.run_id}</dd>
            <dt>Wersja schematu / parsera</dt>
            <dd>
              {event.schema_version} / {event.parser_version}
            </dd>
            <dt>SHA-256 envelope</dt>
            <dd className="mono">{event.raw_sha256}</dd>
          </dl>
          <JsonView value={event} />
        </details>
      </div>
    </dialog>
  );
}
