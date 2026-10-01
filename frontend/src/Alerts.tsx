import { time, statusName, useResource } from './utilities';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from './components';
import type { Alert, AlertDetail, Json, Me, Page, Rule, SecurityEvent } from './types';

export function Alerts({
  user,
  onEvent,
  onCreateIncident,
}: {
  user: Me;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
}) {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<(string | null)[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const loader = useCallback(
    () =>
      api.get<Page<Alert>>(
        `/alerts?${new URLSearchParams({ limit: '50', ...(status ? { status } : {}), ...(severity ? { severity } : {}), ...(cursor ? { cursor } : {}) })}`,
      ),
    [status, severity, cursor],
  );
  const resource = useResource(loader);
  return (
    <>
      <div className="intro">
        <div>
          <h2>Alerty do analizy</h2>
          <p>Reguła, zaobserwowane pola i zachowany dowód dla każdego dopasowania.</p>
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
      <Panel
        title="Lista alertów"
        aside={<span className="muted">{resource.data?.total ?? '—'} w zakresie filtrów</span>}
      >
        <div className="form-row">
          <label>
            Status
            <select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value);
                setCursor(null);
                setPrevious([]);
              }}
            >
              <option value="">Wszystkie</option>
              {['new', 'acknowledged', 'false_positive', 'resolved'].map((value) => (
                <option key={value} value={value}>
                  {statusName[value]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Waga
            <select
              value={severity}
              onChange={(event) => {
                setSeverity(event.target.value);
                setCursor(null);
                setPrevious([]);
              }}
            >
              <option value="">Wszystkie</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
        </div>
        <ErrorNotice error={resource.error} />
        {resource.pending && <Loading />}
        {resource.data &&
          !resource.error &&
          (resource.data.items.length ? (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Alert / reguła</th>
                      <th>Waga</th>
                      <th>Status</th>
                      <th>Czas zdarzenia</th>
                      <th>Wykryto</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {resource.data.items.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <strong>{item.title}</strong>
                          <small>
                            {item.rule_id} · {item.rule_version}
                          </small>
                        </td>
                        <td>
                          <Badge tone={item.severity}>{item.severity}</Badge>
                        </td>
                        <td>
                          <Badge>{statusName[item.status]}</Badge>
                        </td>
                        <td className="nowrap">{time(item.event_timestamp)}</td>
                        <td className="nowrap">{time(item.created_at)}</td>
                        <td>
                          <button className="quiet" onClick={() => setSelected(item.id)}>
                            Analizuj
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
                    Poprzednia
                  </button>
                  <button
                    disabled={!resource.data.next_cursor || resource.pending}
                    onClick={() => {
                      setPrevious((items) => [...items, cursor]);
                      setCursor(resource.data!.next_cursor);
                    }}
                  >
                    Następna
                  </button>
                </div>
              </div>
            </>
          ) : (
            <Empty title="Brak alertów w tym zakresie">
              Zmień filtry lub sprawdź aktywne reguły. Alerty powstają dopiero z dopasowanych
              zdarzeń.
            </Empty>
          ))}
      </Panel>
      {selected && (
        <AlertDialog
          id={selected}
          user={user}
          onClose={() => setSelected(null)}
          onEvent={onEvent}
          onCreateIncident={onCreateIncident}
          onChange={() => {
            void resource.reload();
          }}
        />
      )}
    </>
  );
}
function AlertDialog({
  id,
  user,
  onClose,
  onEvent,
  onChange,
  onCreateIncident,
}: {
  id: string;
  user: Me;
  onClose: () => void;
  onEvent: (event: SecurityEvent) => void;
  onChange: () => void;
  onCreateIncident: (alert: Alert) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => {
      element?.close();
    };
  }, []);
  const loader = useCallback(() => api.get<AlertDetail>(`/alerts/${id}`), [id]);
  const resource = useResource(loader);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function change(status: string) {
    if (!resource.data) return;
    setPending(true);
    setError(null);
    try {
      await api.patch(`/alerts/${id}`, { status }, resource.data.version);
      await resource.reload();
      onChange();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <dialog
      className="detail-dialog"
      ref={dialog}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      aria-labelledby="alert-title"
    >
      <header className="detail-header">
        <div>
          <span className="eyebrow">ANALIZA ALERTU</span>
          <h2 id="alert-title">{resource.data?.title ?? 'Szczegóły alertu'}</h2>
        </div>
        <button onClick={onClose} aria-label="Zamknij alert">
          ✕
        </button>
      </header>
      <div className="detail-body">
        <ErrorNotice error={resource.error ?? error} />
        {resource.pending && <Loading />}
        {resource.data && (
          <>
            <div className="detail-badges">
              <Badge tone={resource.data.severity}>{resource.data.severity}</Badge>
              <Badge>{statusName[resource.data.status]}</Badge>
              <Badge>{resource.data.mode}</Badge>
            </div>
            <dl className="facts">
              <dt>Czas zdarzenia</dt>
              <dd>{time(resource.data.event_timestamp)}</dd>
              <dt>Wykryto</dt>
              <dd>{time(resource.data.created_at)}</dd>
              <dt>Reguła / wersja</dt>
              <dd>
                {resource.data.rule_id} / {resource.data.rule_version}
              </dd>
              <dt>Potwierdzono</dt>
              <dd>{time(resource.data.acknowledged_at)}</dd>
              <dt>Ocena ryzyka</dt>
              <dd>Niedostępna · brak wdrożonego silnika risk</dd>
            </dl>
            <h3>Dlaczego powstał alert</h3>
            {typeof resource.data.reason === 'object' &&
              resource.data.reason !== null &&
              !Array.isArray(resource.data.reason) &&
              typeof resource.data.reason.summary === 'string' && (
                <p>{resource.data.reason.summary}</p>
              )}
            <details>
              <summary>Sprawdzone pola i pełne uzasadnienie</summary>
              <JsonView value={resource.data.reason} />
            </details>
            <div className="button-row">
              <button
                className="primary"
                onClick={() => {
                  onEvent(resource.data!.event_snapshot);
                  onClose();
                }}
              >
                Otwórz dowód zdarzenia
              </button>
              {user.permissions.includes('incidents:edit') && (
                <button
                  onClick={() => {
                    onCreateIncident(resource.data!);
                    onClose();
                  }}
                >
                  Utwórz incydent z alertu
                </button>
              )}
              {user.permissions.includes('alerts:manage') &&
                ['new', 'acknowledged'].includes(resource.data.status) && (
                  <>
                    <button
                      disabled={
                        pending || resource.pending || resource.data.status === 'acknowledged'
                      }
                      onClick={() => {
                        void change('acknowledged');
                      }}
                    >
                      Potwierdź alert
                    </button>
                    <button
                      disabled={pending || resource.pending}
                      onClick={() => {
                        void change('resolved');
                      }}
                    >
                      Oznacz jako rozwiązany
                    </button>
                    <button
                      disabled={pending || resource.pending}
                      onClick={() => {
                        void change('false_positive');
                      }}
                    >
                      Fałszywy alarm
                    </button>
                  </>
                )}
            </div>
            <details>
              <summary>Snapshot reguły</summary>
              <JsonView value={resource.data.rule_snapshot} />
            </details>
            <details>
              <summary>Identyfikatory i pełna historia pól</summary>
              <JsonView value={resource.data} />
            </details>
          </>
        )}
      </div>
    </dialog>
  );
}

export function Detections({ user }: { user: Me }) {
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
