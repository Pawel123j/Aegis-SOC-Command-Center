import { time, statusName, useResource } from './utilities';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from './components';
import type { Alert, AlertDetail, Me, Page, SecurityEvent } from './types';
import { EventEvidence } from './evidence/EventEvidence';
import { evidenceEvents } from './evidence/events';
import { EventReason } from './evidence/EventReason';
import { RiskScore } from './risk/RiskScore';
import { RiskPanel } from './risk/RiskPanel';
import { MitreMapping } from './mitre/MitreMapping';
import { AlertIntelligence } from './intelligence/AlertIntelligence';

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
                      <th>Ryzyko</th>
                      <th>Status</th>
                      <th>Czas zdarzenia / końca sekwencji</th>
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
                          {item.detection_type === 'correlation' && (
                            <small>Korelacja · liczba zdarzeń: {item.event_count}</small>
                          )}
                          {item.detection_type === 'sigma' && <Badge>Sigma</Badge>}
                          {item.detection_type === 'intelligence' && (
                            <Badge>Threat Intelligence</Badge>
                          )}
                        </td>
                        <td>
                          <Badge tone={item.severity}>{item.severity}</Badge>
                        </td>
                        <td>
                          <RiskScore score={item.risk_score} level={item.risk_level} />
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
export function AlertDialog({
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
              {resource.data.detection_type === 'sigma' && <Badge>Sigma</Badge>}
              {resource.data.detection_type === 'intelligence' && (
                <Badge>Threat Intelligence</Badge>
              )}
            </div>
            <dl className="facts">
              <dt>
                {resource.data.detection_type === 'correlation'
                  ? 'Koniec sekwencji'
                  : 'Czas zdarzenia'}
              </dt>
              <dd>{time(resource.data.event_timestamp)}</dd>
              <dt>Wykryto</dt>
              <dd>{time(resource.data.created_at)}</dd>
              <dt>Reguła / wersja</dt>
              <dd>
                {resource.data.rule_id} / {resource.data.rule_version}
              </dd>
              {resource.data.evaluator_version && (
                <>
                  <dt>Wersja silnika</dt>
                  <dd>{resource.data.evaluator_version}</dd>
                </>
              )}
              <dt>Potwierdzono</dt>
              <dd>{time(resource.data.acknowledged_at)}</dd>
              <dt>Ocena ryzyka</dt>
              <dd>
                <RiskScore score={resource.data.risk_score} level={resource.data.risk_level} />
              </dd>
            </dl>
            <RiskPanel
              subject="alert"
              id={id}
              initial={resource.data.risk_explanation}
              canReadPolicy={user.permissions.includes('detections:read')}
              onRefresh={() => void resource.reload()}
              refreshPending={resource.pending}
            />
            <h3>Dlaczego powstał alert</h3>
            {resource.data.detection_type === 'sigma' && (
              <p className="notice">
                Dopasowano zachowaną wersję reguły Sigma. Priorytet pochodzi z poziomu
                zadeklarowanego przez autora; nie potwierdza pewności ani niezależnego zachowania.
              </p>
            )}
            {resource.data.detection_type === 'intelligence' && (
              <p className="notice">
                Dopasowano zachowaną deklarację lokalnego katalogu IOC. Reputacja pochodzi ze
                wskazanego źródła; dopasowanie nie potwierdza ataku ani złośliwego działania.
              </p>
            )}
            <EventReason reason={resource.data.reason} />
            {resource.data.detection_type === 'intelligence' && (
              <AlertIntelligence reason={resource.data.reason} />
            )}
            <MitreMapping mapping={resource.data.mitre_mapping} />
            <details>
              <summary>Sprawdzone pola i pełne uzasadnienie</summary>
              <JsonView value={resource.data.reason} />
            </details>
            <EventEvidence
              events={evidenceEvents(resource.data)}
              onEvent={(event) => {
                onEvent(event);
                onClose();
              }}
            />
            <div className="button-row">
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
