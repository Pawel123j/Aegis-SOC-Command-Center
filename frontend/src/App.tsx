import { time, useResource } from './utilities';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, Loading, Metric, Panel } from './components';
import type { Alert, Me, Page, SearchResult, SecurityEvent } from './types';
import { Events, EventDetail } from './Events';
import { Sources } from './Sources';
import { System } from './System';
import { Alerts } from './Alerts';
import { Detections } from './detections/Detections';
import { Incidents } from './incidents/Incidents';

type View = 'overview' | 'alerts' | 'events' | 'incidents' | 'detections' | 'sources' | 'system';
const links: { id: View; name: string; icon: string; permission?: string }[] = [
  { id: 'overview', name: 'Przegląd', icon: '◈' },
  { id: 'alerts', name: 'Alerty', icon: '◉', permission: 'alerts:read' },
  { id: 'incidents', name: 'Incydenty', icon: '◇', permission: 'incidents:read' },
  { id: 'events', name: 'Zdarzenia', icon: '⌕', permission: 'events:read' },
  { id: 'detections', name: 'Reguły detekcji', icon: '⌘', permission: 'detections:read' },
  { id: 'sources', name: 'Źródła logów', icon: '⇄', permission: 'sources:manage' },
  { id: 'system', name: 'Stan systemu', icon: '▥', permission: 'system:read' },
];
const roleName = {
  admin: 'Administrator',
  soc_manager: 'Kierownik SOC',
  soc_analyst: 'Analityk SOC',
  read_only: 'Odczyt',
};

export function App() {
  const [user, setUser] = useState<Me | null>(null);
  const identity = useRef<Me | null>(null);
  const authGeneration = useRef(0);
  const [starting, setStarting] = useState(true);
  const [startError, setStartError] = useState<unknown>(null);
  const [view, setView] = useState<View>('overview');
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [query, setQuery] = useState('');
  const [incidentAlert, setIncidentAlert] = useState<Alert | null>(null);
  const [incidentSequence, setIncidentSequence] = useState(0);
  useEffect(() => {
    let active = true;
    const restoreGeneration = authGeneration.current;
    void api
      .restore()
      .then((me) => {
        if (active && authGeneration.current === restoreGeneration) {
          identity.current = me;
          setUser(me);
        }
      })
      .catch((error: unknown) => {
        if (active && authGeneration.current === restoreGeneration) setStartError(error);
      })
      .finally(() => {
        if (active) setStarting(false);
      });
    const unsubscribe = api.subscribe((kind) => {
      const generation = ++authGeneration.current;
      if (kind === 'logout') {
        identity.current = null;
        setUser(null);
        setSelected(null);
        setIncidentAlert(null);
        setQuery('');
        setView('overview');
      } else {
        void api
          .get<Me>('/auth/me')
          .then((me) => {
            if (active && authGeneration.current === generation) {
              const previous = identity.current;
              const authorityChanged =
                previous?.id !== me.id ||
                previous.role !== me.role ||
                previous.permissions.length !== me.permissions.length ||
                !previous.permissions.every((permission) => me.permissions.includes(permission));
              identity.current = me;
              setUser(me);
              if (authorityChanged) {
                setView('overview');
                setSelected(null);
                setIncidentAlert(null);
                setQuery('');
              }
            }
          })
          .catch(() => {
            if (active && authGeneration.current === generation) {
              identity.current = null;
              setUser(null);
              setView('overview');
              setSelected(null);
              setIncidentAlert(null);
              setQuery('');
            }
          });
      }
    });
    return () => {
      active = false;
      unsubscribe();
    };
  }, []);
  if (starting)
    return (
      <div className="startup">
        <div className="brand-mark">A</div>
        <Loading />
      </div>
    );
  if (!user)
    return (
      <Login
        initialError={startError}
        onLogin={(me) => {
          authGeneration.current++;
          identity.current = me;
          setUser(me);
          setStartError(null);
          setView('overview');
          setSelected(null);
          setIncidentAlert(null);
          setQuery('');
        }}
      />
    );
  const allowed = (permission: string) => user.permissions.includes(permission);
  function filterEntity(field: string, value: string) {
    setQuery(`${field} = ${JSON.stringify(value)}`);
    setSelected(null);
    setView('events');
  }
  return (
    <div className="workspace">
      <a className="skip-link" href="#main">
        Przejdź do treści
      </a>
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            setView('overview');
          }}
        >
          <span className="brand-mark">A</span>
          <span>
            AEGIS<small>SOC COMMAND CENTER</small>
          </span>
        </a>
        <p className="nav-label">CENTRUM OPERACYJNE</p>
        <nav aria-label="Menu główne">
          {links
            .filter((item) => !item.permission || allowed(item.permission))
            .map((item) => (
              <button
                key={item.id}
                className={`nav-item ${view === item.id ? 'active' : ''}`}
                aria-current={view === item.id ? 'page' : undefined}
                onClick={() => setView(item.id)}
              >
                <span aria-hidden="true">{item.icon}</span>
                {item.name}
              </button>
            ))}
        </nav>
        <div className="sidebar-footer">
          <span className="status-dot" />
          Środowisko lokalne<small>Logi z Twoich źródeł</small>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div>
            <span className="eyebrow">AEGIS / OPERACJE SOC</span>
            <h1>{links.find((item) => item.id === view)?.name}</h1>
          </div>
          <div className="account">
            <span className="avatar">{user.username.slice(0, 2).toUpperCase()}</span>
            <div>
              <strong>{user.username}</strong>
              <small>{roleName[user.role]}</small>
            </div>
            <button
              className="quiet"
              onClick={() => {
                void api.logout().catch((error: unknown) => setStartError(error));
              }}
            >
              Wyloguj
            </button>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          <ErrorNotice error={startError} />
          {view === 'overview' && (
            <Overview
              onEvent={setSelected}
              onEvents={() => setView('events')}
              onAlerts={() => setView('alerts')}
            />
          )}
          {view === 'events' && allowed('events:read') && (
            <Events key={query} initialQuery={query} onEvent={setSelected} />
          )}
          {view === 'alerts' && allowed('alerts:read') && (
            <Alerts
              user={user}
              onEvent={setSelected}
              onCreateIncident={(alert) => {
                setIncidentAlert(alert);
                setIncidentSequence((value) => value + 1);
                setView('incidents');
              }}
            />
          )}
          {view === 'incidents' && allowed('incidents:read') && (
            <Incidents
              key={incidentSequence}
              user={user}
              onEvent={setSelected}
              initialAlert={incidentAlert}
              onInitialConsumed={() => setIncidentAlert(null)}
            />
          )}
          {view === 'detections' && allowed('detections:read') && (
            <Detections user={user} onEvent={setSelected} />
          )}
          {view === 'sources' && allowed('sources:manage') && (
            <Sources
              onEventId={(id) => {
                setQuery(`event_id = ${JSON.stringify(id)}`);
                setView('events');
              }}
            />
          )}
          {view === 'system' && allowed('system:read') && (
            <System user={user} onEvent={setSelected} />
          )}
        </main>
        <footer className="page-footer">
          Aegis SOC · Czas prezentowany lokalnie, dane przechowywane w UTC.
        </footer>
      </div>
      {selected && (
        <EventDetail event={selected} onClose={() => setSelected(null)} onFilter={filterEntity} />
      )}
    </div>
  );
}

export function Login({
  onLogin,
  initialError,
}: {
  onLogin: (me: Me) => void;
  initialError?: unknown;
}) {
  const [error, setError] = useState<unknown>(initialError);
  const [pending, setPending] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    setPending(true);
    setError(null);
    try {
      const me = await api.login(String(fields.get('username')), String(fields.get('password')));
      form.reset();
      onLogin(me);
    } catch (failure) {
      setError(failure);
      const password = form.elements.namedItem('password') as HTMLInputElement;
      password.value = '';
      password.focus();
    } finally {
      setPending(false);
    }
  }
  return (
    <div className="login-page">
      <section className="login-story">
        <a className="brand">
          <span className="brand-mark">A</span>
          <span>
            AEGIS<small>SOC COMMAND CENTER</small>
          </span>
        </a>
        <span className="eyebrow">WIDOCZNOŚĆ. KONTEKST. REAKCJA.</span>
        <h1>
          Twoje centrum
          <br />
          <span>bezpieczeństwa.</span>
        </h1>
        <p>
          Od surowego logu do sprawdzalnego dowodu. Zdarzenia, alerty i źródła w jednym miejscu.
        </p>
        <div className="login-lines" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <small>Lokalne środowisko SOC · Dostęp dla uprawnionych osób</small>
      </section>
      <section className="login-card">
        <span className="eyebrow">DOSTĘP DO PLATFORMY</span>
        <h2>Zaloguj się do Aegis</h2>
        <p className="muted">Użyj konta utworzonego podczas uruchomienia.</p>
        <ErrorNotice error={error} />
        <form
          onSubmit={(event) => {
            void submit(event);
          }}
        >
          <label>
            Nazwa użytkownika
            <input
              name="username"
              autoComplete="username"
              required
              minLength={3}
              maxLength={64}
              autoFocus
            />
          </label>
          <label>
            Hasło
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
              minLength={15}
              maxLength={128}
            />
          </label>
          <button className="primary full" disabled={pending}>
            {pending ? 'Logowanie…' : 'Zaloguj się'}
            <span aria-hidden="true">→</span>
          </button>
        </form>
        <div className="login-help">
          <strong>Pierwsze uruchomienie?</strong>
          <p>
            Otwórz „Uruchom Aegis.cmd” w folderze projektu i utwórz konto administratora. Następnie
            wróć do tego ekranu.
          </p>
        </div>
      </section>
    </div>
  );
}

function Overview({
  onEvent,
  onEvents,
  onAlerts,
}: {
  onEvent: (event: SecurityEvent) => void;
  onEvents: () => void;
  onAlerts: () => void;
}) {
  const loader = useCallback(async () => {
    const [events, alerts] = await Promise.allSettled([
      api.post<SearchResult>('/events/search', { limit: 6 }),
      api.get<Page<Alert>>('/alerts?limit=6&status=new'),
    ]);
    return {
      events: events.status === 'fulfilled' ? events.value : null,
      eventError: events.status === 'rejected' ? (events.reason as unknown) : null,
      alerts: alerts.status === 'fulfilled' ? alerts.value : null,
      alertError: alerts.status === 'rejected' ? (alerts.reason as unknown) : null,
    };
  }, []);
  const resource = useResource(loader);
  return (
    <>
      <div className="intro">
        <div>
          <h2>Obraz sytuacji</h2>
          <p>Sprawdź najnowszą aktywność i alerty wymagające uwagi.</p>
        </div>
        <button
          onClick={() => {
            void resource.reload();
          }}
          disabled={resource.pending}
        >
          Odśwież
        </button>
      </div>
      <div className="metrics">
        <Metric
          label="Zdarzenia · ostatnie 24 h"
          value={resource.data?.events?.total}
          note="Znormalizowane rekordy w archiwum"
        />
        <Metric
          label="Nowe alerty"
          value={resource.data?.alerts?.total}
          note="Cały dostępny zakres czasu"
        />
        <Metric label="Zakres zdarzeń" value="24 godziny" note="Domyślne okno Event Explorer" />
        <Metric
          label="Ocena ryzyka"
          value="Niedostępna"
          note="Silnik oceny ryzyka czeka na wdrożenie"
        />
      </div>
      {resource.pending && <Loading />}
      <ErrorNotice error={resource.error} />
      <div className="overview-grid">
        <Panel
          title="Najnowsze zdarzenia"
          aside={
            <button className="quiet" onClick={onEvents}>
              Wszystkie →
            </button>
          }
        >
          <ErrorNotice error={resource.data?.eventError} />
          {resource.data?.events &&
            (resource.data.events.items.length ? (
              <div className="activity-list">
                {resource.data.events.items.map((item) => (
                  <button className="activity" key={item.event_id} onClick={() => onEvent(item)}>
                    <span className="activity-icon">⌕</span>
                    <span>
                      <strong>{item.event.action}</strong>
                      <small>
                        {item.source.name} · {item.host.name ?? item.source.ip ?? 'Brak encji'}
                      </small>
                    </span>
                    <span>
                      <Badge tone={item.event.outcome}>{item.event.outcome}</Badge>
                      <small>{time(item.timestamp)}</small>
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <Empty title="Archiwum jest puste">
                Dodaj źródło i prześlij logi. Przetworzone zdarzenia pojawią się tutaj.
              </Empty>
            ))}
        </Panel>
        <Panel
          title="Alerty wymagające uwagi"
          aside={
            <button className="quiet" onClick={onAlerts}>
              Otwórz →
            </button>
          }
        >
          <ErrorNotice error={resource.data?.alertError} />
          {resource.data?.alerts &&
            (resource.data.alerts.items.length ? (
              <div className="activity-list">
                {resource.data.alerts.items.map((item) => (
                  <button className="activity" key={item.id} onClick={onAlerts}>
                    <span className="activity-icon alert-icon">!</span>
                    <span>
                      <strong>{item.title}</strong>
                      <small>{item.rule_id}</small>
                    </span>
                    <Badge tone={item.severity}>{item.severity}</Badge>
                  </button>
                ))}
              </div>
            ) : (
              <Empty title="Brak nowych alertów">
                W tym momencie żadna aktywna reguła nie zgłosiła alertu do analizy.
              </Empty>
            ))}
        </Panel>
      </div>
      <div className="notice">
        <strong>Każdy alert ma źródło.</strong> Otwórz szczegóły, aby sprawdzić regułę,
        zaobserwowane pola i zachowany dowód zdarzenia.
      </div>
    </>
  );
}
