import { useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api';
import { Badge, ErrorNotice, Loading, Metric, Panel } from '../components';
import { useEntityResource } from '../entities/useEntityResource';
import type { Me, SecurityEvent } from '../types';
import { matchesEvidence, uebaEvidencePath, uebaPath, yesterdayUtc } from './filters';
import type { UebaEvidence, UebaIndicator, UebaIndicatorId, UebaReport } from './types';
import './ueba.css';

const names: Record<UebaIndicatorId, string> = {
  unusual_login_hour: 'Nietypowa pora logowania',
  new_login_ip: 'Nowy adres IP logowania',
  new_login_host: 'Nowy host logowania użytkownika',
  first_admin_tool: 'Pierwsze użycie narzędzia administracyjnego',
  failed_login_burst: 'Wzrost nieudanych logowań',
  activity_burst: 'Wzrost aktywności',
  admin_account_use: 'Użycie konta uprzywilejowanego',
};
const indicatorStates = {
  anomaly: 'Odchylenie od wzorca',
  normal: 'Bez wykrytego odchylenia',
  insufficient_data: 'Za mało danych do porównania',
  unsupported: 'Brak wymaganych informacji',
};
const errorMessages: Record<string, string> = {
  invalid_ueba_day: 'Wybierz zakończony dzień UTC, od 29 stycznia 1970 do wczoraj.',
  entity_not_found: 'Profil nie jest dostępny w tym zakresie. Otwórz go ponownie z listy.',
  ueba_limit_exceeded:
    'Dane przekraczają limit analizy. Wynik nie został obliczony; wybierz inny dzień lub profil.',
  ueba_integrity_mismatch:
    'Nie można potwierdzić zgodności zachowanych dowodów. Ponów analizę przed otwarciem zdarzenia.',
  ueba_changed:
    'Wynik analizy zmienił się. Kliknij „Analizuj dzień”, aby pobrać aktualne wyniki i dowody.',
};
function UebaError({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || !Object.hasOwn(errorMessages, error.code))
    return <ErrorNotice error={error} />;
  return (
    <div className="notice error" role="alert">
      {errorMessages[error.code]}
      {error.requestId && <small>Identyfikator żądania: {error.requestId}</small>}
    </div>
  );
}

export function UebaProfile({
  id,
  kind,
  params,
  user,
  onEvent,
}: {
  id: string;
  kind: string;
  params: string;
  user: Me;
  onEvent: (event: SecurityEvent) => void;
}) {
  if (kind !== 'user' && kind !== 'host') return null;
  if (
    !['events:read', 'alerts:read', 'incidents:read'].every((permission) =>
      user.permissions.includes(permission),
    )
  )
    return (
      <Panel title="Analiza zachowania">
        <p className="notice">Analiza wymaga uprawnień do profili, zdarzeń, alertów i spraw.</p>
      </Panel>
    );
  return (
    <Analysis
      key={`${id}/${params}/${user.id}/${user.role}/${[...user.permissions].sort().join(',')}`}
      id={id}
      params={params}
      user={user}
      onEvent={onEvent}
    />
  );
}

function Analysis({ id, params, user, onEvent }: Omit<Parameters<typeof UebaProfile>[0], 'kind'>) {
  const [day, setDay] = useState(yesterdayUtc);
  const [path, setPath] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [expired, setExpired] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const authority = useRef(0);
  const active = useRef(true);
  const controller = useRef<AbortController | null>(null);
  const flight = useRef(false);
  const resource = useEntityResource<UebaReport>(path);
  useEffect(() => {
    const liveness = active;
    const counter = authority;
    const requests = controller;
    const pending = flight;
    liveness.current = true;
    const unsubscribe = api.subscribe(() => {
      counter.current++;
      requests.current?.abort();
      pending.current = false;
      setPath(null);
      setChecking(false);
      setExpired(true);
      setError(null);
    });
    return () => {
      liveness.current = false;
      counter.current++;
      requests.current?.abort();
      unsubscribe();
    };
  }, []);

  async function analyze() {
    if (flight.current) return;
    setError(null);
    let nextPath: string;
    try {
      nextPath = uebaPath(id, params, day);
    } catch (failure) {
      setError(failure);
      return;
    }
    flight.current = true;
    const revision = ++authority.current;
    controller.current?.abort();
    const requestController = new AbortController();
    controller.current = requestController;
    setPath(null);
    setChecking(true);
    try {
      const current = await api.request<Me>('/auth/me', {
        signal: AbortSignal.any([requestController.signal, AbortSignal.timeout(15000)]),
      });
      if (!active.current || authority.current !== revision) return;
      if (
        current.id !== user.id ||
        current.role !== user.role ||
        current.permissions.length !== user.permissions.length ||
        !user.permissions.every((permission) => current.permissions.includes(permission))
      )
        throw new Error('Konto lub uprawnienia zmieniły się. Otwórz profil z menu bieżącej sesji.');
      setExpired(false);
      setPath(nextPath);
    } catch (failure) {
      if (active.current && authority.current === revision) setError(failure);
    } finally {
      if (active.current && authority.current === revision) {
        flight.current = false;
        setChecking(false);
      }
    }
  }
  const report = resource.data;
  const reportMatches =
    report &&
    path &&
    report.entity.id === id.toLowerCase() &&
    report.scope.mode === new URLSearchParams(params).get('mode') &&
    (report.scope.mode === 'live'
      ? report.scope.dataset_id === null && report.scope.run_id === null
      : report.scope.dataset_id === new URLSearchParams(params).get('dataset_id')?.toLowerCase() &&
        report.scope.run_id === new URLSearchParams(params).get('run_id')?.toLowerCase()) &&
    report.observation.from.slice(0, 10) === new URLSearchParams(path.split('?')[1]).get('day');
  return (
    <Panel title="Analiza zachowania">
      <p>
        Porównaj zakończony dzień z poprzednimi 28 dniami w tym samym profilu i zakresie live lub
        replay. Wynik opisuje odchylenie od zaobserwowanego wzorca; nie jest prawdopodobieństwem
        ataku ani oceną ryzyka.
      </p>
      <form
        className="ueba-controls"
        onSubmit={(event) => {
          event.preventDefault();
          void analyze();
        }}
      >
        <label>
          Dzień obserwacji · UTC
          <input
            type="date"
            min="1970-01-29"
            max={yesterdayUtc()}
            value={day}
            disabled={checking}
            onChange={(event) => {
              setDay(event.target.value);
              setPath(null);
              setError(null);
            }}
            required
          />
        </label>
        <button disabled={checking || resource.pending} type="submit">
          Analizuj dzień
        </button>
      </form>
      <p className="muted">
        Własny zakres czasu profilu nie zmienia długości wzorca. Dla danych historycznych i replay
        wybierz dzień, w którym wystąpiły zdarzenia.
      </p>
      {expired && (
        <p className="notice">
          Sesja zmieniła się. Ponowna analiza sprawdzi bieżące konto przed pobraniem danych.
        </p>
      )}
      <UebaError error={error ?? (path ? resource.error : null)} />
      {checking && <p role="status">Sprawdzanie bieżącego konta…</p>}
      {resource.pending && <Loading />}
      {report && !reportMatches && (
        <ErrorNotice
          error={
            new Error('Odpowiedź nie pasuje do wybranego profilu, dnia lub zakresu. Ponów analizę.')
          }
        />
      )}
      {reportMatches && <Report key={path} report={report} onEvent={onEvent} />}
    </Panel>
  );
}

function Report({
  report,
  onEvent,
}: {
  report: UebaReport;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [selected, setSelected] = useState<UebaEvidence | null>(null);
  const event = useEntityResource<SecurityEvent>(
    selected ? uebaEvidencePath(report, selected) : null,
  );
  const delivered = useRef<SecurityEvent | null>(null);
  const validSession = useRef(true);
  useEffect(
    () =>
      api.subscribe(() => {
        validSession.current = false;
      }),
    [],
  );
  const validEvent = event.data && selected && matchesEvidence(event.data, selected, report);
  useEffect(() => {
    if (event.data && validEvent && validSession.current && delivered.current !== event.data) {
      delivered.current = event.data;
      onEvent(event.data);
    }
  }, [event.data, validEvent, onEvent]);
  function open(evidence: UebaEvidence) {
    if (!validSession.current || event.pending) return;
    delivered.current = null;
    if (
      selected?.event_id !== evidence.event_id ||
      selected.document_sha256 !== evidence.document_sha256
    )
      setSelected(evidence);
    else void event.reload();
  }
  return (
    <div className="ueba-report">
      <div className="detail-badges">
        <Badge>{report.scope.mode === 'live' ? 'Live' : 'Replay · odrębny wzorzec'}</Badge>
        <Badge>{report.policy_version}</Badge>
      </div>
      {report.status === 'cold_start' && (
        <p className="notice">
          Wzorzec jeszcze się buduje. Potrzeba co najmniej {report.baseline.minimum_events} zdarzeń
          z wiarygodnym czasem w {report.baseline.minimum_active_days} różnych dniach. Brak oceny
          nie oznacza braku zagrożenia.
        </p>
      )}
      {report.status === 'index_pending' && (
        <p className="notice">
          Indeks jest niepełny: {report.pending_events} zdarzeń oczekuje na indeksowanie. Analiza
          nie podaje oceny na podstawie niepełnych danych.
        </p>
      )}
      {report.status === 'unsupported' && (
        <p className="notice">
          Ten profil nie dostarcza danych wymaganych przez analizę zachowania.
        </p>
      )}
      <div className="metrics">
        <Metric
          label="Odchylenie od wzorca"
          value={report.score ?? undefined}
          note="Skala 0–100 według wersji polityki. Brak oceny: —."
        />
        <Metric
          label="Dzień obserwacji"
          value={report.observation.eligible_events}
          note={`${report.observation.from.slice(0, 10)} UTC · kwalifikujące się zdarzenia`}
        />
        <Metric
          label="Wzorzec z 28 dni"
          value={report.baseline.eligible_events}
          note={`${report.baseline.active_days} dni z aktywnością`}
        />
      </div>
      <details>
        <summary>Zakres analizy i jakość danych</summary>
        <dl className="facts">
          <dt>Stan danych z chwili · UTC</dt>
          <dd>{report.as_of}</dd>
          <dt>Obserwacja · UTC, od włącznie do wyłącznie</dt>
          <dd>
            {report.observation.from} — {report.observation.to}
          </dd>
          <dt>Wzorzec · UTC, od włącznie do wyłącznie</dt>
          <dd>
            {report.baseline.from} — {report.baseline.to}
          </dd>
          <dt>Wszystkie zdarzenia · obserwacja / wzorzec</dt>
          <dd>
            {report.observation.event_count} / {report.baseline.event_count}
          </dd>
          <dt>Pominięte zdarzenia bez wiarygodnego czasu · obserwacja / wzorzec</dt>
          <dd>
            {report.observation.excluded_timestamp_events} /{' '}
            {report.baseline.excluded_timestamp_events}
          </dd>
          <dt>Podstawa tożsamości</dt>
          <dd>{report.entity.identity_basis}</dd>
          <dt>Dataset ID</dt>
          <dd className="mono">{report.scope.dataset_id ?? 'Źródła live'}</dd>
          <dt>Run ID</dt>
          <dd className="mono">{report.scope.run_id ?? 'Live'}</dd>
        </dl>
      </details>
      <UebaError error={event.error} />
      {event.pending && <p role="status">Pobieranie oryginalnego zdarzenia…</p>}
      {event.data && !validEvent && (
        <ErrorNotice
          error={
            new Error(
              'Zdarzenie nie pasuje do zachowanego dowodu lub zakresu analizy. Nie zostało otwarte.',
            )
          }
        />
      )}
      {Boolean(event.error) &&
        !(event.error instanceof ApiError && event.error.code === 'ueba_changed') && (
          <p className="muted">
            Dowód jest sprawdzany ponownie przy otwarciu. Możesz ponowić próbę tym samym przyciskiem
            lub odświeżyć wyniki przyciskiem „Analizuj dzień”.
          </p>
        )}
      <ul className="ueba-indicators" aria-label="Wskaźniki zachowania">
        {report.indicators.map((indicator) => (
          <Indicator key={indicator.id} indicator={indicator} onEvent={open} />
        ))}
      </ul>
    </div>
  );
}
function Indicator({
  indicator,
  onEvent,
}: {
  indicator: UebaIndicator;
  onEvent: (evidence: UebaEvidence) => void;
}) {
  return (
    <li>
      <h3>{names[indicator.id]}</h3>
      <div className="detail-badges">
        <Badge tone={indicator.status === 'anomaly' ? 'medium' : undefined}>
          {indicatorStates[indicator.status]}
        </Badge>
        <Badge>Punkty: {indicator.score}</Badge>
      </div>
      <p>{indicator.explanation}</p>
      <dl className="facts">
        <dt>Zdarzenia wzorca / aktywne dni</dt>
        <dd>
          {indicator.baseline_event_count} / {indicator.baseline_active_days}
        </dd>
        <dt>Zaobserwowana liczba</dt>
        <dd>{indicator.observed_count}</dd>
        {indicator.daily_mean !== null && (
          <>
            <dt>Średnia dzienna</dt>
            <dd>{indicator.daily_mean.toLocaleString('pl-PL', { maximumFractionDigits: 4 })}</dd>
          </>
        )}
        {indicator.daily_stddev !== null && (
          <>
            <dt>Odchylenie standardowe</dt>
            <dd>{indicator.daily_stddev.toLocaleString('pl-PL', { maximumFractionDigits: 4 })}</dd>
          </>
        )}
        {indicator.threshold !== null && (
          <>
            <dt>Próg</dt>
            <dd>{indicator.threshold.toLocaleString('pl-PL')}</dd>
          </>
        )}
      </dl>
      <details>
        <summary>Wartości wzorca i obserwacji</summary>
        <p>
          Wzorzec:{' '}
          {indicator.baseline_values.length
            ? indicator.baseline_values.join(', ')
            : 'Brak wartości'}
        </p>
        <p>
          Obserwacja:{' '}
          {indicator.observed_values.length
            ? indicator.observed_values.join(', ')
            : 'Brak wartości'}
        </p>
      </details>
      <details>
        <summary>
          Dowody: {indicator.evidence.length} z {indicator.evidence_total}
        </summary>
        {indicator.evidence_total > indicator.evidence.length && (
          <p className="notice">
            Pokazano ograniczoną próbkę dowodów. Łącznie: {indicator.evidence_total} zdarzeń.
          </p>
        )}
        {indicator.evidence.length ? (
          <ol className="ueba-evidence">
            {indicator.evidence.map((evidence) => (
              <li key={evidence.event_id}>
                <time dateTime={evidence.timestamp}>{evidence.timestamp}</time>
                <small className="mono">Event ID: {evidence.event_id}</small>
                <small className="mono">SHA-256 dokumentu: {evidence.document_sha256}</small>
                <button
                  onClick={() => onEvent(evidence)}
                  aria-label={`Otwórz dowód: ${names[indicator.id]}, ${evidence.event_id}`}
                >
                  Otwórz zdarzenie dowodowe
                </button>
              </li>
            ))}
          </ol>
        ) : (
          <p className="muted">Brak zdarzeń dowodowych dla tego wskaźnika.</p>
        )}
      </details>
    </li>
  );
}
