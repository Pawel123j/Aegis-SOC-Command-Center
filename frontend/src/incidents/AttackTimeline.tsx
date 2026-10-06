import { ApiError } from '../api';
import { Badge, Empty, ErrorNotice, Loading, Panel } from '../components';
import type { Me, SecurityEvent } from '../types';
import { statusName, time } from '../utilities';
import { Pagination } from './Pagination';
import type { AttackTimelineEvent, IncidentDetail } from './types';
import { useAttackTimeline } from './useAttackTimeline';

const errors: Record<string, string> = {
  attack_timeline_changed:
    'Sprawa, powiązane alerty lub indeks zdarzeń zmieniły się. Odśwież sprawę i chronologię od pierwszej strony.',
  attack_timeline_integrity_mismatch:
    'Nie można potwierdzić zgodności zachowanych dowodów. Chronologia nie została pokazana.',
  attack_timeline_limit_exceeded:
    'Sprawa przekracza limit chronologii. Nie można pokazać pełnego widoku.',
  attack_timeline_page_too_large:
    'Zachowane dowody na tej stronie przekraczają limit rozmiaru. Wybierz mniej zdarzeń na stronie i spróbuj ponownie.',
};
const detectionNames = {
  single_event: 'Reguła pojedynczego zdarzenia',
  correlation: 'Korelacja',
  sigma: 'Sigma',
  intelligence: 'Threat Intelligence',
};
function account(value: SecurityEvent['user'] | SecurityEvent['user']['target']) {
  const name = value.name ?? value.id;
  return name ? `${value.realm ? `${value.realm}\\` : ''}${name}` : 'Brak danych';
}
function TimelineFailure({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || !Object.hasOwn(errors, error.code))
    return <ErrorNotice error={error} />;
  return (
    <div className="notice error" role="alert">
      {errors[error.code]}
      {error.requestId && <small>Identyfikator żądania: {error.requestId}</small>}
    </div>
  );
}

export function AttackTimeline({
  incident,
  user,
  onEvent,
  onIncidentRefresh,
  refreshKey,
  paused,
}: {
  incident: IncidentDetail;
  user: Me;
  onEvent: (event: SecurityEvent) => void;
  onIncidentRefresh: () => void | Promise<void>;
  refreshKey: number;
  paused: boolean;
}) {
  const allowed = ['incidents:read', 'alerts:read', 'events:read'].every((permission) =>
    user.permissions.includes(permission),
  );
  if (!allowed)
    return (
      <Panel title="Chronologia zdarzeń">
        <p className="notice">Odczyt chronologii wymaga uprawnień do spraw, alertów i zdarzeń.</p>
      </Panel>
    );
  if (paused)
    return (
      <Panel title="Chronologia zdarzeń">
        <p className="muted">Chronologia będzie dostępna po odświeżeniu szczegółów sprawy.</p>
      </Panel>
    );
  return (
    <TimelineView
      key={`${incident.id}/${incident.version}/${refreshKey}/${user.id}/${user.role}/${[...user.permissions].sort().join(',')}`}
      incident={incident}
      user={user}
      onEvent={onEvent}
      onIncidentRefresh={onIncidentRefresh}
    />
  );
}

function TimelineView({
  incident,
  user,
  onEvent,
  onIncidentRefresh,
}: {
  incident: IncidentDetail;
  user: Me;
  onEvent: (event: SecurityEvent) => void;
  onIncidentRefresh: () => void | Promise<void>;
}) {
  const resource = useAttackTimeline(incident.id, user);
  const data = resource.data;
  const changed =
    resource.error instanceof ApiError && resource.error.code === 'attack_timeline_changed';
  const newer = data && data.incident_version !== incident.version;
  return (
    <Panel title="Chronologia zdarzeń">
      <p className="muted">
        Od najwcześniejszego zdarzenia. Każdy zachowany dowód występuje raz, nawet gdy pasuje do
        kilku aktywnie powiązanych alertów. Kolejność czasu nie potwierdza związku przyczynowego ani
        etapów ataku.
      </p>
      <div className="attack-timeline-controls">
        <label>
          Zdarzeń na stronie
          <select
            value={resource.limit}
            disabled={resource.expired || resource.checking}
            onChange={(event) => resource.changeLimit(Number(event.target.value))}
          >
            {[1, 5, 10, 25].map((limit) => (
              <option key={limit} value={limit}>
                {limit}
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={resource.pending || resource.checking}
          onClick={() => void resource.refresh(changed || newer ? onIncidentRefresh : undefined)}
        >
          {changed || newer ? 'Odśwież sprawę i chronologię' : 'Odśwież chronologię'}
        </button>
      </div>
      <TimelineFailure error={resource.error} />
      {resource.expired && !resource.checking && !resource.error && (
        <p className="notice" role="alert">
          Sesja zmieniła się. Odśwież chronologię, aby sprawdzić bieżące konto i ponownie pobrać
          dowody.
        </p>
      )}
      {resource.checking && <p role="status">Sprawdzanie bieżącego konta…</p>}
      {resource.pending && <Loading />}
      {data && (
        <>
          <div className="detail-badges">
            <Badge>
              {data.mode === 'live' ? 'Live · aktywne powiązania' : 'Replay · aktywne powiązania'}
            </Badge>
            <Badge>{data.total} różnych zdarzeń w indeksie</Badge>
          </div>
          <p className={data.index_status.complete ? 'muted' : 'notice'}>
            Zindeksowane alerty: {data.index_status.indexed_alerts} z{' '}
            {data.index_status.eligible_alerts}.
            {data.index_status.complete
              ? ' Indeks obejmuje wszystkie aktywnie powiązane alerty.'
              : ` Widok jest niepełny: ${data.index_status.pending_alerts} alertów czeka na indeksowanie. Odczyt chronologii nie uzupełnia indeksu.`}
          </p>
          {newer && (
            <p className="notice">
              Chronologia pochodzi z innej wersji sprawy. Odśwież również jej szczegóły.
            </p>
          )}
          <details className="attack-timeline-scope">
            <summary>Zakres i wersja chronologii</summary>
            <dl className="facts">
              <dt>Wersja sprawy</dt>
              <dd>{data.incident_version}</dd>
              <dt>Dataset ID</dt>
              <dd className="mono">{data.dataset_id ?? 'Wiele źródeł live'}</dd>
              <dt>Run ID</dt>
              <dd className="mono">{data.run_id}</dd>
              <dt>Wersja widoku</dt>
              <dd>{data.projection_version}</dd>
              <dt>SHA-256 widoku</dt>
              <dd className="mono">{data.view_fingerprint}</dd>
            </dl>
          </details>
          {data.items.length ? (
            <ol className="attack-timeline" aria-label="Chronologia zachowanych zdarzeń">
              {data.items.map((item) => (
                <TimelineEvent
                  key={item.event_id}
                  item={item}
                  onEvent={(event) => {
                    if (resource.isCurrent()) onEvent(event);
                  }}
                />
              ))}
            </ol>
          ) : (
            <Empty
              title={
                data.index_status.complete
                  ? 'Brak zdarzeń w chronologii'
                  : 'Nie ma jeszcze zindeksowanych zdarzeń'
              }
            >
              {data.index_status.complete
                ? 'Żaden aktywnie powiązany alert nie wnosi zachowanego zdarzenia do tego widoku.'
                : 'Brak wpisów nie oznacza braku zdarzeń. Indeks aktywnych alertów jest niepełny.'}
            </Empty>
          )}
          <Pagination {...resource.pagination} />
        </>
      )}
    </Panel>
  );
}

function TimelineEvent({
  item,
  onEvent,
}: {
  item: AttackTimelineEvent;
  onEvent: (event: SecurityEvent) => void;
}) {
  const event = item.event_snapshot;
  return (
    <li>
      <div className="attack-timeline-heading">
        <time dateTime={event.timestamp}>{time(event.timestamp)}</time>
        <Badge tone={event.event.outcome}>
          {statusName[event.event.outcome] ?? event.event.outcome}
        </Badge>
      </div>
      <h3>{event.event.action}</h3>
      <p className="muted">
        {event.source.name} · {event.source.type}
      </p>
      {event.quality.includes('timestamp_from_received_at') && (
        <p className="notice">
          Brak czasu źródłowego: pokazany czas pochodzi z przyjęcia zdarzenia przez serwer.
        </p>
      )}
      <dl className="attack-timeline-facts">
        <dt>Wykonawca</dt>
        <dd>{account(event.user)}</dd>
        <dt>Konto docelowe</dt>
        <dd>{account(event.user.target)}</dd>
        <dt>Host</dt>
        <dd>{event.host.name ?? event.host.id ?? 'Brak danych'}</dd>
        <dt>IP źródłowy</dt>
        <dd className="mono">{event.source.ip ?? 'Brak danych'}</dd>
      </dl>
      <button
        className="quiet"
        onClick={() => onEvent(event)}
        aria-label={`Otwórz oryginalne zdarzenie: ${event.event.action}`}
      >
        Otwórz oryginalne zdarzenie
      </button>
      <details>
        <summary>Powiązane alerty ({item.alerts.length})</summary>
        <ul className="attack-timeline-alerts">
          {item.alerts.map((alert) => (
            <li key={alert.id}>
              <strong>{alert.title}</strong>
              <div className="detail-badges">
                <Badge tone={alert.severity}>{alert.severity}</Badge>
                <Badge>{statusName[alert.status] ?? alert.status}</Badge>
                <Badge>{detectionNames[alert.detection_type]}</Badge>
              </div>
              <p>
                Reguła: {alert.rule_id} / {alert.rule_version} · powiązano: {time(alert.linked_at)}
              </p>
              <small className="mono">{alert.id}</small>
            </li>
          ))}
        </ul>
      </details>
      <details>
        <summary>Identyfikator, dokładny czas i SHA-256 dowodu</summary>
        <dl className="facts">
          <dt>Event ID</dt>
          <dd className="mono">{item.event_id}</dd>
          <dt>Czas zdarzenia · UTC</dt>
          <dd className="mono">{event.timestamp}</dd>
          <dt>SHA-256</dt>
          <dd className="mono">{item.event_sha256}</dd>
        </dl>
      </details>
    </li>
  );
}
