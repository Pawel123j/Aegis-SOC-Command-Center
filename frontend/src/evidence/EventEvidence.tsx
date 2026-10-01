import { Badge } from '../components';
import type { EventSnapshot, SecurityEvent } from '../types';
import { statusName, time } from '../utilities';
import './evidence.css';

function account(value: SecurityEvent['user'] | SecurityEvent['user']['target']) {
  const name = value.name ?? value.id;
  return name ? `${value.realm ? `${value.realm}\\` : ''}${name}` : null;
}

export function EventEvidence({
  events,
  onEvent,
}: {
  events: EventSnapshot[];
  onEvent: (event: SecurityEvent) => void;
}) {
  const timestamps = events.map((item) => item.event_snapshot.timestamp).sort();
  return (
    <section className="event-evidence" aria-label="Zdarzenia dowodowe">
      <h3>Zdarzenia dowodowe ({events.length})</h3>
      <p className="muted">
        Zachowane rekordy użyte w dopasowaniu. Otwórz każdy z nich, aby sprawdzić oryginalny log i
        jego pochodzenie.
      </p>
      {events.length > 1 && (
        <dl className="facts">
          <dt>Pierwszy dowód</dt>
          <dd>{time(timestamps[0])}</dd>
          <dt>Ostatni dowód</dt>
          <dd>{time(timestamps.at(-1))}</dd>
        </dl>
      )}
      <ol className="evidence-events">
        {events.map(({ event_id, event_sha256, event_snapshot: event }, index) => {
          const actor = account(event.user);
          const target = account(event.user.target);
          const login =
            event.source.type === 'windows_auth' &&
            event.event.category === 'authentication' &&
            ['4624', '4625'].includes(event.event.code ?? '');
          return (
            <li key={event_id}>
              <div className="evidence-event-heading">
                <strong>
                  {index + 1}. {event.event.action}
                </strong>
                <Badge tone={event.event.outcome}>
                  {statusName[event.event.outcome] ?? event.event.outcome}
                </Badge>
              </div>
              <small>
                {time(event.timestamp)} · {event.source.name} · {event.source.type}
              </small>
              <p>
                {login
                  ? `Konto logowania: ${target ?? 'Brak danych'}`
                  : `Wykonawca: ${actor ?? 'Brak danych'}`}
              </p>
              {login && actor && actor !== target && <small>Wykonawca: {actor}</small>}
              {!login && target && target !== actor && <small>Konto docelowe: {target}</small>}
              <p>
                Host: {event.host.name ?? 'Brak danych'} · IP źródłowy:{' '}
                {event.source.ip ?? 'Brak danych'}
              </p>
              <button
                className="quiet"
                aria-label={`Otwórz zdarzenie ${index + 1}: ${event.event.action}`}
                onClick={() => onEvent(event)}
              >
                Otwórz oryginalne zdarzenie
              </button>
              {event_sha256 && (
                <details>
                  <summary>Identyfikator i SHA-256 dowodu</summary>
                  <dl className="facts">
                    <dt>Event ID</dt>
                    <dd className="mono">{event_id}</dd>
                    <dt>SHA-256</dt>
                    <dd className="mono">{event_sha256}</dd>
                  </dl>
                </details>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
