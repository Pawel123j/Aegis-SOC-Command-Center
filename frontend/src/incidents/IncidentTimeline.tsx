import { useCallback } from 'react';
import { Empty, ErrorNotice, JsonView, Loading, Panel } from '../components';
import type { SecurityEvent } from '../types';
import { AlertEvidenceButton } from '../evidence/AlertEvidenceButton';
import { time } from '../utilities';
import { incidentsApi } from './api';
import { incidentStatuses } from './labels';
import { Pagination } from './Pagination';
import type { IncidentDetail, IncidentTimelineEntry } from './types';
import { usePage } from './usePage';

const labels: Record<string, string> = {
  incident_created: 'Utworzono incydent',
  alert_attached: 'Powiązano alert',
  alert_detached: 'Odpięto alert · dowód zachowany',
  fields_updated: 'Zmieniono opis, wagę lub tagi',
  status_changed: 'Zmieniono status',
  owner_changed: 'Zmieniono przypisanie analityka',
  note_added: 'Dodano notatkę analityka',
};

function fields(entry: IncidentTimelineEntry) {
  return entry.data !== null && typeof entry.data === 'object' && !Array.isArray(entry.data)
    ? entry.data
    : {};
}

export function IncidentTimeline({
  incident,
  onEvent,
}: {
  incident: IncidentDetail;
  onEvent: (event: SecurityEvent) => void;
}) {
  const { id, version } = incident;
  const loader = useCallback(
    (cursor: string | null) => {
      void version;
      return incidentsApi.timeline(id, cursor);
    },
    [id, version],
  );
  const resource = usePage(loader);
  return (
    <Panel title="Historia pracy analityka">
      <p className="muted">
        Od najnowszego wpisu. Czas działania analityka i czas oryginalnego zdarzenia są opisane
        oddzielnie.
      </p>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data &&
        !resource.error &&
        (resource.data.items.length ? (
          <>
            <ol className="incident-timeline">
              {resource.data.items.map((entry) => {
                const data = fields(entry);
                return (
                  <li key={entry.id}>
                    <time dateTime={entry.occurred_at}>{time(entry.occurred_at)}</time>
                    <strong>{labels[entry.kind] ?? entry.kind}</strong>
                    <small>
                      {entry.actor?.username ?? 'System'}
                      {entry.kind === 'incident_created' && data.automatic === true
                        ? ' · automatycznie po wykryciu alertu'
                        : ''}
                    </small>
                    {typeof data.title === 'string' && <p>{data.title}</p>}
                    {typeof data.event_timestamp === 'string' && (
                      <p className="muted">Czas zdarzenia: {time(data.event_timestamp)}</p>
                    )}
                    {entry.kind === 'status_changed' && (
                      <p>
                        {typeof data.before === 'string'
                          ? (incidentStatuses[data.before as keyof typeof incidentStatuses] ??
                            data.before)
                          : '—'}
                        {' → '}
                        {typeof data.after === 'string'
                          ? (incidentStatuses[data.after as keyof typeof incidentStatuses] ??
                            data.after)
                          : '—'}
                        {typeof data.reason === 'string' && (
                          <span className="incident-note"> · {data.reason}</span>
                        )}
                      </p>
                    )}
                    {entry.kind === 'note_added' && typeof data.body === 'string' && (
                      <p className="incident-note">{data.body}</p>
                    )}
                    {typeof data.alert_id === 'string' && typeof data.event_id === 'string' && (
                      <AlertEvidenceButton
                        alertId={data.alert_id}
                        onEvent={onEvent}
                        label="Otwórz zdarzenie z osi czasu"
                      />
                    )}
                    <details>
                      <summary>Pełny zapis działania</summary>
                      <JsonView value={entry.data} />
                    </details>
                  </li>
                );
              })}
            </ol>
            <Pagination {...resource.pagination} />
          </>
        ) : (
          <Empty title="Brak wpisów na osi czasu" />
        ))}
    </Panel>
  );
}
