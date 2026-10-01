import { useCallback } from 'react';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from '../components';
import type { SecurityEvent } from '../types';
import { time } from '../utilities';
import { incidentsApi } from './api';
import { Pagination } from './Pagination';
import type { IncidentDetail } from './types';
import { usePage } from './usePage';
import { EventEvidence } from '../evidence/EventEvidence';
import { evidenceEvents } from '../evidence/events';
import { EventReason } from '../evidence/EventReason';

export function IncidentEvidence({
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
      return incidentsApi.evidence(id, cursor);
    },
    [id, version],
  );
  const resource = usePage(loader);
  return (
    <Panel title="Zachowane dowody">
      <p className="muted">Odpięcie alertu zachowuje jego dowód i zapis na osi czasu.</p>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data &&
        !resource.error &&
        (resource.data.items.length ? (
          <>
            {resource.data.items.map((evidence) => (
              <article className="incident-note-card" key={evidence.id}>
                <div className="detail-badges">
                  <Badge>{evidence.active ? 'Alert powiązany' : 'Alert odpięty'}</Badge>
                  <Badge>{evidence.event_snapshot.source.type}</Badge>
                </div>
                <strong>{evidence.event_snapshot.event.action}</strong>
                <small>
                  {time(evidence.event_timestamp)} · {evidence.event_snapshot.source.name}
                </small>
                <EventReason reason={evidence.reason} />
                <EventEvidence events={evidenceEvents(evidence)} onEvent={onEvent} />
                <details>
                  <summary>Pochodzenie i uzasadnienie</summary>
                  <dl className="facts">
                    <dt>Powiązano</dt>
                    <dd>{time(evidence.linked_at)}</dd>
                    <dt>Odpięto</dt>
                    <dd>{time(evidence.detached_at)}</dd>
                    <dt>Alert ID</dt>
                    <dd className="mono">{evidence.alert_id}</dd>
                    <dt>SHA-256 dowodu</dt>
                    <dd className="mono">{evidence.event_sha256}</dd>
                  </dl>
                  <JsonView value={evidence.reason} />
                  <JsonView value={evidence.rule_snapshot} />
                </details>
              </article>
            ))}
            <Pagination {...resource.pagination} />
          </>
        ) : (
          <Empty title="Brak dowodów">
            Powiąż alert, aby zachować dowód zdarzenia w tej sprawie.
          </Empty>
        ))}
    </Panel>
  );
}
