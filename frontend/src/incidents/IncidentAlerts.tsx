import { useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Panel } from '../components';
import type { Alert, AlertDetail, SecurityEvent } from '../types';
import { time, statusName } from '../utilities';
import { incidentsApi } from './api';
import { AlertPicker } from './AlertPicker';
import type { IncidentDetail } from './types';
import type { IncidentMutation } from './useIncident';

export function IncidentAlerts({
  incident,
  editable,
  disabled,
  mutate,
  onEvent,
}: {
  incident: IncidentDetail;
  editable: boolean;
  disabled: boolean;
  mutate: IncidentMutation;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<Alert[]>([]);
  const [opening, setOpening] = useState(false);
  const [error, setError] = useState<unknown>(null);
  async function open(alertId: string) {
    setOpening(true);
    setError(null);
    try {
      const alert = await api.get<AlertDetail>(`/alerts/${encodeURIComponent(alertId)}`);
      onEvent(alert.event_snapshot);
    } catch (failure) {
      setError(failure);
    } finally {
      setOpening(false);
    }
  }
  async function attach() {
    if (!selected[0]) return;
    const result = await mutate((version) =>
      incidentsApi.attach(incident.id, selected[0].id, version),
    );
    if (result) {
      setSelected([]);
      setAdding(false);
    }
  }
  return (
    <Panel
      title="Powiązane alerty"
      aside={
        editable && (
          <button disabled={disabled} onClick={() => setAdding((value) => !value)}>
            {adding ? 'Anuluj powiązanie' : 'Powiąż alert'}
          </button>
        )
      }
    >
      <ErrorNotice error={error} />
      {editable && adding && (
        <fieldset disabled={disabled}>
          <AlertPicker
            single
            scope={incident}
            selected={selected}
            onSelect={setSelected}
            exclude={incident.related_alerts.map((alert) => alert.id)}
          />
          <button className="primary" disabled={!selected.length} onClick={() => void attach()}>
            Dodaj wybrany alert
          </button>
        </fieldset>
      )}
      {incident.related_alerts.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Alert / zdarzenie</th>
                <th>Waga / status</th>
                <th>Dowód</th>
                {editable && <th>Powiązanie</th>}
              </tr>
            </thead>
            <tbody>
              {incident.related_alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <strong>{alert.title}</strong>
                    <small>
                      {time(alert.event_timestamp)} · {alert.rule_id}
                    </small>
                  </td>
                  <td>
                    <Badge tone={alert.severity}>{alert.severity}</Badge>
                    <small>{statusName[alert.status]}</small>
                  </td>
                  <td>
                    <button
                      className="quiet"
                      disabled={opening}
                      onClick={() => void open(alert.id)}
                    >
                      Otwórz dowód
                    </button>
                  </td>
                  {editable && (
                    <td>
                      <button
                        className="danger-quiet"
                        disabled={disabled}
                        aria-label={`Odłącz alert: ${alert.title}`}
                        onClick={() => {
                          void mutate((version) =>
                            incidentsApi.detach(incident.id, alert.id, version),
                          );
                        }}
                      >
                        Odłącz alert
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="Brak powiązanych alertów">
          Dołącz alerty dotyczące tego samego incydentu.
        </Empty>
      )}
    </Panel>
  );
}
