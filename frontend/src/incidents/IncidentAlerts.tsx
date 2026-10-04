import { useState } from 'react';
import { Badge, Empty, Panel } from '../components';
import type { Alert, SecurityEvent } from '../types';
import { AlertEvidenceButton } from '../evidence/AlertEvidenceButton';
import { time, statusName } from '../utilities';
import { incidentsApi } from './api';
import { AlertPicker } from './AlertPicker';
import type { IncidentDetail } from './types';
import type { IncidentMutation } from './useIncident';
import { AlertRiskButton } from '../risk/AlertRiskButton';
import { RiskScore } from '../risk/RiskScore';

export function IncidentAlerts({
  incident,
  editable,
  disabled,
  mutate,
  onEvent,
  riskReadable,
  policyReadable,
}: {
  incident: IncidentDetail;
  editable: boolean;
  disabled: boolean;
  mutate: IncidentMutation;
  onEvent: (event: SecurityEvent) => void;
  riskReadable: boolean;
  policyReadable: boolean;
}) {
  const [adding, setAdding] = useState(false);
  const [selected, setSelected] = useState<Alert[]>([]);
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
                <th>Ryzyko</th>
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
                    {alert.detection_type === 'correlation' && (
                      <small>Korelacja · liczba zdarzeń: {alert.event_count}</small>
                    )}
                    {alert.detection_type === 'sigma' && <Badge>Sigma</Badge>}
                  </td>
                  <td>
                    <Badge tone={alert.severity}>{alert.severity}</Badge>
                    <small>{statusName[alert.status]}</small>
                  </td>
                  <td>
                    <RiskScore score={alert.risk_score} level={alert.risk_level} />
                    {riskReadable && (
                      <div>
                        <AlertRiskButton
                          alertId={alert.id}
                          title={alert.title}
                          canReadPolicy={policyReadable}
                        />
                      </div>
                    )}
                  </td>
                  <td>
                    <AlertEvidenceButton alertId={alert.id} onEvent={onEvent} />
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
