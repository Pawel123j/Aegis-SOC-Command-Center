import { useCallback } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Loading, Panel } from '../components';
import type { Page } from '../types';
import { time } from '../utilities';
import { incidentSeverities, incidentStatuses } from './labels';
import { Pagination } from './Pagination';
import type { Incident } from './types';
import { usePage } from './usePage';
import { RiskScore } from '../risk/RiskScore';

export interface IncidentFilters {
  status: string;
  severity: string;
  mode: string;
  tag: string;
  owner_id: string;
}

export function IncidentList({
  filters,
  onSelect,
}: {
  filters: IncidentFilters;
  onSelect: (id: string) => void;
}) {
  const loader = useCallback(
    (cursor: string | null) =>
      api.get<Page<Incident>>(
        `/incidents?${new URLSearchParams({
          limit: '50',
          ...Object.fromEntries(Object.entries(filters).filter(([, value]) => value)),
          ...(cursor ? { cursor } : {}),
        })}`,
      ),
    [filters],
  );
  const resource = usePage(loader);
  return (
    <Panel
      title="Lista incydentów"
      aside={
        <div className="button-row">
          <span className="muted">{resource.data?.total ?? '—'} w zakresie filtrów</span>
          <button
            className="quiet"
            disabled={resource.pending}
            onClick={() => {
              void resource.reload();
            }}
          >
            Odśwież listę
          </button>
        </div>
      }
    >
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data &&
        !resource.error &&
        (resource.data.items.length ? (
          <>
            <div className="table-wrap" aria-busy={resource.pending}>
              <table>
                <thead>
                  <tr>
                    <th>Incydent</th>
                    <th>Waga / status</th>
                    <th>Ryzyko</th>
                    <th>Analityk</th>
                    <th>Alerty</th>
                    <th>Ostatnie zdarzenie</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {resource.data.items.map((incident) => (
                    <tr key={incident.id}>
                      <td>
                        <strong>{incident.title}</strong>
                        <small>
                          {incident.mode} · utworzono {time(incident.created_at)}
                        </small>
                      </td>
                      <td>
                        <Badge tone={incident.severity}>
                          {incidentSeverities[incident.severity]}
                        </Badge>
                        <small>{incidentStatuses[incident.status]}</small>
                      </td>
                      <td>
                        <RiskScore score={incident.risk_score} level={incident.risk_level} />
                      </td>
                      <td>{incident.owner?.username ?? 'Nieprzypisany'}</td>
                      <td>{incident.alert_count}</td>
                      <td className="nowrap">{time(incident.last_seen)}</td>
                      <td>
                        <button className="quiet" onClick={() => onSelect(incident.id)}>
                          Otwórz incydent
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination {...resource.pagination} />
          </>
        ) : (
          <Empty title="Brak incydentów w tym zakresie">
            Nowe alerty o wysokiej lub krytycznej wadze tworzą osobne incydenty. Możesz też utworzyć
            sprawę ręcznie i połączyć jej alerty.
          </Empty>
        ))}
    </Panel>
  );
}
