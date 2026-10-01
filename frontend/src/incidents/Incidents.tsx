import { useState } from 'react';
import type { FormEvent } from 'react';
import { Panel } from '../components';
import type { Alert, Me, SecurityEvent } from '../types';
import { CreateIncident } from './CreateIncident';
import { IncidentDetails } from './IncidentDetails';
import { IncidentList } from './IncidentList';
import type { IncidentFilters } from './IncidentList';
import { incidentSeverities, incidentStatuses } from './labels';
import './incidents.css';

export function Incidents({
  user,
  onEvent,
  initialAlert,
  onInitialConsumed,
}: {
  user: Me;
  onEvent: (event: SecurityEvent) => void;
  initialAlert?: Alert | null;
  onInitialConsumed: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(Boolean(initialAlert));
  const [filters, setFilters] = useState<IncidentFilters>({
    status: '',
    severity: '',
    mode: '',
    tag: '',
    owner_id: '',
  });
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    setFilters({
      status: String(fields.get('status')),
      severity: String(fields.get('severity')),
      mode: String(fields.get('mode')),
      tag: String(fields.get('tag')).trim(),
      owner_id: String(fields.get('owner_id')),
    });
  }
  if (selected)
    return (
      <IncidentDetails
        key={selected}
        id={selected}
        user={user}
        onEvent={onEvent}
        onBack={() => setSelected(null)}
      />
    );
  return (
    <>
      <div className="intro">
        <div>
          <h2>Sprawy zespołu SOC</h2>
          <p>Połącz alerty, przypisz analityka i dokumentuj przebieg obsługi.</p>
        </div>
        {user.permissions.includes('incidents:edit') && (
          <button className="primary" onClick={() => setCreating(true)}>
            Nowy incydent
          </button>
        )}
      </div>
      <Panel title="Filtrowanie spraw">
        <form className="form-row" onSubmit={filter}>
          <label>
            Status
            <select name="status" defaultValue={filters.status}>
              <option value="">Wszystkie</option>
              {Object.entries(incidentStatuses).map(([value, title]) => (
                <option value={value} key={value}>
                  {title}
                </option>
              ))}
            </select>
          </label>
          <label>
            Waga
            <select name="severity" defaultValue={filters.severity}>
              <option value="">Wszystkie</option>
              {Object.entries(incidentSeverities).map(([value, title]) => (
                <option value={value} key={value}>
                  {title}
                </option>
              ))}
            </select>
          </label>
          <label>
            Tryb
            <select name="mode" defaultValue={filters.mode}>
              <option value="">Wszystkie</option>
              <option value="live">Live</option>
              <option value="replay">Replay</option>
            </select>
          </label>
          <label>
            Prowadzący
            <select name="owner_id" defaultValue={filters.owner_id}>
              <option value="">Wszyscy</option>
              <option value={user.id}>Przypisane do mnie</option>
            </select>
          </label>
          <label>
            Tag
            <input name="tag" maxLength={64} placeholder="np. windows" defaultValue={filters.tag} />
          </label>
          <button type="submit">Filtruj</button>
        </form>
      </Panel>
      <IncidentList key={JSON.stringify(filters)} filters={filters} onSelect={setSelected} />
      {creating && user.permissions.includes('incidents:edit') && (
        <CreateIncident
          initialAlert={initialAlert}
          onClose={() => {
            setCreating(false);
            onInitialConsumed();
          }}
          onCreated={(incident) => {
            setCreating(false);
            setSelected(incident.id);
            onInitialConsumed();
          }}
        />
      )}
    </>
  );
}
