import { useCallback } from 'react';
import type { FormEvent } from 'react';
import { ErrorNotice, Loading, Panel } from '../components';
import type { Me } from '../types';
import { useResource } from '../utilities';
import { incidentsApi } from './api';
import type { IncidentDetail } from './types';
import type { IncidentMutation } from './useIncident';

export function IncidentOwner({
  incident,
  user,
  disabled,
  mutate,
}: {
  incident: IncidentDetail;
  user: Me;
  disabled: boolean;
  mutate: IncidentMutation;
}) {
  if (!user.permissions.includes('incidents:assign_any'))
    return (
      <Panel title="Przypisanie analityka">
        <p className="muted">Możesz przejąć prowadzenie tego incydentu.</p>
        <button
          disabled={disabled}
          onClick={() => {
            void mutate((version) =>
              incidentsApi.patch(
                incident.id,
                { owner_id: incident.owner_id === user.id ? null : user.id },
                version,
              ),
            );
          }}
        >
          {incident.owner_id === user.id ? 'Zwolnij moje przypisanie' : 'Przypisz do mnie'}
        </button>
      </Panel>
    );
  return <OwnerDirectory incident={incident} disabled={disabled} mutate={mutate} />;
}

function OwnerDirectory({
  incident,
  disabled,
  mutate,
}: {
  incident: IncidentDetail;
  disabled: boolean;
  mutate: IncidentMutation;
}) {
  const loader = useCallback(() => incidentsApi.assignees(), []);
  const resource = useResource(loader);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    const ownerId = String(fields.get('owner')) || null;
    if (ownerId === incident.owner_id) return;
    await mutate((version) => incidentsApi.patch(incident.id, { owner_id: ownerId }, version));
  }
  return (
    <Panel title="Przypisanie analityka">
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      <form onSubmit={(event) => void submit(event)}>
        <fieldset disabled={disabled || resource.pending || Boolean(resource.error)}>
          <label>
            Analityk prowadzący
            <select name="owner" defaultValue={incident.owner_id ?? ''} key={incident.owner_id}>
              <option value="">Nieprzypisany</option>
              {incident.owner &&
                !resource.data?.items.some((item) => item.id === incident.owner_id) && (
                  <option value={incident.owner.id} disabled>
                    {incident.owner.username} · obecne przypisanie
                  </option>
                )}
              {resource.data?.items.map((person) => (
                <option value={person.id} key={person.id}>
                  {person.username}
                </option>
              ))}
            </select>
          </label>
          <button type="submit">Zapisz przypisanie</button>
        </fieldset>
      </form>
    </Panel>
  );
}
