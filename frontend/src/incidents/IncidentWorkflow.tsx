import { useState } from 'react';
import type { FormEvent } from 'react';
import { ErrorNotice, Panel } from '../components';
import type { Me } from '../types';
import { incidentsApi } from './api';
import { incidentSeverities, incidentStatuses, parseTags, permittedStatuses } from './labels';
import type { IncidentDetail, IncidentPatch, IncidentStatus } from './types';
import type { IncidentMutation } from './useIncident';
import { IncidentOwner } from './IncidentOwner';

export function IncidentWorkflow({
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
  const editable = user.permissions.includes('incidents:edit');
  const closed = incident.status === 'closed';
  return (
    <>
      {editable && !closed && (
        <IncidentEditor incident={incident} disabled={disabled} mutate={mutate} />
      )}
      {closed && (
        <div className="notice">
          Sprawa jest zamknięta. Można dopisać końcową notatkę; dalsza analiza wymaga ponownego
          otwarcia przez kierownika SOC lub administratora.
        </div>
      )}
      {editable && (!closed || user.permissions.includes('incidents:reopen')) && (
        <StatusEditor incident={incident} user={user} disabled={disabled} mutate={mutate} />
      )}
      {!closed &&
        (user.permissions.includes('incidents:assign_self') ||
          user.permissions.includes('incidents:assign_any')) && (
          <IncidentOwner incident={incident} user={user} disabled={disabled} mutate={mutate} />
        )}
    </>
  );
}

function IncidentEditor({
  incident,
  disabled,
  mutate,
}: {
  incident: IncidentDetail;
  disabled: boolean;
  mutate: IncidentMutation;
}) {
  const [error, setError] = useState<unknown>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    setError(null);
    try {
      const body: IncidentPatch = {
        title: String(fields.get('title')).trim(),
        description: String(fields.get('description')).trim(),
        severity: String(fields.get('severity')) as IncidentDetail['severity'],
        tags: parseTags(String(fields.get('tags'))),
      };
      if (!body.title) throw new Error('Podaj tytuł incydentu.');
      const changed = Object.fromEntries(
        Object.entries(body).filter(
          ([key, value]) =>
            JSON.stringify(value) !== JSON.stringify(incident[key as keyof IncidentDetail]),
        ),
      ) as IncidentPatch;
      if (!Object.keys(changed).length) throw new Error('Zmień co najmniej jedno pole.');
      await mutate((version) => incidentsApi.patch(incident.id, changed, version));
    } catch (failure) {
      setError(failure);
    }
  }
  return (
    <Panel title="Opis, waga i tagi">
      <ErrorNotice error={error} />
      <form onSubmit={(event) => void submit(event)}>
        <fieldset disabled={disabled}>
          <label>
            Tytuł incydentu
            <input name="title" required maxLength={256} defaultValue={incident.title} />
          </label>
          <label>
            Opis incydentu
            <textarea name="description" maxLength={10000} defaultValue={incident.description} />
          </label>
          <label>
            Waga incydentu
            <select name="severity" defaultValue={incident.severity}>
              {Object.entries(incidentSeverities).map(([value, title]) => (
                <option value={value} key={value}>
                  {title}
                </option>
              ))}
            </select>
          </label>
          <label>
            Tagi · rozdziel przecinkami
            <input name="tags" maxLength={1299} defaultValue={incident.tags.join(', ')} />
          </label>
          <button type="submit">Zapisz opis, wagę i tagi</button>
        </fieldset>
      </form>
    </Panel>
  );
}

function StatusEditor({
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
  const [status, setStatus] = useState<IncidentStatus>(
    incident.status === 'closed' ? 'investigating' : incident.status,
  );
  const [reason, setReason] = useState('');
  const [error, setError] = useState<unknown>(null);
  const reasonRequired =
    ['contained', 'resolved', 'closed'].includes(status) ||
    (status === 'investigating' && ['resolved', 'closed'].includes(incident.status));
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (reasonRequired && !reason.trim()) {
      setError(new Error('Podaj uzasadnienie zmiany statusu.'));
      return;
    }
    const result = await mutate((version) =>
      incidentsApi.patch(
        incident.id,
        { status, ...(reason.trim() ? { status_reason: reason.trim() } : {}) },
        version,
      ),
    );
    if (result) setReason('');
  }
  return (
    <Panel title={incident.status === 'closed' ? 'Ponowne otwarcie' : 'Status sprawy'}>
      <ErrorNotice error={error} />
      <form onSubmit={(event) => void submit(event)}>
        <fieldset disabled={disabled}>
          <label>
            Status incydentu
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value as IncidentStatus)}
            >
              {Object.entries(incidentStatuses)
                .filter(([value]) => {
                  return (
                    value === incident.status ||
                    permittedStatuses(incident.status, user.permissions).includes(
                      value as IncidentStatus,
                    )
                  );
                })
                .map(([value, title]) => (
                  <option value={value} key={value}>
                    {title}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Uzasadnienie zmiany statusu
            <input
              value={reason}
              required={reasonRequired}
              maxLength={1000}
              onChange={(event) => setReason(event.target.value)}
            />
          </label>
          <button type="submit" disabled={status === incident.status}>
            {incident.status === 'closed' ? 'Otwórz ponownie' : 'Zmień status'}
          </button>
        </fieldset>
      </form>
    </Panel>
  );
}
