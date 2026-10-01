import { useCallback, useState } from 'react';
import type { FormEvent } from 'react';
import { Empty, ErrorNotice, Loading, Panel } from '../components';
import { time } from '../utilities';
import { incidentsApi } from './api';
import { Pagination } from './Pagination';
import type { IncidentDetail } from './types';
import type { IncidentMutation } from './useIncident';
import { usePage } from './usePage';

export function IncidentNotes({
  incident,
  editable,
  disabled,
  mutate,
}: {
  incident: IncidentDetail;
  editable: boolean;
  disabled: boolean;
  mutate: IncidentMutation;
}) {
  const { id, version } = incident;
  const loader = useCallback(
    (cursor: string | null) => {
      void version;
      return incidentsApi.notes(id, cursor);
    },
    [id, version],
  );
  const resource = usePage(loader);
  const [body, setBody] = useState('');
  const [error, setError] = useState<unknown>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (!body.trim()) {
      setError(new Error('Wpisz treść notatki.'));
      return;
    }
    const result = await mutate((currentVersion) =>
      incidentsApi.note(id, body.trim(), currentVersion),
    );
    if (result) setBody('');
  }
  return (
    <Panel title="Notatki analityków">
      {editable && (
        <form onSubmit={(event) => void submit(event)}>
          <fieldset disabled={disabled}>
            <label>
              Nowa notatka
              <textarea
                value={body}
                onChange={(event) => setBody(event.target.value)}
                maxLength={5000}
                required
                rows={4}
              />
            </label>
            <button type="submit">Dodaj notatkę</button>
          </fieldset>
          <ErrorNotice error={error} />
        </form>
      )}
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data &&
        !resource.error &&
        (resource.data.items.length ? (
          <>
            {resource.data.items.map((note) => (
              <article className="incident-note-card" key={note.id}>
                <small>
                  {note.author?.username ?? 'System'} · {time(note.created_at)}
                </small>
                <p className="incident-note">{note.body}</p>
              </article>
            ))}
            <Pagination {...resource.pagination} />
          </>
        ) : (
          <Empty title="Brak notatek">Zapisz ustalenia z analizy i podjęte działania.</Empty>
        ))}
    </Panel>
  );
}
