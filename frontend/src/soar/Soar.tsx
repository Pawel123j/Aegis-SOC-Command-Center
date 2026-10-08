import { useState } from 'react';
import { Badge, Empty, ErrorNotice, Loading, Panel } from '../components';
import type { Me, Page } from '../types';
import { time } from '../utilities';
import { useSigmaScope } from '../sigma/useSigmaScope';
import type { SigmaScope } from '../sigma/useSigmaScope';
import { useSigmaResource } from '../sigma/useSigmaResource';
import type { Actions, Notification, Playbook, RunSummary } from './types';
import { actionLabel, canReadSoar, stateLabel } from './types';
import { PlaybookEditor } from './PlaybookEditor';
import { RunDetails } from './RunDetails';
import { RunLauncher } from './RunLauncher';
import { useSoarMutation } from './useSoarMutation';
import './soar.css';

export function Soar({ user }: { user: Me }) {
  return canReadSoar(user.permissions) ? (
    <SoarWorkspace key={`${user.id}:${user.role}:${user.permissions.join(',')}`} user={user} />
  ) : null;
}

function SoarWorkspace({ user }: { user: Me }) {
  const scope = useSigmaScope();
  const books = useSigmaResource<{ items: Playbook[] }>('/playbooks', scope);
  const actions = useSigmaResource<Actions>('/playbooks/actions', scope);
  const mutation = useSoarMutation(user, scope);
  const [editing, setEditing] = useState<Playbook | 'new' | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState('procedures');
  const manager = user.permissions.includes('playbooks:manage');
  if (scope.expired)
    return (
      <p role="status">Sesja zmieniła się. Otwórz ponownie panel procedur po sprawdzeniu konta.</p>
    );
  return (
    <div className="soar-workspace">
      <p className="notice">
        <strong>SIMULATION</strong> · Procedury analizują rzeczywiste alerty i mogą zapisywać
        lokalne efekty. Blokowanie IP, izolacja komputera i webhooki są symulowane.
      </p>
      <div className="button-row">
        {['procedures', 'history', 'inbox'].map((value, i) => (
          <button key={value} aria-pressed={tab === value} onClick={() => setTab(value)}>
            {['Procedury', 'Historia wykonań', 'Moje powiadomienia'][i]}
          </button>
        ))}
      </div>
      <ErrorNotice error={books.error ?? actions.error ?? mutation.error} />
      {(books.pending || actions.pending) && <Loading />}
      {selected && (
        <RunDetails
          key={selected}
          id={selected}
          user={user}
          scope={scope}
          books={books.data?.items ?? []}
          onRun={setSelected}
          onClose={() => setSelected(null)}
        />
      )}
      {tab === 'procedures' && (
        <Panel
          title="Procedury reagowania"
          aside={
            <button onClick={books.reload} disabled={books.pending}>
              Odśwież procedury
            </button>
          }
        >
          <p>Uruchomienie jest dostępne w szczegółach alertu, po przeglądzie planowanych kroków.</p>
          {manager && (
            <button onClick={() => setEditing('new')} disabled={!!editing || !actions.data}>
              Nowa procedura
            </button>
          )}
          {editing && actions.data && (
            <PlaybookEditor
              key={editing === 'new' ? 'new' : editing.id}
              user={user}
              scope={scope}
              actions={actions.data}
              book={editing === 'new' ? undefined : editing}
              onClose={() => setEditing(null)}
              onSaved={() => {
                setEditing(null);
                books.reload();
              }}
            />
          )}
          {books.data?.items.length === 0 && (
            <Empty title="Brak procedur">
              Kierownik SOC lub administrator może przygotować i opublikować pierwszą procedurę.
            </Empty>
          )}
          {books.data?.items.map((book) => (
            <article className="soar-book" key={book.id}>
              <h3>{book.definition.title}</h3>
              <p>{book.definition.description}</p>
              <Badge>{book.enabled ? 'Włączona' : 'Wyłączona'}</Badge>
              <p>
                Ostatnia wersja: {book.latest_revision} · Opublikowana:{' '}
                {book.published_revision ?? 'brak'}
              </p>
              <ol>
                {book.definition.steps.map((step) => (
                  <li key={step.id}>{actionLabel[step.action] ?? step.action}</li>
                ))}
              </ol>
              {book.published_revision !== book.latest_revision && (
                <p>Widoczna najnowsza wersja oczekuje na publikację.</p>
              )}
              {manager && (
                <div className="button-row">
                  <button disabled={mutation.pending || !!editing} onClick={() => setEditing(book)}>
                    Edytuj jako nową wersję
                  </button>
                  <button
                    disabled={mutation.pending || book.published_revision === book.latest_revision}
                    onClick={() => {
                      void mutation
                        .send<Playbook>(
                          `/playbooks/${book.id}/publish`,
                          { revision: book.latest_revision },
                          { headers: { 'If-Match': `"${book.version}"` } },
                        )
                        .then((result) => {
                          if (result) books.reload();
                        });
                    }}
                  >
                    Opublikuj wersję {book.latest_revision}
                  </button>
                  <button
                    disabled={mutation.pending}
                    onClick={() => {
                      void mutation
                        .send<Playbook>(
                          `/playbooks/${book.id}`,
                          { enabled: !book.enabled },
                          { method: 'PATCH', headers: { 'If-Match': `"${book.version}"` } },
                        )
                        .then((result) => {
                          if (result) books.reload();
                        });
                    }}
                  >
                    {book.enabled ? 'Wyłącz procedurę' : 'Włącz procedurę'}
                  </button>
                </div>
              )}
            </article>
          ))}
        </Panel>
      )}
      {tab === 'history' && <RunHistory scope={scope} onRun={setSelected} />}
      {tab === 'inbox' && <Inbox user={user} scope={scope} onRun={setSelected} />}
    </div>
  );
}

function RunHistory({ scope, onRun }: { scope: SigmaScope; onRun: (id: string) => void }) {
  const [mode, setMode] = useState('live');
  const [dataset, setDataset] = useState('');
  const [dataRun, setDataRun] = useState('');
  const [filter, setFilter] = useState('mode=live');
  return (
    <Panel title="Historia wykonań">
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          const query = new URLSearchParams({ mode });
          if (mode === 'replay') {
            query.set('dataset_id', dataset);
            query.set('data_run_id', dataRun);
          }
          setFilter(query.toString());
        }}
      >
        <label>
          Dane
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="live">Bieżące</option>
            <option value="replay">Replay</option>
          </select>
        </label>
        {mode === 'replay' && (
          <>
            <label>
              Dataset
              <input required value={dataset} onChange={(e) => setDataset(e.target.value)} />
            </label>
            <label>
              Przebieg danych
              <input required value={dataRun} onChange={(e) => setDataRun(e.target.value)} />
            </label>
          </>
        )}
        <button>Zastosuj zakres</button>
      </form>
      <HistoryPage key={filter} filter={filter} scope={scope} onRun={onRun} />
    </Panel>
  );
}

function HistoryPage({
  filter,
  scope,
  onRun,
}: {
  filter: string;
  scope: SigmaScope;
  onRun: (id: string) => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const resource = useSigmaResource<Page<RunSummary>>(
    `/playbook-runs?${filter}${cursor ? `&before=${cursor}` : ''}`,
    scope,
  );
  return (
    <>
      <button
        onClick={() => {
          setCursor(null);
          resource.reload();
        }}
        disabled={resource.pending}
      >
        Odśwież historię
      </button>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      <p>
        Wyświetlony zakres: {new URLSearchParams(filter).get('mode')}
        {new URLSearchParams(filter).get('mode') === 'replay' &&
          ` · ${new URLSearchParams(filter).get('dataset_id')} · ${new URLSearchParams(filter).get('data_run_id')}`}
      </p>
      {resource.data && !resource.data.items.length && (
        <Empty title="Brak wykonań w tym zakresie">Uruchom procedurę ze szczegółów alertu.</Empty>
      )}
      <ul className="soar-history">
        {resource.data?.items.map((row) => (
          <li key={row.id}>
            <button onClick={() => onRun(row.id)}>
              {stateLabel[row.state]} · {time(row.created_at)}
            </button>
            <small>
              Alert: {row.alert_id} · {row.mode}
            </small>
          </li>
        ))}
      </ul>
      {resource.data?.next_cursor && (
        <button onClick={() => setCursor(resource.data!.next_cursor)}>Starsze wykonania</button>
      )}
    </>
  );
}

function Inbox({
  user,
  scope,
  onRun,
}: {
  user: Me;
  scope: SigmaScope;
  onRun: (id: string) => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const resource = useSigmaResource<Page<Notification>>(
    `/soar-notifications${cursor ? `?before=${cursor}` : ''}`,
    scope,
  );
  const mutation = useSoarMutation(user, scope);
  return (
    <Panel
      title="Moje powiadomienia z procedur"
      aside={
        <button
          onClick={() => {
            setCursor(null);
            resource.reload();
          }}
        >
          Odśwież powiadomienia
        </button>
      }
    >
      <ErrorNotice error={resource.error ?? mutation.error} />
      {resource.pending && <Loading />}
      {resource.data?.items.length === 0 && (
        <Empty title="Brak powiadomień">Pojawią się tutaj wyniki kroku powiadomienia.</Empty>
      )}
      <ul className="soar-history">
        {resource.data?.items.map((row) => (
          <li key={row.id}>
            <p>{row.message}</p>
            <small>
              {time(row.created_at)} · {row.read_at ? 'Przeczytane' : 'Nieprzeczytane'}
            </small>
            <div className="button-row">
              <button onClick={() => onRun(row.run_id)}>Otwórz przebieg</button>
              {!row.read_at && (
                <button
                  disabled={mutation.pending}
                  onClick={() => {
                    void mutation.send(`/soar-notifications/${row.id}/read`, {}).then((result) => {
                      if (result) resource.reload();
                    });
                  }}
                >
                  Oznacz jako przeczytane
                </button>
              )}
            </div>
          </li>
        ))}
      </ul>
      {resource.data?.next_cursor && (
        <button onClick={() => setCursor(resource.data!.next_cursor)}>Starsze powiadomienia</button>
      )}
    </Panel>
  );
}

export function AlertSoar({ user, alertId }: { user: Me; alertId: string }) {
  const [open, setOpen] = useState(false);
  if (!canReadSoar(user.permissions)) return null;
  return (
    <section>
      <button onClick={() => setOpen((value) => !value)}>
        {open ? 'Zwiń procedury SOAR' : 'Procedury SOAR dla alertu'}
      </button>
      {open && (
        <AlertWorkflow
          key={`${alertId}:${user.id}:${user.role}:${user.permissions.join(',')}`}
          user={user}
          alertId={alertId}
        />
      )}
    </section>
  );
}

function AlertWorkflow({ user, alertId }: { user: Me; alertId: string }) {
  const scope = useSigmaScope();
  const books = useSigmaResource<{ items: Playbook[] }>('/playbooks', scope);
  const [selected, setSelected] = useState<string | null>(null);
  if (scope.expired) return <p>Sesja zmieniła się. Otwórz ponownie procedury dla alertu.</p>;
  return (
    <>
      <ErrorNotice error={books.error} />
      {books.pending && <Loading />}
      {books.data && user.permissions.includes('playbooks:run') && !selected && (
        <RunLauncher
          user={user}
          scope={scope}
          books={books.data.items}
          alertId={alertId}
          onRun={setSelected}
        />
      )}
      {selected && (
        <RunDetails
          key={selected}
          id={selected}
          user={user}
          scope={scope}
          books={books.data?.items ?? []}
          onRun={setSelected}
          onClose={() => setSelected(null)}
        />
      )}
      <p>Pełna historia wykonań jest dostępna w panelu Procedury SOAR.</p>
    </>
  );
}
