import { useEffect, useState } from 'react';
import { Badge, ErrorNotice, JsonView, Loading, Panel } from '../components';
import type { Me } from '../types';
import { time } from '../utilities';
import { useSigmaResource } from '../sigma/useSigmaResource';
import type { SigmaScope } from '../sigma/useSigmaScope';
import type { Playbook, Run } from './types';
import { actionLabel, stateLabel } from './types';
import { RunLauncher } from './RunLauncher';
import { useSoarMutation } from './useSoarMutation';

export function RunDetails({
  id,
  user,
  scope,
  books,
  onRun,
  onClose,
}: {
  id: string;
  user: Me;
  scope: SigmaScope;
  books: Playbook[];
  onRun: (id: string) => void;
  onClose: () => void;
}) {
  const resource = useSigmaResource<Run>(`/playbook-runs/${id}`, scope);
  const mutation = useSoarMutation(user, scope);
  const [replay, setReplay] = useState(false);
  const row = resource.data?.id === id ? resource.data : null;
  const active = !!row && ['queued', 'running'].includes(row.state);
  const { reload } = resource;
  useEffect(() => {
    if (!active || scope.expired) return;
    const timer = setTimeout(reload, 4000);
    return () => clearTimeout(timer);
  }, [active, scope.expired, reload, resource.data]);
  const canCancel =
    !!row &&
    user.permissions.includes('playbooks:run') &&
    (row.requested_by === user.id || user.permissions.includes('playbooks:manage'));
  return (
    <Panel title="Przebieg procedury" aside={<button onClick={onClose}>Zamknij przebieg</button>}>
      <ErrorNotice error={resource.error ?? mutation.error} />
      {resource.pending && <Loading />}
      <button onClick={reload} disabled={resource.pending}>
        Odśwież przebieg
      </button>
      {row && (
        <>
          <h3>
            {row.definition.title} · wersja {row.revision}
          </h3>
          <div className="detail-badges">
            <Badge>SIMULATION</Badge>
            <Badge>{row.mode}</Badge>
            <Badge>{stateLabel[row.state] ?? row.state}</Badge>
          </div>
          <dl className="facts">
            <dt>Alert</dt>
            <dd>
              {row.context.alert_title} · {row.alert_id}
            </dd>
            <dt>Cel</dt>
            <dd>
              {row.context.ip ?? 'Brak IP'} · {row.context.host ?? 'Brak komputera'}
            </dd>
            <dt>Utworzono / zakończono</dt>
            <dd>
              {time(row.created_at)} / {time(row.finished_at)}
            </dd>
            <dt>Inicjator</dt>
            <dd>{row.requested_by}</dd>
            <dt>Dataset / przebieg danych</dt>
            <dd>
              {row.dataset_id} / {row.data_run_id}
            </dd>
            {row.replay_of && (
              <>
                <dt>Ponowienie</dt>
                <dd>{row.replay_of}</dd>
              </>
            )}
          </dl>
          {row.error_code && (
            <p role="status">
              Procedura zatrzymana: {row.error_code}. Dotychczasowe efekty pozostają w historii.
            </p>
          )}
          {active && (
            <p>
              Aktualizacja co 4 sekundy. Najbliższa próba lub odzyskanie przerwanego kroku:{' '}
              {time(row.next_attempt_at)}. Termin zakończenia: {time(row.deadline_at)}.
            </p>
          )}
          <ol className="soar-steps">
            {row.steps.map((step) => (
              <li key={step.id}>
                <h4>{actionLabel[step.action] ?? step.action}</h4>
                <Badge>
                  {step.not_executed_reason
                    ? 'Nie wykonano'
                    : (stateLabel[step.state] ?? step.state)}
                </Badge>
                {step.output?.simulated && <Badge>SIMULATION</Badge>}
                {step.output?.local_effect && <Badge>Zapisano w aplikacji</Badge>}
                <p>
                  {step.output?.reason ??
                    step.error_code ??
                    (step.not_executed_reason
                      ? 'Wykonanie zatrzymano przed tym krokiem.'
                      : 'Oczekuje na wykonanie.')}
                </p>
                <small>
                  Liczba prób: {step.attempts} · {time(step.started_at)} / {time(step.finished_at)}
                </small>
                {step.history.length > 0 && (
                  <details>
                    <summary>Historia prób kroku</summary>
                    <ul>
                      {step.history.map((attempt) => (
                        <li key={attempt.number}>
                          Próba {attempt.number}: {stateLabel[attempt.outcome] ?? attempt.outcome} ·{' '}
                          {time(attempt.started_at)} — {time(attempt.finished_at)}{' '}
                          {attempt.error_code}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
                {step.output && (
                  <details>
                    <summary>Wynik i zachowane dowody kroku</summary>
                    <JsonView value={step.output} />
                  </details>
                )}
              </li>
            ))}
          </ol>
          {active && canCancel && (
            <button
              disabled={mutation.pending}
              onClick={() => {
                void mutation.send<Run>(`/playbook-runs/${id}/cancel`, {}).then((result) => {
                  if (result) reload();
                });
              }}
            >
              Zatrzymaj dalsze kroki
            </button>
          )}
          {!active &&
            ['failed', 'cancelled'].includes(row.state) &&
            user.permissions.includes('playbooks:run') && (
              <button onClick={() => setReplay((value) => !value)}>
                Przejrzyj plan ponowienia
              </button>
            )}
          {replay && (
            <RunLauncher
              user={user}
              scope={scope}
              books={books}
              alertId={row.alert_id}
              replay={row}
              onRun={onRun}
            />
          )}
        </>
      )}
    </Panel>
  );
}
