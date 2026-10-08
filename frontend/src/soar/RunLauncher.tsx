import { useRef, useState } from 'react';
import { Badge, ErrorNotice, Loading } from '../components';
import type { Me } from '../types';
import { useSigmaResource } from '../sigma/useSigmaResource';
import type { SigmaScope } from '../sigma/useSigmaScope';
import type { Playbook, Run, Targets } from './types';
import { actionLabel } from './types';
import { useSoarMutation } from './useSoarMutation';

export function RunLauncher({
  user,
  scope,
  books,
  alertId,
  replay,
  onRun,
}: {
  user: Me;
  scope: SigmaScope;
  books: Playbook[];
  alertId: string;
  replay?: Run;
  onRun: (id: string) => void;
}) {
  const targets = useSigmaResource<Targets>(`/playbook-targets/${alertId}`, scope);
  const [bookId, setBookId] = useState(replay?.playbook_id ?? '');
  const [eventId, setEventId] = useState(replay?.context.event_id ?? '');
  const [ipField, setIpField] = useState<'source' | 'destination'>(
    replay?.context.ip_field ?? 'source',
  );
  const [approved, setApproved] = useState(false);
  const receipt = useRef({ body: '', key: '' });
  const mutation = useSoarMutation(user, scope);
  const available = books.filter(
    (book) =>
      book.enabled &&
      book.published_revision &&
      book.required_permissions.every((p) => user.permissions.includes(p)),
  );
  const book = available.find((item) => item.id === bookId);
  const target = targets.data?.items.find(
    (item) => item.event_id === (eventId || targets.data?.anchor_event_id),
  );
  return (
    <section className="soar-launcher" aria-label="Uruchomienie procedury">
      <h3>{replay ? 'Ponowienie zatrzymanej procedury' : 'Uruchom procedurę z alertu'}</h3>
      <Badge>SIMULATION</Badge>
      <ErrorNotice error={targets.error ?? mutation.error} />
      {targets.pending && <Loading />}
      {targets.data && (
        <>
          <p>
            {targets.data.title} · {targets.data.mode}
          </p>
          <small>
            Alert: {alertId}
            <br />
            Dataset: {targets.data.dataset_id}
            <br />
            Przebieg danych: {targets.data.data_run_id}
          </small>
          <label>
            Opublikowana procedura
            <select
              value={bookId}
              disabled={mutation.pending}
              onChange={(e) => {
                setBookId(e.target.value);
                setApproved(false);
              }}
            >
              <option value="">Wybierz procedurę</option>
              {available
                .filter(
                  (b) =>
                    !replay ||
                    (b.id === replay.playbook_id && b.published_revision === replay.revision),
                )
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.published_definition?.title} · wersja {item.published_revision}
                  </option>
                ))}
            </select>
          </label>
          {!available.length && (
            <p>
              Brak dostępnej opublikowanej procedury. Kierownik SOC może ją przygotować w panelu
              Procedury SOAR.
            </p>
          )}
          <label>
            Zdarzenie źródłowe
            <select
              value={target?.event_id ?? ''}
              disabled={mutation.pending || !!replay}
              onChange={(e) => {
                setEventId(e.target.value);
                setApproved(false);
              }}
            >
              {targets.data.items.map((item) => (
                <option value={item.event_id} key={item.event_id}>
                  {item.timestamp} · {item.host ?? 'Brak hosta'} · {item.event_id}
                </option>
              ))}
            </select>
          </label>
          <label>
            Adres do analizy
            <select
              value={ipField}
              disabled={mutation.pending || !!replay}
              onChange={(e) => {
                setIpField(e.target.value as 'source' | 'destination');
                setApproved(false);
              }}
            >
              <option value="source">Źródłowy: {target?.source_ip ?? 'brak IP w dowodzie'}</option>
              <option value="destination">
                Docelowy: {target?.destination_ip ?? 'brak IP w dowodzie'}
              </option>
            </select>
          </label>
          {book && (
            <>
              <h4>Planowane kroki — wersja {book.published_revision}</h4>
              <ol>
                {book.published_definition?.steps.map((step) => (
                  <li key={step.id}>{actionLabel[step.action] ?? step.action}</li>
                ))}
              </ol>
              <p>
                Incydent i lokalne powiadomienie mogą zostać zapisane w aplikacji. Nowy IOC
                pozostanie nieaktywny; dla danych replay jest symulowany. Blokada IP, izolacja hosta
                i webhook są wyłącznie symulacją.
              </p>
              {replay && (
                <p>
                  To nowe wykonanie. Wcześniejsze skutki zostaną zachowane, a powiadomienie może
                  powstać ponownie.
                </p>
              )}
              <label>
                <input
                  type="checkbox"
                  checked={approved}
                  disabled={mutation.pending}
                  onChange={(e) => setApproved(e.target.checked)}
                />
                Znam planowane efekty w aplikacji i chcę uruchomić tę wersję.
              </label>
              <button
                disabled={!approved || !target || mutation.pending}
                onClick={() => {
                  const body = {
                    revision: book.published_revision,
                    alert_id: alertId,
                    event_id: target!.event_id,
                    ip_field: ipField,
                    execution_mode: 'simulation',
                    replay_of: replay?.id ?? null,
                  };
                  const fingerprint = JSON.stringify({ book: book.id, body });
                  if (receipt.current.body !== fingerprint)
                    receipt.current = { body: fingerprint, key: crypto.randomUUID() };
                  void mutation
                    .send<Run>(`/playbooks/${book.id}/runs`, body, {
                      headers: { 'Idempotency-Key': receipt.current.key },
                    })
                    .then((result) => {
                      if (result) {
                        setApproved(false);
                        onRun(result.id);
                      }
                    });
                }}
              >
                {mutation.pending ? 'Zapisywanie wykonania…' : 'Uruchom w trybie SIMULATION'}
              </button>
            </>
          )}
        </>
      )}
    </section>
  );
}
