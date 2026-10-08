import { useState } from 'react';
import { ErrorNotice } from '../components';
import type { Me } from '../types';
import type { SigmaScope } from '../sigma/useSigmaScope';
import type { Actions, Definition, Playbook } from './types';
import { actionLabel } from './types';
import { useSoarMutation } from './useSoarMutation';

export function PlaybookEditor({
  user,
  scope,
  actions,
  book,
  onSaved,
  onClose,
}: {
  user: Me;
  scope: SigmaScope;
  actions: Actions;
  book?: Playbook;
  onSaved: () => void;
  onClose: () => void;
}) {
  const [title, setTitle] = useState(book?.definition.title ?? 'Reakcja na podejrzany adres IP');
  const [description, setDescription] = useState(
    book?.definition.description ?? 'Lokalna analiza alertu i plan reakcji.',
  );
  const [steps, setSteps] = useState(
    book?.definition.steps.map((s) => s.action) ?? [
      'enrich_ip',
      'check_threat_intelligence',
      'calculate_risk',
      'create_incident',
      'notify_analyst',
      'simulate_block_ip',
    ],
  );
  const mutation = useSoarMutation(user, scope);
  return (
    <form
      className="soar-editor"
      onSubmit={(event) => {
        event.preventDefault();
        const body: Definition = {
          schema_version: 1,
          title: title.trim(),
          description: description.trim(),
          steps: steps.map((action, index) => ({ id: `step_${index + 1}`, action })),
        };
        void mutation
          .send<Playbook>(
            book ? `/playbooks/${book.id}/versions` : '/playbooks',
            body,
            book ? { headers: { 'If-Match': `"${book.version}"` } } : {},
          )
          .then((result) => {
            if (result) onSaved();
          });
      }}
    >
      <h3>{book ? 'Nowa wersja procedury' : 'Nowa procedura'}</h3>
      <label>
        Nazwa
        <input required maxLength={128} value={title} onChange={(e) => setTitle(e.target.value)} />
      </label>
      <label>
        Opis
        <input
          maxLength={1024}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </label>
      <ol>
        {steps.map((action, index) => (
          <li key={index}>
            <label>
              Krok {index + 1}
              <select
                value={action}
                onChange={(e) =>
                  setSteps((values) => values.map((v, i) => (i === index ? e.target.value : v)))
                }
              >
                {actions.actions.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              disabled={index === 0 || mutation.pending}
              aria-label={`Przesuń krok ${index + 1} w górę`}
              onClick={() =>
                setSteps((values) => {
                  const next = [...values];
                  [next[index - 1], next[index]] = [next[index], next[index - 1]];
                  return next;
                })
              }
            >
              ↑
            </button>
            <button
              type="button"
              disabled={steps.length === 1 || mutation.pending}
              aria-label={`Usuń krok ${index + 1}: ${actionLabel[action]}`}
              onClick={() => setSteps((values) => values.filter((_, i) => i !== index))}
            >
              Usuń
            </button>
          </li>
        ))}
      </ol>
      <div className="button-row">
        <button
          type="button"
          disabled={steps.length >= 20 || mutation.pending}
          onClick={() => setSteps((values) => [...values, 'notify_analyst'])}
        >
          Dodaj krok
        </button>
        <button disabled={mutation.pending || !title.trim()}>Zapisz wersję roboczą</button>
        <button type="button" onClick={onClose} disabled={mutation.pending}>
          Zamknij edytor
        </button>
      </div>
      <p>Publikacja wymaga osobnego wyboru. Rozpoczęte wykonania zachowają wcześniejszą wersję.</p>
      <ErrorNotice error={mutation.error} />
    </form>
  );
}
