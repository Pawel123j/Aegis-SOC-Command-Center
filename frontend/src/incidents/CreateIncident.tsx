import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { ErrorNotice } from '../components';
import type { Alert } from '../types';
import { incidentsApi } from './api';
import { AlertPicker } from './AlertPicker';
import { incidentSeverities, parseTags } from './labels';
import type { IncidentCreate, IncidentDetail, IncidentSeverity } from './types';

export function CreateIncident({
  initialAlert,
  onClose,
  onCreated,
}: {
  initialAlert?: Alert | null;
  onClose: () => void;
  onCreated: (incident: IncidentDetail) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const receipt = useRef<{ signature: string; key: string; body: IncidentCreate } | null>(null);
  const [selected, setSelected] = useState<Alert[]>(initialAlert ? [initialAlert] : []);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const fields = new FormData(event.currentTarget);
    setError(null);
    try {
      const body: IncidentCreate = {
        title: String(fields.get('title')).trim(),
        description: String(fields.get('description')).trim(),
        severity: String(fields.get('severity')) as IncidentSeverity,
        alert_ids: selected.map((alert) => alert.id).sort(),
        tags: parseTags(String(fields.get('tags'))),
      };
      if (!body.title) throw new Error('Podaj tytuł incydentu.');
      const signature = JSON.stringify(body);
      if (receipt.current?.signature !== signature)
        receipt.current = { signature, key: crypto.randomUUID(), body };
      setPending(true);
      const incident = await incidentsApi.create(receipt.current.body, receipt.current.key);
      receipt.current = null;
      onCreated(incident);
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <dialog
      ref={dialog}
      className="detail-dialog"
      aria-labelledby="create-incident-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!pending) onClose();
      }}
    >
      <header className="detail-header">
        <h2 id="create-incident-title">Nowy incydent</h2>
        <button onClick={onClose} disabled={pending} aria-label="Zamknij tworzenie incydentu">
          ✕
        </button>
      </header>
      <form
        className="detail-body"
        onSubmit={(event) => {
          void submit(event);
        }}
      >
        <ErrorNotice error={error} />
        <fieldset disabled={pending}>
          <label>
            Tytuł incydentu
            <input name="title" required maxLength={256} defaultValue={initialAlert?.title ?? ''} />
          </label>
          <label>
            Opis incydentu
            <textarea name="description" maxLength={10000} rows={4} />
          </label>
          <div className="form-row">
            <label>
              Waga incydentu
              <select
                name="severity"
                defaultValue={
                  initialAlert?.severity && initialAlert.severity in incidentSeverities
                    ? initialAlert.severity
                    : 'medium'
                }
              >
                {Object.entries(incidentSeverities).map(([value, title]) => (
                  <option value={value} key={value}>
                    {title}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Tagi · rozdziel przecinkami
              <input name="tags" maxLength={1299} placeholder="np. windows, analiza" />
            </label>
          </div>
          <h3>Powiązane alerty</h3>
          <AlertPicker selected={selected} onSelect={setSelected} />
          <p className="muted">
            Bez alertów powstanie pusty incydent live. Ryzyko i pewność czekają na wdrożenie
            silników oceny.
          </p>
          <div className="button-row">
            <button className="primary" type="submit">
              {pending ? 'Tworzenie…' : 'Utwórz incydent'}
            </button>
            <button type="button" onClick={onClose}>
              Anuluj
            </button>
          </div>
        </fieldset>
      </form>
    </dialog>
  );
}
