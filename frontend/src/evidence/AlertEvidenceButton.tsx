import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { ErrorNotice } from '../components';
import type { AlertDetail, SecurityEvent } from '../types';
import { EventEvidence } from './EventEvidence';
import { evidenceEvents } from './events';
import { EventReason } from './EventReason';

export function AlertEvidenceButton({
  alertId,
  onEvent,
  label = 'Otwórz dowód',
}: {
  alertId: string;
  onEvent: (event: SecurityEvent) => void;
  label?: string;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const generation = useRef(0);
  useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  async function open() {
    if (pending) return;
    const revision = ++generation.current;
    setPending(true);
    setError(null);
    try {
      const detail = await api.get<AlertDetail>(`/alerts/${encodeURIComponent(alertId)}`);
      if (generation.current !== revision) return;
      const events = evidenceEvents(detail);
      if (events.length === 1) onEvent(events[0].event_snapshot);
      else setAlert(detail);
    } catch (failure) {
      if (generation.current === revision) setError(failure);
    } finally {
      if (generation.current === revision) setPending(false);
    }
  }
  return (
    <>
      <button className="quiet" disabled={pending} onClick={() => void open()}>
        {pending ? 'Pobieranie dowodów…' : label}
      </button>
      <ErrorNotice error={error} />
      {alert && <EvidenceDialog alert={alert} onClose={() => setAlert(null)} onEvent={onEvent} />}
    </>
  );
}

function EvidenceDialog({
  alert,
  onClose,
  onEvent,
}: {
  alert: AlertDetail;
  onClose: () => void;
  onEvent: (event: SecurityEvent) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="detail-dialog"
      aria-labelledby="evidence-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <header className="detail-header">
        <div>
          <span className="eyebrow">DOWODY ALERTU</span>
          <h2 id="evidence-title">{alert.title}</h2>
        </div>
        <button aria-label="Zamknij dowody alertu" onClick={onClose}>
          ✕
        </button>
      </header>
      <div className="detail-body">
        <EventReason reason={alert.reason} />
        <EventEvidence
          events={evidenceEvents(alert)}
          onEvent={(event) => {
            onClose();
            onEvent(event);
          }}
        />
      </div>
    </dialog>
  );
}
