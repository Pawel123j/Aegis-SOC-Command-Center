import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { ErrorNotice, Loading } from '../components';
import type { AlertDetail } from '../types';
import { useResource } from '../utilities';
import { RiskPanel } from './RiskPanel';

export function AlertRiskButton({
  alertId,
  title,
  canReadPolicy = false,
}: {
  alertId: string;
  title: string;
  canReadPolicy?: boolean;
}) {
  return <RiskButton key={alertId} alertId={alertId} title={title} canReadPolicy={canReadPolicy} />;
}

function RiskButton({
  alertId,
  title,
  canReadPolicy,
}: {
  alertId: string;
  title: string;
  canReadPolicy: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        className="quiet"
        onClick={() => setOpen(true)}
        aria-label={`Ocena ryzyka alertu: ${title}`}
      >
        Ocena ryzyka
      </button>
      {open && (
        <AlertRiskDialog
          id={alertId}
          title={title}
          onClose={() => setOpen(false)}
          canReadPolicy={canReadPolicy}
        />
      )}
    </>
  );
}

function AlertRiskDialog({
  id,
  title,
  onClose,
  canReadPolicy,
}: {
  id: string;
  title: string;
  onClose: () => void;
  canReadPolicy: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  const loader = useCallback(() => api.get<AlertDetail>(`/alerts/${encodeURIComponent(id)}`), [id]);
  const resource = useResource(loader);
  return (
    <dialog
      ref={dialog}
      className="detail-dialog"
      aria-labelledby="alert-risk-title"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <header className="detail-header">
        <div>
          <span className="eyebrow">RYZYKO ALERTU</span>
          <h2 id="alert-risk-title">{title}</h2>
        </div>
        <button aria-label="Zamknij ocenę ryzyka alertu" onClick={onClose}>
          ✕
        </button>
      </header>
      <div className="detail-body">
        <ErrorNotice error={resource.error} />
        {resource.pending && <Loading />}
        {Boolean(resource.error) && (
          <button onClick={() => void resource.reload()} disabled={resource.pending}>
            Ponów pobranie oceny
          </button>
        )}
        {resource.data && !resource.error && (
          <RiskPanel
            subject="alert"
            id={id}
            initial={resource.data.risk_explanation}
            canReadPolicy={canReadPolicy}
            onRefresh={() => void resource.reload()}
            refreshPending={resource.pending}
          />
        )}
      </div>
    </dialog>
  );
}
