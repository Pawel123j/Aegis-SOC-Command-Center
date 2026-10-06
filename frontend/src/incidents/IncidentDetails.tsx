import { ErrorNotice, Loading } from '../components';
import type { Me, SecurityEvent } from '../types';
import { IncidentAlerts } from './IncidentAlerts';
import { IncidentEvidence } from './IncidentEvidence';
import { IncidentNotes } from './IncidentNotes';
import { IncidentSummary } from './IncidentSummary';
import { IncidentTimeline } from './IncidentTimeline';
import { IncidentWorkflow } from './IncidentWorkflow';
import { useIncident } from './useIncident';
import { RiskPanel } from '../risk/RiskPanel';
import { AttackTimeline } from './AttackTimeline';

export function IncidentDetails({
  id,
  user,
  onBack,
  onEvent,
}: {
  id: string;
  user: Me;
  onBack: () => void;
  onEvent: (event: SecurityEvent) => void;
}) {
  const resource = useIncident(id);
  const editable = user.permissions.includes('incidents:edit');
  const disabled = resource.pending || resource.blocked;
  const incident = resource.data;
  return (
    <div className="incident-header">
      <button className="quiet" onClick={onBack}>
        ← Wszystkie incydenty
      </button>
      <div className="intro">
        <div>
          <span className="eyebrow">SZCZEGÓŁY INCYDENTU</span>
          <h2>{incident?.title ?? 'Incydent'}</h2>
          <p>Dowody, przebieg analizy i ustalenia zespołu.</p>
        </div>
        <button disabled={resource.pending} onClick={() => void resource.reload()}>
          Odśwież szczegóły
        </button>
      </div>
      <ErrorNotice error={resource.error} />
      {resource.conflict && (
        <p className="notice">
          Odśwież szczegóły, aby pobrać aktualną wersję sprawy. Potem ponownie przejrzyj zmiany.
        </p>
      )}
      {resource.loading && <Loading />}
      {incident && (
        <>
          <IncidentSummary incident={incident} />
          <RiskPanel
            subject="incident"
            id={id}
            initial={incident.risk_explanation}
            canReadPolicy={user.permissions.includes('detections:read')}
            onRefresh={() => void resource.reload()}
            refreshPending={resource.pending}
          />
          <AttackTimeline
            incident={incident}
            user={user}
            onEvent={onEvent}
            onIncidentRefresh={resource.reload}
            refreshKey={resource.refreshKey}
            paused={disabled}
          />
          <div className="incident-grid">
            <div>
              <IncidentAlerts
                incident={incident}
                editable={editable && incident.status !== 'closed'}
                disabled={disabled}
                mutate={resource.mutate}
                onEvent={onEvent}
                riskReadable={user.permissions.includes('alerts:read')}
                policyReadable={user.permissions.includes('detections:read')}
              />
              <IncidentTimeline incident={incident} onEvent={onEvent} />
              <IncidentEvidence incident={incident} onEvent={onEvent} />
            </div>
            <div>
              <IncidentWorkflow
                key={resource.refreshKey}
                incident={incident}
                user={user}
                disabled={disabled}
                mutate={resource.mutate}
              />
              <IncidentNotes
                incident={incident}
                editable={editable}
                disabled={disabled}
                mutate={resource.mutate}
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
}
