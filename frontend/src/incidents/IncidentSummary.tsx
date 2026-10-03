import { Badge, Metric, Panel } from '../components';
import { time } from '../utilities';
import { incidentSeverities, incidentStatuses } from './labels';
import type { IncidentDetail } from './types';
import { IncidentMitre } from '../mitre/MitreMapping';

export function IncidentSummary({ incident }: { incident: IncidentDetail }) {
  return (
    <>
      <div className="metrics">
        <Metric label="Powiązane alerty" value={incident.alert_count} note="Aktywne powiązania" />
        <Metric
          label="Ocena ryzyka"
          value={incident.risk_score === null ? 'Nie obliczono' : `${incident.risk_score} / 100`}
          note="Priorytet analizy · szczegóły poniżej"
        />
        <Metric
          label="Pewność"
          value={incident.confidence ?? 'Nie obliczono'}
          note="Bez oszacowania pewności"
        />
        <Metric
          label="Zachowane dowody"
          value={incident.evidence_count}
          note="Także po odpięciu alertu"
        />
      </div>
      <Panel title="Kontekst incydentu">
        <div className="detail-badges">
          <Badge tone={incident.severity}>{incidentSeverities[incident.severity]}</Badge>
          <Badge>{incidentStatuses[incident.status]}</Badge>
          <Badge>{incident.mode}</Badge>
          {incident.tags.map((tag) => (
            <Badge key={tag}>{tag}</Badge>
          ))}
        </div>
        <p className="incident-description">{incident.description || 'Brak opisu incydentu.'}</p>
        <dl className="facts">
          <dt>Analityk</dt>
          <dd>{incident.owner?.username ?? 'Nieprzypisany'}</dd>
          <dt>Utworzono</dt>
          <dd>{time(incident.created_at)}</dd>
          <dt>Zaktualizowano</dt>
          <dd>{time(incident.updated_at)}</dd>
          <dt>Pierwsze zdarzenie</dt>
          <dd>{time(incident.first_seen)}</dd>
          <dt>Ostatnie zdarzenie</dt>
          <dd>{time(incident.last_seen)}</dd>
        </dl>
        <Entities title="Powiązani użytkownicy" values={incident.related_users} />
        <Entities title="Powiązane hosty" values={incident.related_hosts} />
        <Entities title="Powiązane adresy IP" values={incident.related_ip_addresses} />
        <IncidentMitre mapping={incident.mitre_mapping} />
        <details>
          <summary>Identyfikatory i zakres danych</summary>
          <dl className="facts">
            <dt>ID incydentu</dt>
            <dd className="mono">{incident.id}</dd>
            <dt>Dataset ID</dt>
            <dd className="mono">{incident.dataset_id ?? 'Wiele źródeł live'}</dd>
            <dt>Zestawy dowodów</dt>
            <dd className="mono">{incident.dataset_ids.join(', ') || 'Brak'}</dd>
            <dt>Run ID</dt>
            <dd className="mono">{incident.run_id}</dd>
            <dt>Wersja</dt>
            <dd>{incident.version}</dd>
          </dl>
        </details>
      </Panel>
    </>
  );
}

function Entities({ title, values }: { title: string; values: string[] }) {
  return (
    <div>
      <h3>{title}</h3>
      {values.length ? (
        <div className="incident-entities">
          {values.map((value) => (
            <Badge key={value}>{value}</Badge>
          ))}
        </div>
      ) : (
        <p className="muted">Brak w powiązanych alertach.</p>
      )}
    </div>
  );
}
