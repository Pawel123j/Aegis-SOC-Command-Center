import { Badge } from '../components';
import { RiskScore } from '../risk/RiskScore';
import { time } from '../utilities';
import type { EntityScope, EntitySummary, IndexStatus } from './types';
import { entityKinds } from './labels';
export function ScopeNotice({ scope }: { scope: EntityScope }) {
  return (
    <p className="entity-scope">
      Wynik: {scope.mode === 'live' ? 'Live' : 'Replay'} · {time(scope.from)} – {time(scope.to)}
      {scope.mode === 'replay' && (
        <small className="mono">
          Dataset ID: {scope.dataset_id} · Run ID: {scope.run_id}
        </small>
      )}
    </p>
  );
}
export function IndexNotice({ status }: { status: IndexStatus }) {
  if (status.complete) return <p className="muted">Indeks kompletny dla wybranego zakresu.</p>;
  return (
    <div className="notice" role="status">
      <strong>Wynik niepełny — indeks oczekuje na uzupełnienie.</strong>
      <p>
        Zaległe zdarzenia: {status.pending_events} · zaległe alerty: {status.pending_alerts}. Brak
        widocznych powiązań może wynikać z nieukończonego indeksowania. Administrator może uzupełnić
        indeks w liście profili, a następnie odświeżyć wyniki.
      </p>
    </div>
  );
}
export function EntityTable({
  items,
  onSelect,
}: {
  items: EntitySummary[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table aria-label="Profile encji">
        <thead>
          <tr>
            <th>Profil / rodzaj</th>
            <th>Zdarzenia</th>
            <th>Alerty</th>
            <th>Incydenty</th>
            <th>Ryzyko powiązanych alertów</th>
            <th>Ostatnio w zakresie</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <th scope="row">
                <button className="inline-link entity-label" onClick={() => onSelect(item.id)}>
                  {item.label}
                </button>
                <small>
                  <Badge>{entityKinds[item.kind]}</Badge>
                </small>
              </th>
              <td>{item.counts.events}</td>
              <td>
                {item.counts.alerts}
                <small>Fałszywe alarmy: {item.counts.false_positive_alerts}</small>
              </td>
              <td>{item.counts.incidents}</td>
              <td>
                <RiskScore score={item.risk_score} level={item.risk_level} />
              </td>
              <td>{time(item.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
