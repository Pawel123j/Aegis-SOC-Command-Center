import { Badge, JsonView } from '../components';
import { time } from '../utilities';
import { confidenceStatusNames, riskContextNames, riskStatusNames } from './labels';
import { RiskScore } from './RiskScore';
import type { RiskCalculation } from './types';

export function RiskExplanation({ calculation }: { calculation: RiskCalculation }) {
  return (
    <div className="risk-breakdown">
      <div className="risk-summary">
        <RiskScore score={calculation.score} level={calculation.level} />
        <span className="muted">Obliczono {time(calculation.created_at)}</span>
      </div>
      <p className="muted">
        Wynik określa priorytet analizy. Nie jest prawdopodobieństwem ataku ani potwierdzeniem
        kompromitacji.
      </p>
      <div className="table-wrap">
        <table>
          <caption className="sr-only">Składniki oceny ryzyka</caption>
          <thead>
            <tr>
              <th>Składnik</th>
              <th>Punkty</th>
              <th>Dane i uzasadnienie</th>
            </tr>
          </thead>
          <tbody>
            {calculation.components.map((component) => (
              <tr key={component.code}>
                <td>
                  <strong>{component.label}</strong>
                  <small>Limit: {component.maximum}</small>
                </td>
                <td className="risk-points">
                  {component.status === 'unknown'
                    ? '—'
                    : `${component.points >= 0 ? '+' : ''}${component.points}`}
                </td>
                <td className="risk-reason">
                  <Badge>{riskStatusNames[component.status]}</Badge>
                  <p>{component.reason}</p>
                  <details>
                    <summary>Dane składnika i identyfikatory dowodów</summary>
                    <JsonView
                      value={{ evidence_ids: component.evidence_ids, ...component.details }}
                    />
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr>
              <th>Suma składników</th>
              <td className="risk-points">{calculation.raw_score}</td>
              <td>Przed ograniczeniem do skali 0–100.</td>
            </tr>
            <tr>
              <th>Ograniczenie skali</th>
              <td className="risk-points">{calculation.clipping}</td>
              <td>Końcowy wynik: {calculation.score} / 100.</td>
            </tr>
          </tfoot>
        </table>
      </div>
      {calculation.missing_contexts.length > 0 && (
        <>
          <h3>Brakujące informacje</h3>
          <p className="muted">
            Brak danych nie oznacza, że źródło jest bezpieczne. Te informacje nie dodają punktów.
          </p>
          <ul className="risk-missing">
            {calculation.missing_contexts.map((context) => (
              <li key={context}>{riskContextNames[context] ?? context}</li>
            ))}
          </ul>
        </>
      )}
      <dl className="facts">
        <dt>Pewność detekcji</dt>
        <dd>{confidenceStatusNames[calculation.confidence_status]}</dd>
        <dt>Wersja polityki</dt>
        <dd>{calculation.policy_version}</dd>
        <dt>Wersja oceny</dt>
        <dd>{calculation.subject_revision}</dd>
      </dl>
      {calculation.excluded_alert_ids.length > 0 && (
        <p className="muted">
          Alerty wyłączone z tej oceny: {calculation.excluded_alert_ids.length}. Ich identyfikatory
          są w zachowanym zapisie poniżej.
        </p>
      )}
      <details>
        <summary>Zachowany zapis obliczenia, dowodów i sumy kontrolnej</summary>
        <JsonView value={calculation} />
      </details>
    </div>
  );
}
