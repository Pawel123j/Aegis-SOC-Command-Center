import { useCallback, useState } from 'react';
import { api } from '../api';
import { ErrorNotice, JsonView, Loading } from '../components';
import { useResource } from '../utilities';
import { riskContextNames } from './labels';
import { riskLevelNames } from './levels';
import type { RiskLevel } from './levels';
import type { RiskPolicy as Policy } from './types';

export function RiskPolicy() {
  const [open, setOpen] = useState(false);
  return (
    <div className="risk-actions">
      <button className="quiet" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
        {open ? 'Zwiń zasady punktacji' : 'Zasady punktacji'}
      </button>
      {open && <PolicyDetails />}
    </div>
  );
}

function PolicyDetails() {
  const loader = useCallback(() => api.get<Policy>('/risk/policy'), []);
  const resource = useResource(loader);
  return (
    <div>
      <h3>Polityka oceny ryzyka</h3>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {Boolean(resource.error) && (
        <button
          className="quiet"
          disabled={resource.pending}
          onClick={() => void resource.reload()}
        >
          Ponów pobranie zasad
        </button>
      )}
      {resource.data && !resource.error && (
        <>
          <p>{resource.data.description}</p>
          <div className="table-wrap">
            <table>
              <caption>Poziomy priorytetu</caption>
              <thead>
                <tr>
                  <th>Poziom</th>
                  <th>Punkty</th>
                </tr>
              </thead>
              <tbody>
                {(Object.keys(riskLevelNames) as RiskLevel[]).map((level) => (
                  <tr key={level}>
                    <td>{riskLevelNames[level]}</td>
                    <td>{resource.data!.level_thresholds[level].join('–')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="table-wrap">
            <table>
              <caption>Limity składników</caption>
              <thead>
                <tr>
                  <th>Składnik</th>
                  <th>Maksimum punktów</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.components.map((component) => (
                  <tr key={component.code}>
                    <td>{component.label}</td>
                    <td>{component.maximum}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted">
            Informacje niedostępne w obecnym środowisku:{' '}
            {resource.data.production_unknown_contexts
              .map((context) => riskContextNames[context] ?? context)
              .join(', ') || 'Brak'}
            .
          </p>
          <details>
            <summary>Wersja i zachowany zapis polityki</summary>
            <JsonView value={resource.data} />
          </details>
        </>
      )}
    </div>
  );
}
