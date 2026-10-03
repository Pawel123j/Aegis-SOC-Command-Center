import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Badge, Empty, ErrorNotice, Loading, Panel } from '../components';
import { time } from '../utilities';
import { RiskExplanation } from './RiskExplanation';
import { RiskScore } from './RiskScore';
import { RiskPolicy } from './RiskPolicy';
import type { RiskCalculation, RiskHistory, RiskSubject } from './types';
import './risk.css';

interface RiskPanelProps {
  subject: RiskSubject;
  id: string;
  initial: RiskCalculation | null;
  canReadPolicy?: boolean;
  onRefresh?: () => void;
  refreshPending?: boolean;
}

export function RiskPanel(props: RiskPanelProps) {
  return (
    <RiskPanelState
      key={`${props.subject}/${props.id}/${props.initial?.id ?? 'unscored'}`}
      {...props}
    />
  );
}

function RiskPanelState({
  subject,
  id,
  initial,
  canReadPolicy = false,
  onRefresh,
  refreshPending = false,
}: RiskPanelProps) {
  const [history, setHistory] = useState<RiskHistory | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [expanded, setExpanded] = useState(false);
  const generation = useRef(0);
  useEffect(() => {
    const counter = generation;
    return () => {
      counter.current++;
    };
  }, []);
  async function loadHistory() {
    const revision = ++generation.current;
    setExpanded(true);
    setPending(true);
    setError(null);
    try {
      const response = await api.get<RiskHistory>(
        `/${subject}s/${encodeURIComponent(id)}/risk?limit=10`,
      );
      if (generation.current === revision) setHistory(response);
    } catch (failure) {
      if (generation.current === revision) {
        setError(failure);
      }
    } finally {
      if (generation.current === revision) setPending(false);
    }
  }
  const current = initial;
  const hasNewer =
    history?.current !== null &&
    history?.current !== undefined &&
    history.current.id !== initial?.id;
  const previous = history?.history.filter((calculation) => calculation.id !== current?.id) ?? [];
  return (
    <Panel title="Ocena ryzyka">
      {current ? (
        <RiskExplanation calculation={current} />
      ) : (
        <Empty title="Ocena nie została obliczona">
          Nie ma zachowanego wyniku dla tego {subject === 'alert' ? 'alertu' : 'incydentu'}.
        </Empty>
      )}
      <div className="button-row risk-actions">
        <button className="quiet" disabled={pending} onClick={() => void loadHistory()}>
          {expanded ? 'Odśwież historię ryzyka' : 'Pokaż historię ryzyka'}
        </button>
        {expanded && (
          <button className="quiet" onClick={() => setExpanded(false)}>
            Zwiń historię ryzyka
          </button>
        )}
      </div>
      {expanded && (
        <div aria-busy={pending}>
          <h3>Historia ocen ryzyka</h3>
          <ErrorNotice error={error} />
          {pending && <Loading />}
          {history && !error && (
            <>
              {hasNewer && (
                <div className="notice">
                  Historia zawiera nowszą ocenę. Odśwież szczegóły{' '}
                  {subject === 'alert' ? 'alertu' : 'incydentu'}, aby uaktualnić wynik i jego
                  uzasadnienie.
                  {onRefresh && (
                    <div className="risk-actions">
                      <button disabled={refreshPending} onClick={onRefresh}>
                        Odśwież szczegóły {subject === 'alert' ? 'alertu' : 'incydentu'}
                      </button>
                    </div>
                  )}
                </div>
              )}
              {history.history_truncated && (
                <p className="notice">
                  Pokazano najnowsze 10 obliczeń. Starsze wyniki pozostają w historii systemu.
                </p>
              )}
              {previous.length ? (
                <ol className="risk-history">
                  {previous.map((calculation) => (
                    <li key={calculation.id}>
                      {hasNewer && calculation.id === history.current?.id && (
                        <Badge>Nowsza ocena</Badge>
                      )}
                      <div className="risk-summary">
                        <RiskScore score={calculation.score} level={calculation.level} />
                        <span>
                          {time(calculation.created_at)} · wersja oceny{' '}
                          {calculation.subject_revision}
                        </span>
                      </div>
                      <details>
                        <summary>Uzasadnienie historycznej oceny</summary>
                        <RiskExplanation calculation={calculation} />
                      </details>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="muted">Brak wcześniejszych ocen.</p>
              )}
            </>
          )}
        </div>
      )}
      {canReadPolicy && <RiskPolicy />}
    </Panel>
  );
}
