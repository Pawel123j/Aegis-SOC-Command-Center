import { useId, useState } from 'react';
import type { Me, SecurityEvent } from '../types';
import { Correlations } from './Correlations';
import { SingleEventRules } from './SingleEventRules';
import './detections.css';

export function Detections({
  user,
  onEvent,
}: {
  user: Me;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [tab, setTab] = useState('single');
  const id = useId();
  return (
    <>
      <div className="detection-tabs" role="tablist" aria-label="Rodzaj reguł detekcji">
        {[
          ['single', 'Pojedyncze zdarzenia'],
          ['correlation', 'Korelacja zdarzeń'],
        ].map(([value, label]) => (
          <button
            key={value}
            id={`${id}-${value}-tab`}
            role="tab"
            aria-selected={tab === value}
            aria-controls={`${id}-${value}-panel`}
            tabIndex={tab === value ? 0 : -1}
            onClick={() => setTab(value)}
            onKeyDown={(event) => {
              if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
                event.preventDefault();
                const next =
                  event.key === 'Home'
                    ? 'single'
                    : event.key === 'End'
                      ? 'correlation'
                      : tab === 'single'
                        ? 'correlation'
                        : 'single';
                setTab(next);
                document.getElementById(`${id}-${next}-tab`)?.focus();
              }
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`${id}-single-panel`}
        aria-labelledby={`${id}-single-tab`}
        hidden={tab !== 'single'}
      >
        <SingleEventRules user={user} />
      </div>
      <div
        role="tabpanel"
        id={`${id}-correlation-panel`}
        aria-labelledby={`${id}-correlation-tab`}
        hidden={tab !== 'correlation'}
      >
        <Correlations user={user} onEvent={onEvent} />
      </div>
    </>
  );
}
