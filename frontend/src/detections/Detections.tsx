import { useId, useState } from 'react';
import type { Me, SecurityEvent } from '../types';
import { Correlations } from './Correlations';
import { SingleEventRules } from './SingleEventRules';
import { SigmaRules } from '../sigma/SigmaRules';
import './detections.css';

export function Detections({
  user,
  onEvent,
}: {
  user: Me;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [tab, setTab] = useState('single');
  const [sigmaOpened, setSigmaOpened] = useState(false);
  const id = useId();
  const tabs = [
    ['single', 'Pojedyncze zdarzenia'],
    ['correlation', 'Korelacja zdarzeń'],
    ['sigma', 'Sigma'],
  ];
  function selectTab(value: string) {
    setTab(value);
    if (value === 'sigma') setSigmaOpened(true);
  }
  return (
    <>
      <div className="detection-tabs" role="tablist" aria-label="Rodzaj reguł detekcji">
        {tabs.map(([value, label]) => (
          <button
            key={value}
            id={`${id}-${value}-tab`}
            role="tab"
            aria-selected={tab === value}
            aria-controls={`${id}-${value}-panel`}
            tabIndex={tab === value ? 0 : -1}
            onClick={() => selectTab(value)}
            onKeyDown={(event) => {
              if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
                event.preventDefault();
                const next =
                  event.key === 'Home'
                    ? 'single'
                    : event.key === 'End'
                      ? 'sigma'
                      : tabs[
                          (tabs.findIndex(([value]) => value === tab) +
                            (event.key === 'ArrowRight' ? 1 : -1) +
                            tabs.length) %
                            tabs.length
                        ][0];
                selectTab(next);
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
        id={`${id}-sigma-panel`}
        aria-labelledby={`${id}-sigma-tab`}
        hidden={tab !== 'sigma'}
      >
        {sigmaOpened && <SigmaRules user={user} onEvent={onEvent} />}
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
