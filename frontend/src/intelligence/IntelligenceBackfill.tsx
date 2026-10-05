import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Panel } from '../components';
import { IntelligenceFailure } from './IntelligenceFailure';
import type { IntelligenceBackfillResult } from './types';
import type { IntelligenceScope } from './useIntelligenceScope';

export function IntelligenceBackfill({ scope }: { scope: IntelligenceScope }) {
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
  const [result, setResult] = useState<{ epoch: number; value: IntelligenceBackfillResult } | null>(
    null,
  );
  const [error, setError] = useState<{ epoch: number; value: unknown } | null>(null);
  const alive = useRef(true);
  const flight = useRef<number | null>(null);
  const pending = pendingEpoch === scope.epoch;
  useEffect(() => {
    const active = alive;
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  async function backfill() {
    if (scope.expired || flight.current === scope.capture()) return;
    const epoch = scope.capture();
    flight.current = epoch;
    setPendingEpoch(epoch);
    setResult(null);
    setError(null);
    try {
      const response = await api.post<IntelligenceBackfillResult>('/intelligence/backfill', {
        limit: 25,
      });
      if (alive.current && scope.isCurrent(epoch)) setResult({ epoch, value: response });
    } catch (value) {
      if (alive.current && scope.isCurrent(epoch)) setError({ epoch, value });
    } finally {
      if (alive.current && scope.isCurrent(epoch)) setPendingEpoch(null);
      if (flight.current === epoch) flight.current = null;
    }
  }
  const currentResult = !scope.expired && result?.epoch === scope.epoch ? result.value : null;
  return (
    <Panel title="Analiza starszych zdarzeń IOC">
      <p>
        Sprawdź jedną partię do 25 zdarzeń bez utrwalonej analizy IOC. Operacja obejmuje cały system
        i używa bieżącego lokalnego katalogu. Nigdy nie nadpisuje starszych dopasowań, nie tworzy
        historycznych alertów i nie przelicza ryzyka.
      </p>
      <button disabled={pending || scope.expired} onClick={() => void backfill()}>
        {pending ? 'Analizowanie partii IOC…' : 'Przeanalizuj jedną partię IOC'}
      </button>
      <IntelligenceFailure
        error={!scope.expired && error?.epoch === scope.epoch ? error.value : null}
      />
      {currentResult && (
        <p role="status">
          Zbadane zdarzenia: {currentResult.events}; utrwalone dopasowania: {currentResult.matches};
          pozostało bez analizy: {currentResult.remaining}. Utworzone alerty:{' '}
          {currentResult.alerts_created}. Kolejna partia wymaga osobnego uruchomienia.
        </p>
      )}
    </Panel>
  );
}
