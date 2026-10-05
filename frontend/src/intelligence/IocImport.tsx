import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Panel } from '../components';
import { IntelligenceFailure } from './IntelligenceFailure';
import type { IocImportResult } from './types';
import type { IntelligenceScope } from './useIntelligenceScope';

export function IocImport({
  scope,
  onSaved,
  onClose,
}: {
  scope: IntelligenceScope;
  onSaved: (result: IocImportResult) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState('[]');
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
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
  async function importIocs() {
    if (scope.expired || flight.current === scope.capture()) return;
    const epoch = scope.capture();
    flight.current = epoch;
    setPendingEpoch(epoch);
    setError(null);
    try {
      let items: unknown;
      try {
        items = JSON.parse(text);
      } catch {
        throw new Error('Wklej poprawną tablicę JSON wskaźników.');
      }
      if (!Array.isArray(items) || items.length < 1 || items.length > 100)
        throw new Error('Import wymaga od 1 do 100 wskaźników w tablicy JSON.');
      const body = { items };
      if (new TextEncoder().encode(JSON.stringify(body)).byteLength > 1048576)
        throw new Error('Cały import może mieć najwyżej 1 MiB UTF-8.');
      const result = await api.post<IocImportResult>('/intelligence/import', body);
      if (alive.current && scope.isCurrent(epoch)) onSaved(result);
    } catch (value) {
      if (alive.current && scope.isCurrent(epoch)) setError({ epoch, value });
    } finally {
      if (alive.current && scope.isCurrent(epoch)) setPendingEpoch(null);
      if (flight.current === epoch) flight.current = null;
    }
  }
  return (
    <Panel
      title="Importuj katalog IOC"
      aside={
        <button disabled={pending} onClick={onClose}>
          Zamknij import IOC
        </button>
      }
    >
      <p>
        Wklej od 1 do 100 wskaźników, do 1 MiB UTF-8. Każdy wpis wymaga type, value i source. Jeden
        błędny wpis lub powtórzona wartość kanoniczna odrzuca całą partię; wcześniejszy katalog
        pozostaje zachowany.
      </p>
      <label>
        Wskaźniki IOC · tablica JSON
        <textarea
          rows={10}
          value={text}
          disabled={pending || scope.expired}
          onChange={(event) => setText(event.target.value)}
        />
      </label>
      <details>
        <summary>Przykład lokalnego importu</summary>
        <pre className="json-view">
          {
            '[{"type":"ip","value":"192.0.2.10","source":"Własna analiza","reputation":"suspicious","confidence":null,"active":true}]'
          }
        </pre>
      </details>
      <IntelligenceFailure
        error={!scope.expired && error?.epoch === scope.epoch ? error.value : null}
      />
      <button
        className="primary"
        disabled={pending || scope.expired}
        onClick={() => void importIocs()}
      >
        {pending ? 'Importowanie IOC…' : 'Zapisz partię IOC'}
      </button>
      <p className="muted">
        Dokładny duplikat bieżącej deklaracji nie tworzy rewizji. Zmienioną deklarację istniejącego
        IOC edytuj osobno z jego wersją.
      </p>
    </Panel>
  );
}
