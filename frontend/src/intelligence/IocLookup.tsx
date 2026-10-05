import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from '../api';
import { Badge, Panel } from '../components';
import { IntelligenceFailure } from './IntelligenceFailure';
import { iocTypes, reputations, reputationTone } from './labels';
import type { IocLookupResult, IocType } from './types';
import type { IntelligenceScope } from './useIntelligenceScope';

export function IocLookup({
  scope,
  onSelect,
}: {
  scope: IntelligenceScope;
  onSelect: (id: string) => void;
}) {
  const [type, setType] = useState<IocType>('ip');
  const [value, setValue] = useState('');
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<{ epoch: number; value: IocLookupResult } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const generation = useRef(0);
  useEffect(() => {
    const counter = generation;
    return () => {
      counter.current++;
    };
  }, []);
  function changed() {
    generation.current++;
    setPending(false);
    setResult(null);
    setError(null);
  }
  async function lookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending || scope.expired) return;
    const revision = ++generation.current;
    const epoch = scope.capture();
    setPending(true);
    setResult(null);
    setError(null);
    try {
      const response = await api.post<IocLookupResult>('/intelligence/lookup', {
        type,
        value: value.trim(),
      });
      if (generation.current === revision && scope.isCurrent(epoch))
        setResult({ epoch, value: response });
    } catch (failure) {
      if (generation.current === revision && scope.isCurrent(epoch)) setError(failure);
    } finally {
      if (generation.current === revision && scope.isCurrent(epoch)) setPending(false);
    }
  }
  const data = !scope.expired && result?.epoch === scope.epoch ? result.value : null;
  return (
    <Panel title="Sprawdź konkretny wskaźnik">
      <form onSubmit={(event) => void lookup(event)}>
        <div className="form-row intelligence-filters">
          <label>
            Typ do sprawdzenia
            <select
              disabled={scope.expired}
              value={type}
              onChange={(event) => {
                changed();
                setType(event.target.value as IocType);
              }}
            >
              {Object.entries(iocTypes).map(([key, label]) => (
                <option key={key} value={key}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Wartość do sprawdzenia
            <input
              disabled={scope.expired}
              required
              maxLength={2048}
              value={value}
              onChange={(event) => {
                changed();
                setValue(event.target.value);
              }}
            />
          </label>
          <button disabled={pending || scope.expired}>
            {pending ? 'Sprawdzanie wskaźnika…' : 'Sprawdź IOC'}
          </button>
        </div>
      </form>
      {!scope.expired && <IntelligenceFailure error={error} />}
      {data && (
        <div role="status">
          <p className="ioc-value mono">Wartość kanoniczna: {data.canonical_value}</p>
          {data.found && data.item ? (
            <>
              <Badge tone={reputationTone[data.item.reputation]}>
                {reputations[data.item.reputation]}
              </Badge>{' '}
              <Badge>{data.item.active ? 'Aktywny' : 'Wyłączony'}</Badge>
              <p>
                Źródło: {data.item.source}. Deklarowana pewność:{' '}
                {data.item.confidence ?? 'nieznana'}.
              </p>
              <button onClick={() => onSelect(data.item!.id)}>Otwórz znaleziony IOC</button>
            </>
          ) : (
            <p>
              Brak wpisu w lokalnym katalogu. To nie potwierdza bezpieczeństwa adresu ani pliku.
            </p>
          )}
        </div>
      )}
      <p className="muted">
        Porównanie używa znormalizowanej wartości i uwzględnia także wyłączone wpisy. Nie otwiera
        adresów URL ani nie odpytuje usług zewnętrznych.
      </p>
    </Panel>
  );
}
