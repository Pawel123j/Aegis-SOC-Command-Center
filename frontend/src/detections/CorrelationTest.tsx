import { useState } from 'react';
import { api } from '../api';
import { ErrorNotice, JsonView } from '../components';
import { EventEvidence } from '../evidence/EventEvidence';
import { EventReason } from '../evidence/EventReason';
import type { SecurityEvent } from '../types';
import { time } from '../utilities';
import type { CorrelationRule, CorrelationTestResult } from './types';

export function CorrelationTest({
  rule,
  onEvent,
}: {
  rule: CorrelationRule;
  onEvent: (event: SecurityEvent) => void;
}) {
  const [payload, setPayload] = useState('[]');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<{
    response: CorrelationTestResult;
    events: SecurityEvent[];
  } | null>(null);
  async function test() {
    if (pending) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const events = JSON.parse(payload) as unknown;
      if (!Array.isArray(events) || events.length < 1 || events.length > 100)
        throw new Error('Podaj od 1 do 100 pełnych znormalizowanych rekordów.');
      const body = { id: rule.id, events };
      if (new TextEncoder().encode(JSON.stringify(body)).length > 65536)
        throw new Error('Test może zawierać najwyżej 64 KiB danych.');
      const response = await api.post<CorrelationTestResult>('/correlations/test', body);
      setResult({ response, events: events as SecurityEvent[] });
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <section className="correlation-test">
      <h3>Izolowany test korelacji</h3>
      <p className="muted">
        Wklej pełne rekordy JSON z Event Explorer. Test nie tworzy alertów ani incydentów.
        Uwzględnia tylko te rekordy, a ich kolejność wynika z czasu zdarzenia.
      </p>
      <label>
        Zdarzenia korelacji (JSON array)
        <textarea
          className="code-input"
          rows={9}
          maxLength={60000}
          value={payload}
          onChange={(event) => setPayload(event.target.value)}
        />
      </label>
      <button className="primary" disabled={pending} onClick={() => void test()}>
        {pending ? 'Sprawdzanie…' : 'Uruchom test korelacji'}
      </button>
      <ErrorNotice error={error} />
      {result && (
        <div role="status" className="correlation-result">
          <h3>
            {result.response.complete
              ? `Dopasowania: ${result.response.matches.length}`
              : 'Wynik niekompletny'}
          </h3>
          <p className="muted">
            {result.response.rule_id} · {result.response.rule_version} ·{' '}
            {result.response.evaluator_version}
          </p>
          {result.response.complete && !result.response.matches.length && (
            <p>Przesłany zestaw nie spełnia warunków reguły.</p>
          )}
          {!result.response.complete && (
            <p>Sprawdź kompletność zestawu. Ten wynik nie pozwala potwierdzić braku dopasowań.</p>
          )}
          {result.response.matches.map((match, index) => {
            const events = match.event_ids.flatMap((id) => {
              const event = result.events.find((item) => item.event_id === id);
              return event ? [{ event_id: id, event_sha256: '', event_snapshot: event }] : [];
            });
            return (
              <article className="correlation-match" key={index}>
                <h4>
                  Dopasowanie {index + 1} · {time(match.event_timestamp)}
                </h4>
                <EventReason reason={match.reason} />
                <EventEvidence events={events} onEvent={onEvent} />
                {events.length !== match.event_ids.length && (
                  <p className="notice error">
                    Nie wszystkie dowody są dostępne w przesłanym zestawie.
                  </p>
                )}
                <details>
                  <summary>Pełne uzasadnienie dopasowania</summary>
                  <JsonView value={match.reason} />
                </details>
              </article>
            );
          })}
          <details>
            <summary>Pełny wynik testu</summary>
            <JsonView value={result.response} />
          </details>
        </div>
      )}
    </section>
  );
}
