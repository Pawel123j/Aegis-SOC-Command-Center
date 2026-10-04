import { useState } from 'react';
import { api } from '../api';
import { JsonView } from '../components';
import { EventEvidence } from '../evidence/EventEvidence';
import type { SecurityEvent } from '../types';
import { checkBody } from './limits';
import { SigmaFailure } from './SigmaFailure';
import type { SigmaCapabilities, SigmaRuleDetail, SigmaTestResult } from './types';
import type { SigmaScope } from './useSigmaScope';

export function SigmaTest({
  rule,
  capabilities,
  scope,
  onEvent,
  payload,
  onPayloadChange,
}: {
  rule: SigmaRuleDetail;
  capabilities: SigmaCapabilities;
  scope: SigmaScope;
  onEvent: (event: SecurityEvent) => void;
  payload: string;
  onPayloadChange: (value: string) => void;
}) {
  const [pendingEpoch, setPendingEpoch] = useState<number | null>(null);
  const [failure, setFailure] = useState<{ epoch: number; value: unknown } | null>(null);
  const [result, setResult] = useState<{
    epoch: number;
    value: SigmaTestResult;
    events: SecurityEvent[];
  } | null>(null);
  const pending = pendingEpoch === scope.epoch;
  const visible = result?.epoch === scope.epoch && !scope.expired ? result : null;
  async function test() {
    if (pending || scope.expired) return;
    const epoch = scope.capture();
    setPendingEpoch(epoch);
    setFailure(null);
    setResult(null);
    try {
      const events = JSON.parse(payload) as unknown;
      if (
        !Array.isArray(events) ||
        events.length < 1 ||
        events.length > capabilities.max_test_events
      )
        throw new Error(
          `Podaj od 1 do ${capabilities.max_test_events} pełnych znormalizowanych rekordów.`,
        );
      const body = { yaml: rule.definition_yaml, events };
      checkBody(body, capabilities.max_test_body_bytes);
      const value = await api.post<SigmaTestResult>('/sigma/test', body);
      if (value.definition.source_sha256 !== rule.source_sha256)
        throw new Error('Wynik dotyczy innej definicji Sigma. Odśwież szczegóły reguły.');
      if (scope.isCurrent(epoch)) setResult({ epoch, value, events: events as SecurityEvent[] });
    } catch (value) {
      if (scope.isCurrent(epoch)) setFailure({ epoch, value });
    } finally {
      if (scope.isCurrent(epoch)) setPendingEpoch(null);
    }
  }
  return (
    <section className="correlation-test">
      <h3>Izolowany test Sigma</h3>
      <p className="muted">
        Wklej pełne rekordy JSON z Event Explorer. Test sprawdza zachowaną definicję wersji{' '}
        {rule.revision}, także gdy reguła jest wyłączona. Nie zapisuje alertów ani incydentów i nie
        zmienia włączenia reguły.
      </p>
      <label>
        Zdarzenia Sigma (JSON array)
        <textarea
          className="code-input"
          rows={9}
          value={payload}
          disabled={pending || scope.expired}
          onChange={(event) => {
            onPayloadChange(event.target.value);
            setResult(null);
            setFailure(null);
          }}
        />
      </label>
      <button className="primary" disabled={pending || scope.expired} onClick={() => void test()}>
        {pending ? 'Sprawdzanie…' : 'Uruchom test Sigma'}
      </button>
      <SigmaFailure error={failure?.epoch === scope.epoch ? failure.value : null} />
      {visible && (
        <div className="correlation-result" role="status">
          <h3>Dopasowania Sigma: {visible.value.matches.length}</h3>
          <p>
            Sprawdzone zdarzenia: {visible.value.tested_events} ·{' '}
            {visible.value.definition.evaluator_version}
          </p>
          {!visible.value.matches.length && <p>Przesłany zestaw nie spełnia warunków reguły.</p>}
          {visible.value.matches.map((match, index) => {
            const event = visible.events.find((item) => item.event_id === match.event_id);
            return (
              <article className="correlation-match" key={`${match.event_id}/${index}`}>
                <h4>Dopasowanie {index + 1}</h4>
                {event ? (
                  <EventEvidence
                    onEvent={onEvent}
                    events={[{ event_id: event.event_id, event_sha256: '', event_snapshot: event }]}
                  />
                ) : (
                  <p className="notice error">Dowód nie jest dostępny w przesłanym zestawie.</p>
                )}
                <details>
                  <summary>Uzasadnienie dopasowania Sigma</summary>
                  <JsonView value={match.reason} />
                </details>
              </article>
            );
          })}
          <details>
            <summary>Pełny wynik testu Sigma</summary>
            <JsonView value={visible.value} />
          </details>
        </div>
      )}
    </section>
  );
}
