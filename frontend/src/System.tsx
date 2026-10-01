import { statusName, useResource } from './utilities';
import { useCallback, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from './api';
import { Badge, ErrorNotice, JsonView, Loading, Metric, Panel } from './components';
import type { Me, Pipeline, SecurityEvent } from './types';

interface PipelineHealth {
  states: Record<string, number>;
  oldest_pending_seconds: number;
}
interface IngestionHealth extends PipelineHealth {
  retained_events: number;
  receipt_records: number;
  payload_bytes: number;
  limits: Record<string, number>;
}
interface Health {
  status: string;
  checks: Record<string, string>;
}
export function System({ user, onEvent }: { user: Me; onEvent: (event: SecurityEvent) => void }) {
  const loader = useCallback(async () => {
    const [health, pipeline, ingestion, detections] = await Promise.all([
      api.get<Health>('/system/health'),
      api.get<PipelineHealth>('/system/pipeline'),
      api.get<IngestionHealth>('/system/ingestion'),
      api.get<PipelineHealth>('/system/detections'),
    ]);
    return { health, pipeline, ingestion, detections };
  }, []);
  const resource = useResource(loader);
  const [job, setJob] = useState<Pipeline | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  async function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    setJob(null);
    try {
      setJob(
        await api.get<Pipeline>(
          `/events/${encodeURIComponent(String(new FormData(event.currentTarget).get('id')))}/pipeline`,
        ),
      );
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  async function retry() {
    if (!job) return;
    setPending(true);
    setError(null);
    try {
      setJob(
        await api.post<Pipeline>(
          `/events/${job.event_id}/pipeline/retry`,
          {},
          { 'If-Match': `"${job.version}"` },
        ),
      );
      await resource.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Stan przyjmowania i przetwarzania</h2>
          <p>
            Rzeczywiste sondy usług i trwałe liczniki. Opóźnienia są widoczne przed pojawieniem się
            zdarzeń w archiwum.
          </p>
        </div>
        <button
          onClick={() => {
            void resource.reload();
          }}
          disabled={resource.pending}
        >
          Odśwież
        </button>
      </div>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data && (
        <>
          <div className="metrics">
            <Metric
              label="Przyjęte logi"
              value={resource.data.ingestion.retained_events}
              note="Niezmienne rekordy raw w magazynie"
            />
            <Metric
              label="W archiwum"
              value={resource.data.pipeline.states.projected ?? 0}
              note="Zakończona projekcja do ClickHouse"
            />
            <Metric
              label="Kwarantanna parsera"
              value={resource.data.pipeline.states.quarantined ?? 0}
              note="Zachowane logi wymagające analizy"
            />
            <Metric
              label="Najstarsza praca"
              value={`${resource.data.pipeline.oldest_pending_seconds}s`}
              note="Wiek oczekującego przetwarzania"
            />
          </div>
          <div className="overview-grid">
            <Panel
              title="Dostępność usług"
              aside={
                <Badge tone={resource.data.health.status === 'ready' ? 'success' : 'failure'}>
                  {resource.data.health.status === 'ready' ? 'Gotowy' : 'Niedostępny'}
                </Badge>
              }
            >
              <div className="health-list">
                {Object.entries(resource.data.health.checks).map(([name, state]) => (
                  <div key={name}>
                    <strong>{name}</strong>
                    <Badge tone={state === 'ok' ? 'success' : 'failure'}>
                      {state === 'ok' ? 'Działa' : 'Niedostępny'}
                    </Badge>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Etapy pipeline">
              <div className="health-list">
                {[
                  'pending',
                  'normalizing',
                  'normalized',
                  'projecting',
                  'projected',
                  'quarantined',
                  'projection_failed',
                ].map((state) => (
                  <div key={state}>
                    <span>{statusName[state]}</span>
                    <strong className="mono">{resource.data!.pipeline.states[state] ?? 0}</strong>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
          <Panel title="Praca detekcji">
            <div className="health-list">
              {['pending', 'processed', 'quarantined'].map((state) => (
                <div key={state}>
                  <span>{statusName[state]}</span>
                  <strong>{resource.data!.detections.states[state] ?? 0}</strong>
                </div>
              ))}
              <div>
                <span>Najstarsze oczekiwanie</span>
                <strong>{resource.data.detections.oldest_pending_seconds} s</strong>
              </div>
            </div>
          </Panel>
          <Panel title="Pojemność magazynu">
            <dl className="facts">
              <dt>Raw records</dt>
              <dd>
                {resource.data.ingestion.retained_events.toLocaleString('pl-PL')} /{' '}
                {resource.data.ingestion.limits.stored_events.toLocaleString('pl-PL')}
              </dd>
              <dt>Pozycje batchy</dt>
              <dd>
                {resource.data.ingestion.receipt_records.toLocaleString('pl-PL')} /{' '}
                {resource.data.ingestion.limits.receipt_records.toLocaleString('pl-PL')}
              </dd>
              <dt>Logiczne bajty raw</dt>
              <dd>
                {resource.data.ingestion.payload_bytes.toLocaleString('pl-PL')} /{' '}
                {resource.data.ingestion.limits.payload_bytes.toLocaleString('pl-PL')}
              </dd>
              <dt>Raw w kwarantannie</dt>
              <dd>{resource.data.ingestion.states.quarantined ?? 0}</dd>
              <dt>Najstarsze przyjęcie</dt>
              <dd>{resource.data.ingestion.oldest_pending_seconds} s</dd>
            </dl>
            <details>
              <summary>Pełny status przyjmowania</summary>
              <JsonView value={resource.data.ingestion} />
            </details>
          </Panel>
        </>
      )}
      <Panel title="Sprawdź pracę zdarzenia">
        <form
          className="form-row"
          onSubmit={(event) => {
            void inspect(event);
          }}
        >
          <label>
            Event ID
            <input
              name="id"
              required
              maxLength={36}
              placeholder="UUID z potwierdzenia batcha"
              pattern="[0-9a-fA-F-]{36}"
            />
          </label>
          <button className="primary" disabled={pending}>
            Sprawdź status
          </button>
        </form>
        <ErrorNotice error={error} />
        {job && (
          <>
            <dl className="facts">
              <dt>Stan</dt>
              <dd>{statusName[job.state] ?? job.state}</dd>
              <dt>Próby normalizacji / projekcji</dt>
              <dd>
                {job.normalization_attempts} / {job.projection_attempts}
              </dd>
              <dt>Kod błędu</dt>
              <dd>{job.error_code ?? '—'}</dd>
              <dt>Wersja</dt>
              <dd>{job.version}</dd>
            </dl>
            <div className="button-row">
              {user.permissions.includes('sources:manage') &&
                ['quarantined', 'projection_failed'].includes(job.state) && (
                  <button
                    disabled={pending}
                    onClick={() => {
                      void retry();
                    }}
                  >
                    Ponów etap przetwarzania
                  </button>
                )}
              {job.state === 'projected' && (
                <button
                  onClick={() => {
                    void api
                      .get<SecurityEvent>(`/events/${job.event_id}`)
                      .then(onEvent)
                      .catch(setError);
                  }}
                >
                  Otwórz dowód
                </button>
              )}
            </div>
            <p className="muted">
              Retry zachowuje oryginalny log. Nie naprawia jego treści; jest przydatny po poprawie
              parsera lub przywróceniu usługi.
            </p>
          </>
        )}
      </Panel>
    </>
  );
}
