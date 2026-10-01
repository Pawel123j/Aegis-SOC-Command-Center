import { time, statusName, useResource } from './utilities';
import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { api } from './api';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Panel } from './components';
import type { BatchStatus, Credential, Enrollment, Page, Source } from './types';

const sourceTypes = [
  'generic_json',
  'linux_auth',
  'windows_auth',
  'windows_process',
  'firewall',
  'nginx',
];
export function Sources({ onEventId }: { onEventId: (id: string) => void }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const loader = useCallback(
    () =>
      api.get<Page<Source>>(
        `/sources?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
      ),
    [cursor],
  );
  const resource = useResource(loader);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [credential, setCredential] = useState<{ sourceId: string; data: Credential } | null>(null);
  const [copied, setCopied] = useState(false);
  const [sourceId, setSourceId] = useState('');
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const types = fields.getAll('types').map(String);
    if (!types.length) {
      setError(new Error('Wybierz co najmniej jeden format logów.'));
      return;
    }
    setPending(true);
    setError(null);
    try {
      const result = await api.post<Enrollment>('/sources', {
        name: fields.get('name'),
        timezone: fields.get('timezone'),
        source_types: types,
      });
      setCredential({ sourceId: result.source.id, data: result.credential });
      setCopied(false);
      setSourceId(result.source.id);
      form.reset();
      setCursor(null);
      await resource.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  async function toggle(source: Source) {
    setPending(true);
    setError(null);
    try {
      await api.patch(`/sources/${source.id}`, { enabled: !source.enabled }, source.version);
      if (credential?.sourceId === source.id) setCredential(null);
      await resource.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  async function issue(source: Source) {
    setPending(true);
    setError(null);
    try {
      const result = await api.post<Credential>(`/sources/${source.id}/credentials`, {});
      setCredential({ sourceId: source.id, data: result });
      setCopied(false);
      setSourceId(source.id);
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
          <h2>Podłącz logi do Aegis</h2>
          <p>Każde źródło otrzymuje własny klucz i dozwolone formaty danych.</p>
        </div>
        <button
          disabled={resource.pending}
          onClick={() => {
            void resource.reload();
          }}
        >
          Odśwież
        </button>
      </div>
      <ErrorNotice error={error} />
      {credential?.data.token && (
        <div className="notice credential-notice">
          <div>
            <strong>Nowy klucz źródła · zapisz go teraz</strong>
            <p>
              Jest dostępny wyłącznie teraz, do opuszczenia tego widoku. Ważny do{' '}
              {time(credential.data.expires_at)}.
            </p>
          </div>
          <label>
            Klucz źródła
            <input
              type="password"
              readOnly
              value={credential.data.token}
              aria-label="Nowy klucz źródła"
            />
          </label>
          <div className="button-row">
            <button
              onClick={() => {
                void navigator.clipboard
                  .writeText(credential.data.token!)
                  .then(() => setCopied(true))
                  .catch(() =>
                    setError(
                      new Error('Nie udało się skopiować. Zaznacz klucz i skopiuj go ręcznie.'),
                    ),
                  );
              }}
            >
              {copied ? 'Skopiowano' : 'Kopiuj klucz'}
            </button>
            <button className="quiet" onClick={() => setCredential(null)}>
              Ukryj klucz
            </button>
          </div>
          <p className="muted">
            Uprawnienia klucza: przyjęcie logów i status batcha. Wyłączenie źródła odwołuje
            wszystkie jego klucze.
          </p>
        </div>
      )}
      <div className="source-grid">
        <Panel title="Dodaj źródło">
          <form
            onSubmit={(event) => {
              void create(event);
            }}
          >
            <label>
              Nazwa źródła
              <input name="name" required maxLength={128} placeholder="np. Bastion SSH" />
            </label>
            <label>
              Strefa czasowa IANA
              <input
                name="timezone"
                required
                defaultValue="UTC"
                maxLength={64}
                placeholder="Europe/Warsaw"
              />
            </label>
            <fieldset>
              <legend>Dozwolone formaty</legend>
              <div className="check-grid">
                {sourceTypes.map((type) => (
                  <label className="checkbox" key={type}>
                    <input
                      type="checkbox"
                      name="types"
                      value={type}
                      defaultChecked={type === 'generic_json'}
                    />
                    {type}
                  </label>
                ))}
              </div>
            </fieldset>
            <button className="primary" disabled={pending}>
              Utwórz źródło
            </button>
          </form>
        </Panel>
        <Panel
          title="Źródła"
          aside={<span className="muted">{resource.data?.items.length ?? '—'} na stronie</span>}
        >
          <ErrorNotice error={resource.error} />
          {resource.pending && <Loading />}
          {resource.data &&
            (resource.data.items.length ? (
              <>
                <div className="source-list">
                  {resource.data.items.map((source) => (
                    <article key={source.id}>
                      <div>
                        <strong>{source.name}</strong>
                        <small>
                          {source.source_types.join(', ')} · {source.timezone}
                        </small>
                        <small className="mono">{source.id}</small>
                      </div>
                      <Badge tone={source.enabled ? 'success' : undefined}>
                        {source.enabled ? 'Aktywne' : 'Wyłączone'}
                      </Badge>
                      <div className="button-row">
                        <button
                          disabled={pending || !source.enabled}
                          onClick={() => {
                            void issue(source);
                          }}
                        >
                          Nowy klucz
                        </button>
                        <button
                          className={source.enabled ? 'danger-quiet' : ''}
                          disabled={pending}
                          onClick={() => {
                            void toggle(source);
                          }}
                        >
                          {source.enabled ? 'Wyłącz i odwołaj klucze' : 'Włącz źródło'}
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
                <div className="pagination">
                  <button disabled={!cursor || resource.pending} onClick={() => setCursor(null)}>
                    Pierwsza strona
                  </button>
                  <button
                    disabled={!resource.data.next_cursor || resource.pending}
                    onClick={() => setCursor(resource.data!.next_cursor)}
                  >
                    Następna
                  </button>
                </div>
              </>
            ) : (
              <Empty title="Brak źródeł">
                Dodaj pierwsze źródło, aby odebrać własny klucz do przyjmowania logów.
              </Empty>
            ))}
        </Panel>
      </div>
      <Ingestion
        sources={resource.data?.items ?? []}
        selectedSourceId={sourceId}
        issuedToken={credential?.data.token ?? ''}
        onEventId={onEventId}
      />
    </>
  );
}

function Ingestion({
  sources,
  selectedSourceId,
  issuedToken,
  onEventId,
}: {
  sources: Source[];
  selectedSourceId: string;
  issuedToken: string;
  onEventId: (id: string) => void;
}) {
  const [batchId, setBatchId] = useState<string | null>(null);
  const [pollRevision, setPollRevision] = useState(0);
  const [status, setStatus] = useState<BatchStatus | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  const [polling, setPolling] = useState(false);
  const [format, setFormat] = useState('raw');
  const [key, setKey] = useState<string>(() => crypto.randomUUID());
  const [payload, setPayload] = useState('{"message":"Log testowy z panelu"}');
  const [submitted, setSubmitted] = useState<{
    token: string;
    payload: unknown;
    key: string;
    formSignature: string;
  } | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const currentSource = sources.find((source) => source.id === (selectedId || selectedSourceId));
  const types = currentSource?.source_types ?? sourceTypes;
  useEffect(() => {
    if (!batchId) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    let attempts = 0;
    async function poll() {
      try {
        const response = await api.get<BatchStatus>(`/events/batches/${batchId}`);
        if (!active) return;
        setStatus(response);
        const complete = response.records.every(
          (item) =>
            item.state === 'quarantined' ||
            ['quarantined', 'projection_failed'].includes(item.pipeline_state ?? '') ||
            (item.pipeline_state === 'projected' &&
              ['processed', 'quarantined'].includes(item.detection_state ?? '')),
        );
        if (!complete && ++attempts < 40)
          timer = setTimeout(() => {
            void poll();
          }, 1500);
        else setPolling(false);
      } catch (failure) {
        if (active) {
          setError(failure);
          setPolling(false);
        }
      }
    }
    void poll();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [batchId, pollRevision]);
  async function send(token: string, body: unknown, idempotency: string) {
    setPending(true);
    setError(null);
    setStatus(null);
    try {
      const result = await api.sourcePost<{ batch_id: string }>(token, body, idempotency);
      setBatchId(result.batch_id);
      setPollRevision((revision) => revision + 1);
      setPolling(true);
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const fields = new FormData(event.currentTarget);
    try {
      const token = String(fields.get('token'));
      const formSignature = JSON.stringify({ format, payload, type: fields.get('type') });
      if (
        submitted?.key === key &&
        submitted.token === token &&
        submitted.formSignature === formSignature
      ) {
        void send(token, submitted.payload, key);
        return;
      }
      const body =
        format === 'batch'
          ? (JSON.parse(payload) as unknown)
          : {
              source_type: String(fields.get('type')),
              raw_event: payload.trim().startsWith('{')
                ? (JSON.parse(payload) as unknown)
                : payload,
              timestamp: new Date().toISOString(),
            };
      setSubmitted({ token, payload: body, key, formSignature });
      void send(token, body, key);
    } catch {
      setError(new Error('Treść nie jest poprawnym JSON. Sprawdź nawiasy i cudzysłowy.'));
    }
  }
  return (
    <Panel title="Prześlij logi" aside={<Badge>Potwierdzenie przyjęcia</Badge>}>
      <p className="muted">
        Przyjęcie nie oznacza zakończenia normalizacji. Status pokazuje postęp każdego rekordu.
        Klucz źródła pozostaje wyłącznie w pamięci tej strony.
      </p>
      <ErrorNotice error={error} />
      <form onSubmit={submit}>
        <div className="form-row">
          <label>
            Źródło (lista bieżącej strony)
            <select
              value={selectedId || selectedSourceId}
              onChange={(event) => setSelectedId(event.target.value)}
            >
              <option value="">Zewnętrzny klucz</option>
              {sources
                .filter((source) => source.enabled)
                .map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Klucz do przyjmowania logów
            <input
              name="token"
              type="password"
              required
              defaultValue={issuedToken}
              key={issuedToken}
              autoComplete="off"
            />
          </label>
          <label>
            Format wejścia
            <select value={format} onChange={(event) => setFormat(event.target.value)}>
              <option value="raw">Pojedynczy log</option>
              <option value="batch">Batch envelope JSON</option>
            </select>
          </label>
          {format === 'raw' && (
            <label>
              Typ źródła
              <select name="type" key={types.join()}>
                {types.map((type) => (
                  <option key={type}>{type}</option>
                ))}
              </select>
            </label>
          )}
        </div>
        <label>
          {format === 'raw'
            ? 'Treść logu (tekst albo JSON object)'
            : 'Batch: {"events": [{"source_type": "…", "raw_event": …}]}'}
          <textarea
            className="code-input"
            rows={6}
            value={payload}
            onChange={(event) => setPayload(event.target.value)}
            required
            maxLength={1048576}
          />
        </label>
        <div className="form-row">
          <label>
            Idempotency-Key
            <input
              required
              value={key}
              onChange={(event) => setKey(event.target.value)}
              maxLength={128}
            />
          </label>
          <button type="button" onClick={() => setKey(crypto.randomUUID())}>
            Nowy klucz żądania
          </button>
          <button className="primary" disabled={pending || polling}>
            {pending ? 'Przyjmowanie…' : 'Prześlij logi'}
          </button>
        </div>
        <p className="muted">
          Ten sam klucz ponawia ten sam batch bez podwójnego przyjęcia. Dla nowej treści wybierz
          nowy klucz. Pojedynczy log otrzymuje jawny czas wysłania; dla oryginalnych timestampów
          użyj envelope w batchu.
        </p>
      </form>
      {submitted && Boolean(error) && (
        <button
          disabled={pending}
          onClick={() => {
            void send(submitted.token, submitted.payload, submitted.key);
          }}
        >
          Ponów identyczne żądanie
        </button>
      )}
      {polling && (
        <p role="status" className="loading">
          Sprawdzanie przetwarzania (maksymalnie 60 sekund)…
        </p>
      )}
      {status && (
        <>
          <div className="metrics compact">
            <MetricSmall label="Przyjęte" value={status.accepted_count} />
            <MetricSmall label="Nowe" value={status.created_count} />
            <MetricSmall label="Duplikaty" value={status.duplicate_count} />
            <MetricSmall label="W archiwum" value={status.counts.projected} />
            <MetricSmall label="Sprawdzone przez reguły" value={status.counts.processed} />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Pozycja</th>
                  <th>Event ID</th>
                  <th>Przyjęcie</th>
                  <th>Przetwarzanie</th>
                  <th>Detekcja</th>
                  <th>Błąd</th>
                </tr>
              </thead>
              <tbody>
                {status.records.map((item) => (
                  <tr key={item.position}>
                    <td>{item.position + 1}</td>
                    <td>
                      <button className="inline-link mono" onClick={() => onEventId(item.event_id)}>
                        {item.event_id}
                      </button>
                    </td>
                    <td>{statusName[item.state] ?? item.state}</td>
                    <td>{statusName[item.pipeline_state ?? 'pending'] ?? item.pipeline_state}</td>
                    <td>{statusName[item.detection_state ?? ''] ?? '—'}</td>
                    <td>{item.pipeline_error_code ?? item.error_code ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <details>
            <summary>Potwierdzenie batcha</summary>
            <JsonView value={status} />
          </details>
          <button
            disabled={polling}
            onClick={() => {
              void api
                .get<BatchStatus>(`/events/batches/${batchId}`)
                .then(setStatus)
                .catch(setError);
            }}
          >
            Odśwież status
          </button>
        </>
      )}
    </Panel>
  );
}
function MetricSmall({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value ?? '—'}</strong>
    </div>
  );
}
