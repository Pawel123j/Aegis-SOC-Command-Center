import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { UebaProfile } from '../src/ueba/UebaProfile';
import { matchesEvidence, uebaPath, yesterdayUtc } from '../src/ueba/filters';
import type { UebaReport } from '../src/ueba/types';
import type { Me, SecurityEvent } from '../src/types';
import { entitySummary } from './entityFixtures';
import { original, reader } from './incidentFixtures';
import { uebaFixture, uebaIndicator } from './uebaFixtures';

let report: UebaReport;
const listeners = new Set<(kind: 'logout' | 'session') => void>();
const params = 'mode=live&from=2026-09-01T00:00:00Z&to=2026-10-02T00:00:00Z&limit=25';
beforeEach(() => {
  vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-06T00:30:00Z'));
  report = structuredClone(uebaFixture);
  listeners.clear();
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path === '/auth/me') return reader;
    if (path.includes('/ueba?')) return report;
    if (path.includes('/ueba/events/')) return original;
    throw new Error(`Unexpected request: ${path}`);
  });
});
function view(overrides: Partial<Parameters<typeof UebaProfile>[0]> = {}) {
  return (
    <UebaProfile
      id={entitySummary.id}
      kind="user"
      params={params}
      user={reader}
      onEvent={vi.fn()}
      {...overrides}
    />
  );
}
function requests() {
  return vi.mocked(api.request).mock.calls.filter(([path]) => path.includes('/ueba?'));
}
function evidenceRequests() {
  return vi.mocked(api.request).mock.calls.filter(([path]) => path.includes('/ueba/events/'));
}
async function analyze(day = '2026-10-01') {
  fireEvent.change(screen.getByLabelText('Dzień obserwacji · UTC'), { target: { value: day } });
  fireEvent.submit(screen.getByRole('button', { name: 'Analizuj dzień' }).closest('form')!);
}
async function loaded() {
  return screen.findByRole('list', { name: 'Wskaźniki zachowania' });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { resolve, promise };
}
async function notify(kind: 'logout' | 'session') {
  await act(async () => listeners.forEach((listener) => listener(kind)));
}
function evidenceButton() {
  return screen.getByRole('button', {
    name: `Otwórz dowód: Pierwsze użycie narzędzia administracyjnego, ${original.event_id}`,
  });
}

it('starts with yesterday UTC and waits for explicit analysis without reading or writing data', async () => {
  render(view());
  expect(screen.getByLabelText('Dzień obserwacji · UTC')).toHaveValue('2026-10-05');
  expect(
    screen.getByText(/nie jest prawdopodobieństwem ataku ani oceną ryzyka/),
  ).toBeInTheDocument();
  await act(async () => undefined);
  expect(api.request).not.toHaveBeenCalled();
  expect(yesterdayUtc()).toBe('2026-10-05');
});

it.each(['events:read', 'alerts:read', 'incidents:read'])(
  'does not request analysis without %s',
  async (permission) => {
    render(
      view({
        user: {
          ...reader,
          permissions: reader.permissions.filter((value) => value !== permission),
        },
      }),
    );
    expect(screen.getByText(/Analiza wymaga uprawnień/)).toBeInTheDocument();
    await act(async () => undefined);
    expect(api.request).not.toHaveBeenCalled();
  },
);
it.each(['ip', 'process'])('does not offer unsupported %s profile analysis', async (kind) => {
  render(view({ kind }));
  expect(screen.queryByRole('heading', { name: 'Analiza zachowania' })).not.toBeInTheDocument();
  await act(async () => undefined);
  expect(api.request).not.toHaveBeenCalled();
});

it('verifies the account and sends only the completed day and exact live scope', async () => {
  render(view());
  await analyze();
  await loaded();
  expect(vi.mocked(api.request).mock.calls[0][0]).toBe('/auth/me');
  expect(requests()).toHaveLength(1);
  expect(requests()[0][0]).toBe(`/entities/${entitySummary.id}/ueba?mode=live&day=2026-10-01`);
  expect(requests()[0][1]?.signal).toBeInstanceOf(AbortSignal);
  expect(screen.getByText('2026-09-03T00:00:00Z — 2026-10-01T00:00:00Z')).toBeInTheDocument();
  expect(screen.getByText(/Własny zakres czasu profilu nie zmienia/)).toBeInTheDocument();
  expect(
    screen.getByText('Pominięte zdarzenia bez wiarygodnego czasu · obserwacja / wzorzec'),
  ).toBeInTheDocument();
  expect(vi.mocked(api.request).mock.calls.every(([, options]) => !options?.method)).toBe(true);
});

it.each(['', '2026-10-06', '2099-01-01', '1970-01-28', '2026-02-30', 'not-a-day'])(
  'rejects invalid observation day %s without requesting',
  (day) => {
    expect(() => uebaPath(entitySummary.id, params, day)).toThrow('zakończony dzień UTC');
  },
);
it('shows invalid day guidance in the form and makes no request', async () => {
  render(view());
  await analyze('2026-10-06');
  expect(await screen.findByRole('alert')).toHaveTextContent('zakończony dzień UTC');
  expect(api.request).not.toHaveBeenCalled();
});
it.each([
  'mode=replay',
  'mode=replay&dataset_id=invalid&run_id=invalid',
  `mode=replay&dataset_id=${original.dataset_id}&run_id=${original.run_id}`,
  'mode=other',
])('fails closed for malformed scope %s', (scope) => {
  expect(() => uebaPath(entitySummary.id, scope, '2026-10-01')).toThrow();
});

it('keeps replay baseline in its exact dataset and run and discards stale live IDs', async () => {
  const run = '60000000-0000-0000-0000-000000000006';
  report.scope = { mode: 'replay', dataset_id: original.dataset_id, run_id: run };
  render(
    view({
      params: `mode=replay&dataset_id=${original.dataset_id}&run_id=${run}&from=2026-01-01&limit=50`,
    }),
  );
  await analyze();
  await loaded();
  const query = new URLSearchParams(requests()[0][0].split('?')[1]);
  expect(Object.fromEntries(query)).toEqual({
    mode: 'replay',
    day: '2026-10-01',
    dataset_id: original.dataset_id,
    run_id: run,
  });
  expect(screen.getByText('Replay · odrębny wzorzec')).toBeInTheDocument();
  expect(
    uebaPath(
      entitySummary.id,
      `mode=live&dataset_id=${original.dataset_id}&run_id=${run}`,
      '2026-10-01',
    ),
  ).not.toMatch(/dataset_id|run_id/);
});

it('shows cold start thresholds with absent score instead of a clean zero', async () => {
  report.status = 'cold_start';
  report.score = null;
  report.baseline.active_days = 2;
  report.indicators[0].status = 'insufficient_data';
  report.indicators[0].score = 0;
  render(view());
  await analyze();
  await loaded();
  expect(screen.getByText(/Wzorzec jeszcze się buduje/)).toHaveTextContent(
    '20 zdarzeń z wiarygodnym czasem w 7 różnych dniach',
  );
  expect(screen.getByText('Odchylenie od wzorca').closest('.metric')).toHaveTextContent('—');
  expect(screen.getByText('Za mało danych do porównania')).toBeInTheDocument();
});
it('separates pending indexing from an empty or supported result', async () => {
  report.status = 'index_pending';
  report.score = null;
  report.pending_events = 8;
  report.indicators = [];
  render(view());
  await analyze();
  await loaded();
  expect(screen.getByText(/Indeks jest niepełny/)).toHaveTextContent('8 zdarzeń');
  expect(screen.getByText('Odchylenie od wzorca').closest('.metric')).toHaveTextContent('—');
});
it('renders evidence limits, baseline values, statistics and unsupported privilege facts as API text', async () => {
  report.indicators[0].evidence_total = 41;
  report.indicators[0].daily_mean = 1.5;
  report.indicators[0].daily_stddev = 0.25;
  report.indicators[0].threshold = 6;
  report.indicators[0].observed_values = ['<img src=x onerror=unsafe()>'];
  report.indicators.push({
    ...uebaIndicator,
    id: 'admin_account_use',
    status: 'unsupported',
    score: 0,
    explanation: 'Brak potwierdzonej informacji o uprawnieniach konta.',
    evidence: [],
    evidence_total: 0,
  });
  const { container } = render(view());
  await analyze();
  const list = await loaded();
  expect(within(list).getByText('Dowody: 1 z 41')).toBeInTheDocument();
  expect(screen.getByText(/Pokazano ograniczoną próbkę/)).toBeInTheDocument();
  expect(screen.getByText('1,5')).toBeInTheDocument();
  expect(screen.getByText('0,25')).toBeInTheDocument();
  expect(screen.getByText('Obserwacja: <img src=x onerror=unsafe()>')).toBeInTheDocument();
  expect(screen.getByText('Brak wymaganych informacji')).toBeInTheDocument();
  expect(container.querySelector('img,script')).toBeNull();
});
it('verifies the referenced original event with its exact day and hash on every opening', async () => {
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await analyze();
  await loaded();
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledExactlyOnceWith(original));
  const [endpoint, query] = evidenceRequests()[0][0].split('?');
  expect(endpoint).toBe(`/entities/${entitySummary.id}/ueba/events/${original.event_id}`);
  expect(Object.fromEntries(new URLSearchParams(query))).toEqual({
    mode: 'live',
    day: '2026-10-01',
    document_sha256: uebaIndicator.evidence[0].document_sha256,
  });
  expect(evidenceRequests()[0][1]?.signal).toBeInstanceOf(AbortSignal);
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledTimes(2));
  expect(evidenceRequests()).toHaveLength(2);
  expect(vi.mocked(api.request).mock.calls.some(([path]) => path.startsWith('/events/'))).toBe(
    false,
  );
});
it('verifies replay evidence within the exact dataset and run of the displayed analysis', async () => {
  const run = '60000000-0000-0000-0000-000000000006';
  report.scope = { mode: 'replay', dataset_id: original.dataset_id, run_id: run };
  const replayEvent = { ...original, mode: 'replay', run_id: run };
  vi.mocked(api.request).mockImplementation(async (path) => {
    if (path === '/auth/me') return reader;
    if (path.includes('/ueba?')) return report;
    if (path.includes('/ueba/events/')) return replayEvent;
    throw new Error(`Unexpected request: ${path}`);
  });
  const onEvent = vi.fn();
  render(view({ onEvent, params: `mode=replay&dataset_id=${original.dataset_id}&run_id=${run}` }));
  await analyze();
  await loaded();
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledExactlyOnceWith(replayEvent));
  expect(Object.fromEntries(new URLSearchParams(evidenceRequests()[0][0].split('?')[1]))).toEqual({
    mode: 'replay',
    day: '2026-10-01',
    document_sha256: uebaIndicator.evidence[0].document_sha256,
    dataset_id: original.dataset_id,
    run_id: run,
  });
});
it('preserves microseconds when checking evidence and rejects scope and ID mismatches', () => {
  const evidence = { ...uebaIndicator.evidence[0], timestamp: '2026-10-01T10:00:00.000001+00:00' };
  expect(
    matchesEvidence({ ...original, timestamp: '2026-10-01T10:00:00.000001Z' }, evidence, report),
  ).toBe(true);
  for (const changed of [
    { timestamp: '2026-10-01T10:00:00.000002Z' },
    { timestamp: 'invalid' },
    { event_id: 'other' },
    { mode: 'replay' },
    { run_id: 'other' },
  ])
    expect(matchesEvidence({ ...original, ...changed }, uebaIndicator.evidence[0], report)).toBe(
      false,
    );
  report.scope = { mode: 'replay', dataset_id: original.dataset_id, run_id: 'other' };
  expect(
    matchesEvidence(
      { ...original, mode: 'replay', run_id: 'other', dataset_id: 'wrong' },
      uebaIndicator.evidence[0],
      report,
    ),
  ).toBe(false);
});
it('refuses to open an event from another scope', async () => {
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/auth/me'
      ? reader
      : path.includes('/ueba?')
        ? report
        : { ...original, mode: 'replay' },
  );
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await analyze();
  await loaded();
  fireEvent.click(evidenceButton());
  expect(await screen.findByRole('alert')).toHaveTextContent('Zdarzenie nie pasuje');
  expect(onEvent).not.toHaveBeenCalled();
});
it('shows service errors and retries server verification of the same evidence', async () => {
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await analyze();
  await loaded();
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(503, 'service_unavailable'));
  fireEvent.click(evidenceButton());
  expect(await screen.findByRole('alert')).toHaveTextContent('Usługa jest chwilowo niedostępna');
  expect(screen.getByText(/Dowód jest sprawdzany ponownie przy otwarciu/)).toBeInTheDocument();
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledOnce());
  expect(evidenceRequests()).toHaveLength(2);
});
it('does not reopen a previously read proof when server reports a changed anomaly', async () => {
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await analyze();
  await loaded();
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledOnce());
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(409, 'ueba_changed', 'changed-proof'));
  fireEvent.click(evidenceButton());
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Wynik analizy zmienił się. Kliknij „Analizuj dzień”',
  );
  expect(screen.getByRole('alert')).toHaveTextContent('changed-proof');
  expect(onEvent).toHaveBeenCalledOnce();
  expect(evidenceRequests()).toHaveLength(2);
  await analyze();
  await loaded();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(onEvent).toHaveBeenCalledTimes(2));
});
it.each(['ueba_integrity_mismatch', 'ueba_limit_exceeded', 'forbidden'])(
  'never opens an event rejected by server evidence check: %s',
  async (code) => {
    const onEvent = vi.fn();
    render(view({ onEvent }));
    await analyze();
    await loaded();
    vi.mocked(api.request).mockRejectedValueOnce(
      new ApiError(code === 'forbidden' ? 403 : 409, code),
    );
    fireEvent.click(evidenceButton());
    await screen.findByRole('alert');
    expect(onEvent).not.toHaveBeenCalled();
    expect(evidenceRequests()).toHaveLength(1);
  },
);
it.each([
  ['ueba_limit_exceeded', 'Dane przekraczają limit'],
  ['ueba_integrity_mismatch', 'zgodności zachowanych dowodów'],
  ['invalid_ueba_day', 'zakończony dzień UTC'],
  ['entity_not_found', 'Profil nie jest dostępny'],
  ['forbidden', 'Twoja rola'],
])('explains %s without presenting a clean result', async (code, message) => {
  vi.mocked(api.request).mockImplementation(async (path) => {
    if (path === '/auth/me') return reader;
    throw new ApiError(409, code, 'test-request');
  });
  render(view());
  await analyze();
  expect(await screen.findByRole('alert')).toHaveTextContent(message);
  expect(screen.getByRole('alert')).toHaveTextContent('test-request');
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
});
it.each(['entity', 'scope', 'day'])('rejects response for a different %s', async (field) => {
  if (field === 'entity') report.entity.id = 'other';
  if (field === 'scope') report.scope.mode = 'replay';
  if (field === 'day') report.observation.from = '2026-09-30T00:00:00Z';
  render(view());
  await analyze();
  expect(await screen.findByRole('alert')).toHaveTextContent('Odpowiedź nie pasuje');
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
});
it('clears a report and checks the account again on reload', async () => {
  render(view());
  await analyze();
  await loaded();
  const auth = deferred<Me>();
  vi.mocked(api.request).mockReturnValueOnce(auth.promise);
  await analyze();
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
  await act(async () => auth.resolve(reader));
  await loaded();
  expect(requests()).toHaveLength(2);
});
it.each(['logout', 'session'] as const)(
  'clears the report immediately on %s and refuses another account',
  async (kind) => {
    render(view());
    await analyze();
    await loaded();
    await notify(kind);
    expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
    expect(screen.getByText(/Sesja zmieniła się/)).toBeInTheDocument();
    vi.mocked(api.request).mockResolvedValueOnce({ ...reader, id: 'another-user' });
    await analyze();
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Konto lub uprawnienia zmieniły się',
    );
    expect(requests()).toHaveLength(1);
  },
);
it('ignores a pending report after a session change', async () => {
  const pending = deferred<UebaReport>();
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/auth/me' ? reader : pending.promise,
  );
  render(view());
  await analyze();
  await waitFor(() => expect(requests()).toHaveLength(1));
  await notify('logout');
  await act(async () => pending.resolve(report));
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
});
it('ignores pending account verification after a session change', async () => {
  const pending = deferred<Me>();
  vi.mocked(api.request).mockReturnValueOnce(pending.promise);
  render(view());
  await analyze();
  await notify('session');
  await act(async () => pending.resolve(reader));
  expect(requests()).toHaveLength(0);
  expect(screen.getByText(/Sesja zmieniła się/)).toBeInTheDocument();
});
it('does not deliver pending proof after a session or profile change', async () => {
  const onEvent = vi.fn();
  const component = render(view({ onEvent }));
  await analyze();
  await loaded();
  const pending = deferred<SecurityEvent>();
  vi.mocked(api.request).mockReturnValueOnce(pending.promise);
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(evidenceRequests()).toHaveLength(1));
  await notify('session');
  component.rerender(view({ id: 'other-profile', onEvent }));
  await act(async () => pending.resolve(original));
  expect(onEvent).not.toHaveBeenCalled();
});
it('ignores pending results after scope navigation and clears displayed report when editing the day', async () => {
  const component = render(view());
  await analyze();
  await loaded();
  fireEvent.change(screen.getByLabelText('Dzień obserwacji · UTC'), {
    target: { value: '2026-09-30' },
  });
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
  expect(requests()).toHaveLength(1);
  const pending = deferred<UebaReport>();
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/auth/me' ? reader : pending.promise,
  );
  await analyze('2026-09-30');
  await waitFor(() => expect(requests()).toHaveLength(2));
  component.rerender(
    view({
      params: `mode=replay&dataset_id=${original.dataset_id}&run_id=60000000-0000-0000-0000-000000000006`,
    }),
  );
  await act(async () => pending.resolve(report));
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
});
it('does not deliver pending proof after changing the observation day', async () => {
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await analyze();
  await loaded();
  const pending = deferred<SecurityEvent>();
  vi.mocked(api.request).mockReturnValueOnce(pending.promise);
  fireEvent.click(evidenceButton());
  await waitFor(() => expect(evidenceRequests()).toHaveLength(1));
  fireEvent.change(screen.getByLabelText('Dzień obserwacji · UTC'), {
    target: { value: '2026-09-30' },
  });
  expect(screen.queryByRole('list', { name: 'Wskaźniki zachowania' })).not.toBeInTheDocument();
  await act(async () => pending.resolve(original));
  expect(onEvent).not.toHaveBeenCalled();
});
it('canonicalizes UUID case for requests and response scope matching', async () => {
  const id = 'aaaaaaaa-0000-0000-0000-000000000001';
  const dataset = 'bbbbbbbb-0000-0000-0000-000000000001';
  const run = 'cccccccc-0000-0000-0000-000000000001';
  report.entity.id = id;
  report.scope = { mode: 'replay', dataset_id: dataset, run_id: run };
  render(
    view({
      id: id.toUpperCase(),
      params: `mode=replay&dataset_id=${dataset.toUpperCase()}&run_id=${run.toUpperCase()}`,
    }),
  );
  await analyze();
  await loaded();
  expect(requests()[0][0]).toBe(
    `/entities/${id}/ueba?mode=replay&day=2026-10-01&dataset_id=${dataset}&run_id=${run}`,
  );
  expect(screen.getByText(report.as_of)).toBeInTheDocument();
});
