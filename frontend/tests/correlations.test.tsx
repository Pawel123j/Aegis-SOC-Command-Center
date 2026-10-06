import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { App } from '../src/App';
import { Alerts } from '../src/Alerts';
import { Correlations } from '../src/detections/Correlations';
import { CorrelationTest } from '../src/detections/CorrelationTest';
import { IncidentDetails } from '../src/incidents/IncidentDetails';
import { IncidentEvidence } from '../src/incidents/IncidentEvidence';
import { EventEvidence } from '../src/evidence/EventEvidence';
import {
  correlationAlert,
  correlationAnalyst,
  correlationManager,
  correlationResult,
  correlationRule,
  contributors,
} from './correlationFixtures';
import { alert, incidentFixture, reader, timestamp } from './incidentFixtures';
import { attackTimelineFixture } from './attackTimelineFixtures';

beforeEach(() => {
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path.includes('/attack-timeline?')) return attackTimelineFixture;
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/auth/me') return correlationAnalyst;
    if (path === '/correlations') return { items: [correlationRule], next_cursor: null };
    if (path === '/correlations/status') return { counts: {}, scopes: [], scopes_truncated: false };
    if (path.startsWith('/correlations/')) return correlationRule;
    if (path === '/detections') return { items: [], next_cursor: null };
    if (path.includes('/timeline?'))
      return {
        items: [
          {
            id: 'timeline-detach',
            kind: 'alert_detached',
            occurred_at: timestamp,
            actor: null,
            data: {
              alert_id: alert.id,
              event_id: contributors[5].event_id,
              event_timestamp: contributors[5].timestamp,
            },
          },
        ],
        next_cursor: null,
      };
    if (path.includes('/notes?') || path.includes('/evidence?'))
      return { items: [], next_cursor: null };
    if (path.startsWith('/incidents/')) return incidentFixture;
    if (path.startsWith('/alerts/')) return correlationAlert;
    if (path.startsWith('/alerts?'))
      return { items: [correlationAlert], next_cursor: null, total: 1 };
    return { items: [], next_cursor: null, total: 0 };
  });
  vi.spyOn(api, 'post').mockImplementation(async (path) =>
    path === '/correlations/test' ? correlationResult : { items: [], next_cursor: null, total: 0 },
  );
  vi.spyOn(api, 'patch').mockResolvedValue({ ...correlationRule, enabled: false, version: 4 });
});

it('shows sequence counts, time, stable identities and nested AND/OR to a reader without mutation controls', async () => {
  render(<Correlations user={reader} onEvent={() => undefined} />);
  fireEvent.click(
    await screen.findByRole('button', { name: `Przejrzyj regułę: ${correlationRule.title}` }),
  );
  await screen.findByText('Sekwencja w kolejności czasu zdarzeń');
  expect(screen.getByText('Minimalna liczba zdarzeń: 5')).toBeInTheDocument();
  expect(screen.getByText('600 s (10 min)')).toBeInTheDocument();
  expect(
    screen.getByText('Ten sam użytkownik + Ten sam host + Ten sam IP źródłowy'),
  ).toBeInTheDocument();
  expect(screen.getByText('Wszystkie warunki (AND)')).toBeInTheDocument();
  expect(screen.getByText('Dowolny warunek (OR)')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Uruchom test korelacji' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Wyłącz regułę' })).not.toBeInTheDocument();
  expect(api.patch).not.toHaveBeenCalled();
});

it('runs an isolated complete-set test and opens every submitted contributing proof without creating alerts or cases', async () => {
  const onEvent = vi.fn();
  render(<CorrelationTest rule={correlationRule} onEvent={onEvent} />);
  fireEvent.change(screen.getByLabelText('Zdarzenia korelacji (JSON array)'), {
    target: { value: JSON.stringify(contributors) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom test korelacji' }));
  await screen.findByText('Dopasowania: 1');
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/correlations/test', {
    id: correlationRule.id,
    events: contributors,
  });
  expect(screen.getByText('Zdarzenia dowodowe (6)')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 1: login_failed' }));
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 6: login_success' }));
  expect(onEvent.mock.calls).toEqual([[contributors[0]], [contributors[5]]]);
  expect(api.patch).not.toHaveBeenCalled();
});

it('blocks malformed, empty, oversized count and oversized UTF-8 test requests before sending them', async () => {
  render(<CorrelationTest rule={correlationRule} onEvent={() => undefined} />);
  const payload = screen.getByLabelText('Zdarzenia korelacji (JSON array)');
  const submit = screen.getByRole('button', { name: 'Uruchom test korelacji' });
  for (const invalid of [
    '{',
    '[]',
    JSON.stringify(Array(101).fill(contributors[0])),
    JSON.stringify([{ ...contributors[0], raw_event: 'ą'.repeat(33000) }]),
  ]) {
    fireEvent.change(payload, { target: { value: invalid } });
    fireEvent.click(submit);
    await screen.findByRole('alert');
    expect(submit).toBeEnabled();
  }
  expect(screen.getByRole('alert')).toHaveTextContent('64 KiB');
  expect(api.post).not.toHaveBeenCalled();
});

it('distinguishes no matches from an incomplete test and from unavailable contributing proof', async () => {
  vi.mocked(api.post)
    .mockResolvedValueOnce({ ...correlationResult, matches: [] })
    .mockResolvedValueOnce({ ...correlationResult, complete: false, matches: [] })
    .mockResolvedValueOnce({
      ...correlationResult,
      matches: [{ ...correlationResult.matches[0], event_ids: ['missing-event'] }],
    });
  render(<CorrelationTest rule={correlationRule} onEvent={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Zdarzenia korelacji (JSON array)'), {
    target: { value: JSON.stringify(contributors) },
  });
  const submit = screen.getByRole('button', { name: 'Uruchom test korelacji' });
  fireEvent.click(submit);
  await screen.findByText('Dopasowania: 0');
  fireEvent.click(submit);
  await screen.findByText('Wynik niekompletny');
  expect(screen.queryByText('Dopasowania: 0')).not.toBeInTheDocument();
  fireEvent.click(submit);
  await screen.findByText('Nie wszystkie dowody są dostępne w przesłanym zestawie.');
  expect(screen.queryByRole('button', { name: /Otwórz zdarzenie/ })).not.toBeInTheDocument();
});

it('sends the displayed deployment version and requires explicit refresh after a toggle conflict', async () => {
  vi.mocked(api.patch).mockRejectedValueOnce(new ApiError(412, 'version_conflict'));
  render(<Correlations user={correlationManager} onEvent={() => undefined} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Wyłącz regułę' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Odśwież');
  expect(api.patch).toHaveBeenCalledWith(
    `/correlations/${correlationRule.id}`,
    { enabled: false },
    3,
  );
  expect(screen.getByRole('button', { name: 'Wyłącz regułę' })).toBeDisabled();
  vi.mocked(api.get).mockResolvedValueOnce({
    items: [{ ...correlationRule, version: 4 }],
    next_cursor: null,
  });
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież korelacje' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Wyłącz regułę' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Wyłącz regułę' }));
  await waitFor(() =>
    expect(api.patch).toHaveBeenLastCalledWith(
      `/correlations/${correlationRule.id}`,
      { enabled: false },
      4,
    ),
  );
});

it('keeps a correlation test draft across rule tabs and a same-user auth refresh', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(correlationAnalyst);
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /Reguły detekcji/ }));
  fireEvent.click(screen.getByRole('tab', { name: 'Korelacja zdarzeń' }));
  fireEvent.click(
    await screen.findByRole('button', { name: `Przejrzyj regułę: ${correlationRule.title}` }),
  );
  const input = await screen.findByLabelText('Zdarzenia korelacji (JSON array)');
  fireEvent.change(input, { target: { value: '["szkic"]' } });
  fireEvent.click(screen.getByRole('tab', { name: 'Pojedyncze zdarzenia' }));
  fireEvent.click(screen.getByRole('tab', { name: 'Korelacja zdarzeń' }));
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(screen.getByLabelText('Zdarzenia korelacji (JSON array)')).toHaveValue('["szkic"]');
});

it('shows all six preserved events from an alert and opens the selected contributor', async () => {
  const onEvent = vi.fn();
  render(<Alerts user={reader} onEvent={onEvent} onCreateIncident={() => undefined} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  await screen.findByText('Zdarzenia dowodowe (6)');
  expect(
    screen.getByText(
      'Dopasowano kolejne etapy w oknie 600 s. Wspólne encje: użytkownik, host, IP źródłowy.',
    ),
  ).toBeInTheDocument();
  expect(
    screen.getByText('Nieudane logowania · zdarzenia dowodowe: 5 · wymagane: 5'),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 2: login_failed' }));
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(contributors[1]);
});

it('opens detached timeline correlation evidence in a picker before opening the original selected event', async () => {
  const onEvent = vi.fn();
  render(
    <IncidentDetails
      id={incidentFixture.id}
      user={reader}
      onBack={() => undefined}
      onEvent={onEvent}
    />,
  );
  fireEvent.click(await screen.findByRole('button', { name: 'Otwórz zdarzenie z osi czasu' }));
  const dialog = await screen.findByRole('dialog', { name: correlationRule.title });
  expect(onEvent).not.toHaveBeenCalled();
  expect(within(dialog).getAllByRole('button', { name: /Otwórz zdarzenie/ })).toHaveLength(6);
  fireEvent.click(
    within(dialog).getByRole('button', { name: 'Otwórz zdarzenie 6: login_success' }),
  );
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(contributors[5]);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('retains each immutable event hash and escapes source log text in detached incident evidence', async () => {
  const unsafe = '<script>unsafe-source()</script>';
  const event = { ...contributors[0], source: { ...contributors[0].source, name: unsafe } };
  vi.mocked(api.get).mockResolvedValue({
    items: [
      {
        id: 'proof',
        alert_id: alert.id,
        event_id: contributors[5].event_id,
        event_timestamp: timestamp,
        linked_at: timestamp,
        active: false,
        detached_at: timestamp,
        event_sha256: 'a'.repeat(64),
        rule_snapshot: {},
        reason: {},
        event_snapshot: contributors[5],
        event_snapshots: [
          { event_id: event.event_id, event_sha256: 'b'.repeat(64), event_snapshot: event },
          correlationAlert.event_snapshots![5],
        ],
      },
    ],
    next_cursor: null,
  });
  const onEvent = vi.fn();
  const { container } = render(<IncidentEvidence incident={incidentFixture} onEvent={onEvent} />);
  await screen.findByText('Alert odpięty');
  expect(screen.getByText('Zdarzenia dowodowe (2)')).toBeInTheDocument();
  expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
  expect(container).toHaveTextContent(unsafe);
  expect(container.querySelector('script')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 1: login_failed' }));
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(event);
});

it('ignores a delayed authority response after logout rather than reopening protected views', async () => {
  let resolveAuthority!: (value: typeof correlationAnalyst) => void;
  const authority = new Promise<typeof correlationAnalyst>((resolve) => {
    resolveAuthority = resolve;
  });
  const get = vi.mocked(api.get).getMockImplementation()!;
  vi.mocked(api.get).mockImplementation((path) => (path === '/auth/me' ? authority : get(path)));
  vi.spyOn(api, 'restore').mockResolvedValue(correlationAnalyst);
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  await screen.findByRole('navigation');
  act(() => subscribe.mock.calls[0][0]('session'));
  act(() => subscribe.mock.calls[0][0]('logout'));
  await screen.findByLabelText('Hasło');
  await act(async () => resolveAuthority(correlationAnalyst));
  expect(screen.getByLabelText('Hasło')).toBeInTheDocument();
  expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
});

it('ignores a delayed startup session when logout has already invalidated that restoration', async () => {
  let resolveRestore!: (value: typeof correlationAnalyst) => void;
  vi.spyOn(api, 'restore').mockReturnValue(
    new Promise((resolve) => {
      resolveRestore = resolve;
    }),
  );
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  act(() => subscribe.mock.calls[0][0]('logout'));
  await act(async () => resolveRestore(correlationAnalyst));
  expect(await screen.findByLabelText('Hasło')).toBeInTheDocument();
  expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
});

it('shows incomplete coverage, late records and truncated replay ranges explicitly', async () => {
  const get = vi.mocked(api.get).getMockImplementation()!;
  vi.mocked(api.get).mockImplementation(async (path) =>
    path === '/correlations/status'
      ? {
          counts: { late: 3, incomplete: 2, processed: 10 },
          scopes: [
            {
              namespace: 'replay:dataset:run',
              watermark: null,
              sealed_at: null,
              event_count: 0,
              manifest_sha256: null,
            },
          ],
          scopes_truncated: true,
        }
      : get(path),
  );
  render(<Correlations user={reader} onEvent={() => undefined} />);
  const late = await screen.findByText('Spóźnione');
  expect(late.closest('.metric')).toHaveTextContent('3');
  expect(screen.getByText('Niekompletne').closest('.metric')).toHaveTextContent('2');
  expect(screen.getByText('Przetworzone').closest('.metric')).toHaveTextContent('10');
  expect(screen.getByText('Oczekuje na zamknięcie')).toBeInTheDocument();
  expect(
    screen.getByText('Widok pokazuje pierwsze 100 zakresów. Lista zakresów jest niepełna.'),
  ).toBeInTheDocument();
});

it('reports duplicate event IDs as a rejected test rather than as no matches', async () => {
  vi.mocked(api.post).mockRejectedValueOnce(new ApiError(422, 'duplicate_event_id'));
  render(<CorrelationTest rule={correlationRule} onEvent={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Zdarzenia korelacji (JSON array)'), {
    target: { value: JSON.stringify([contributors[0], contributors[0]]) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom test korelacji' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Usuń powtórzone rekordy');
  expect(screen.queryByText('Dopasowania: 0')).not.toBeInTheDocument();
});

it('clears preserved proof when current authority fails before a different user logs in', async () => {
  const get = vi.mocked(api.get).getMockImplementation()!;
  vi.mocked(api.get).mockImplementation((path) =>
    path === '/auth/me' ? Promise.reject(new ApiError(401, 'unauthorized')) : get(path),
  );
  vi.spyOn(api, 'restore').mockResolvedValue(correlationAnalyst);
  vi.spyOn(api, 'login').mockResolvedValue({ ...reader, id: 'another-user', username: 'viewer2' });
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /^◉Alerty$|^Alerty$/ }));
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Otwórz zdarzenie 1: login_failed' }));
  expect(await screen.findByRole('dialog', { name: 'login_failed' })).toBeInTheDocument();
  await act(async () => subscribe.mock.calls[0][0]('session'));
  fireEvent.change(await screen.findByLabelText('Nazwa użytkownika'), {
    target: { value: 'viewer2' },
  });
  fireEvent.change(screen.getByLabelText('Hasło'), { target: { value: 'a-long-test-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zaloguj się' }));
  expect(await screen.findByRole('heading', { name: 'Obraz sytuacji' })).toBeInTheDocument();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('distinguishes the actor changing an administrator group from its target and the Windows login account', () => {
  const memberChange = {
    ...contributors[0],
    source: { ...contributors[0].source, type: 'windows_auth' },
    event: { ...contributors[0].event, category: 'iam', code: '4732' },
    user: {
      ...contributors[0].user,
      name: 'alice',
      target: { id: null, name: 'bob', realm: null },
    },
  };
  const login = {
    ...memberChange,
    event_id: contributors[1].event_id,
    event: { ...memberChange.event, category: 'authentication', code: '4624' },
    user: { ...memberChange.user, name: 'SYSTEM' },
  };
  render(
    <EventEvidence
      events={[memberChange, login].map((event) => ({
        event_id: event.event_id,
        event_sha256: '',
        event_snapshot: event,
      }))}
      onEvent={() => undefined}
    />,
  );
  expect(screen.getByText('Wykonawca: alice')).toBeInTheDocument();
  expect(screen.getByText('Konto docelowe: bob')).toBeInTheDocument();
  expect(screen.getByText('Konto logowania: bob')).toBeInTheDocument();
  expect(screen.getByText('Wykonawca: SYSTEM')).toBeInTheDocument();
});
