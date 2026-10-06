import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { EventDetail } from '../src/Events';
import { AttackTimeline } from '../src/incidents/AttackTimeline';
import type { AttackTimelinePage } from '../src/incidents/types';
import { attackTimelineFixture } from './attackTimelineFixtures';
import { analyst, incidentFixture, original, reader } from './incidentFixtures';
import type { Me } from '../src/types';

let page: AttackTimelinePage;
const listeners = new Set<(kind: 'logout' | 'session') => void>();
beforeEach(() => {
  page = structuredClone(attackTimelineFixture);
  listeners.clear();
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path === '/auth/me') return reader;
    if (path.includes('/attack-timeline?')) return page;
    throw new Error(`Unexpected request: ${path}`);
  });
});
function view(overrides: Partial<Parameters<typeof AttackTimeline>[0]> = {}) {
  return (
    <AttackTimeline
      incident={incidentFixture}
      user={reader}
      onEvent={vi.fn()}
      onIncidentRefresh={vi.fn()}
      refreshKey={0}
      paused={false}
      {...overrides}
    />
  );
}
function requests() {
  return vi.mocked(api.request).mock.calls.filter(([path]) => path.includes('/attack-timeline?'));
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
async function loaded() {
  return screen.findByRole('list', { name: 'Chronologia zachowanych zdarzeń' });
}

it.each(['incidents:read', 'alerts:read', 'events:read'])(
  'makes no timeline requests without %s',
  async (permission) => {
    render(
      view({
        user: { ...reader, permissions: reader.permissions.filter((item) => item !== permission) },
      }),
    );
    expect(screen.getByText(/Odczyt chronologii wymaga/)).toBeInTheDocument();
    await act(async () => undefined);
    expect(api.request).not.toHaveBeenCalled();
    expect(api.subscribe).not.toHaveBeenCalled();
  },
);

it('renders API chronology with microseconds intact, deduplicated evidence and all alert references', async () => {
  const secondAlert = {
    ...page.items[0].alerts[0],
    id: '50000000-0000-0000-0000-000000000002',
    title: 'Korelacja kilku logów',
    status: 'false_positive' as const,
    detection_type: 'correlation' as const,
  };
  page.items[0].alerts.push(secondAlert);
  page.items[0].event_snapshot.timestamp = '2026-10-01T10:00:00.000001Z';
  page.items[0].event_snapshot.received_at = '2026-10-02T10:00:00Z';
  page.items.push({
    ...structuredClone(page.items[0]),
    event_id: '20000000-0000-0000-0000-000000000000',
    alerts: [secondAlert],
    event_snapshot: {
      ...original,
      event_id: '20000000-0000-0000-0000-000000000000',
      timestamp: '2026-10-01T10:00:00.000002Z',
      event: { ...original.event, action: 'second_observation' },
    },
  });
  page.total = 2;
  render(view());
  const list = await loaded();
  const nodes = within(list)
    .getAllByRole('listitem')
    .filter((item) => item.parentElement === list);
  expect(nodes).toHaveLength(2);
  expect(nodes[0]).toHaveTextContent(original.event.action);
  expect(nodes[1]).toHaveTextContent('second_observation');
  expect(list.querySelectorAll('time')[0]).toHaveAttribute(
    'datetime',
    '2026-10-01T10:00:00.000001Z',
  );
  expect(list.querySelectorAll('time')[1]).toHaveAttribute(
    'datetime',
    '2026-10-01T10:00:00.000002Z',
  );
  expect(within(nodes[0]).getByText('Powiązane alerty (2)')).toBeInTheDocument();
  expect(within(nodes[0]).getByText('Fałszywy alarm')).toBeInTheDocument();
  expect(within(nodes[0]).getByText('Korelacja')).toBeInTheDocument();
  expect(screen.getByText('2 różnych zdarzeń w indeksie')).toBeInTheDocument();
  expect(api.request).toHaveBeenCalledExactlyOnceWith(
    `/incidents/${incidentFixture.id}/attack-timeline?limit=25`,
    expect.objectContaining({ signal: expect.any(AbortSignal) }),
  );
});

it('opens the exact preserved snapshot in the existing event dialog without requesting the archive', async () => {
  const onEvent = vi.fn();
  const component = render(view({ onEvent }));
  await loaded();
  fireEvent.click(
    screen.getByRole('button', { name: `Otwórz oryginalne zdarzenie: ${original.event.action}` }),
  );
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(page.items[0].event_snapshot);
  component.rerender(
    <EventDetail event={onEvent.mock.calls[0][0]} onClose={vi.fn()} onFilter={vi.fn()} />,
  );
  expect(screen.getByRole('dialog')).toHaveTextContent('<script>untrusted-log</script>');
  expect(screen.getByText('Oryginalny log')).toBeInTheDocument();
  expect(requests()).toHaveLength(1);
  expect(vi.mocked(api.request).mock.calls.some(([path]) => path.startsWith('/events/'))).toBe(
    false,
  );
});

it('distinguishes incomplete legacy indexing from a complete empty chronology and never backfills on GET', async () => {
  page.items = [];
  page.total = 0;
  page.index_status = { eligible_alerts: 3, indexed_alerts: 0, pending_alerts: 3, complete: false };
  const component = render(view());
  await screen.findByText('Nie ma jeszcze zindeksowanych zdarzeń');
  expect(screen.getByText(/3 alertów czeka na indeksowanie/)).toBeInTheDocument();
  expect(screen.getByText(/Brak wpisów nie oznacza braku zdarzeń/)).toBeInTheDocument();
  expect(
    vi
      .mocked(api.request)
      .mock.calls.every(
        ([path, options]) => path.includes('/attack-timeline?') && !options?.method,
      ),
  ).toBe(true);
  page.index_status = { eligible_alerts: 0, indexed_alerts: 0, pending_alerts: 0, complete: true };
  component.rerender(view({ refreshKey: 1 }));
  await screen.findByText('Brak zdarzeń w chronologii');
  expect(screen.queryByText(/Widok jest niepełny/)).not.toBeInTheDocument();
});

it('labels received time substitution and keeps actor and target accounts distinct', async () => {
  page.items[0].event_snapshot.quality = ['timestamp_from_received_at'];
  page.items[0].event_snapshot.user = {
    ...original.user,
    name: 'SYSTEM',
    target: { id: null, name: 'alice', realm: 'EXAMPLE' },
  };
  render(view());
  await loaded();
  expect(screen.getByText(/Brak czasu źródłowego: pokazany czas/)).toBeInTheDocument();
  expect(screen.getByText('SYSTEM')).toBeInTheDocument();
  expect(screen.getByText('EXAMPLE\\alice')).toBeInTheDocument();
  expect(screen.getByText('Wykonawca')).toBeInTheDocument();
  expect(screen.getByText('Konto docelowe')).toBeInTheDocument();
});

it('preserves exact replay scope and presents untrusted event and alert strings only as text', async () => {
  const run = '70000000-0000-0000-0000-000000000007';
  page.mode = 'replay';
  page.dataset_id = original.dataset_id;
  page.run_id = run;
  page.items[0].event_snapshot = {
    ...original,
    mode: 'replay',
    run_id: run,
    event: { ...original.event, action: '<img src=x onerror=unsafe()>' },
    source: { ...original.source, name: 'https://unsafe.example/path' },
  };
  page.items[0].alerts[0].title = '<script>alert-title</script>';
  const { container } = render(
    view({
      incident: {
        ...incidentFixture,
        mode: 'replay',
        dataset_id: original.dataset_id,
        run_id: run,
      },
    }),
  );
  await loaded();
  expect(screen.getByText('Replay · aktywne powiązania')).toBeInTheDocument();
  expect(screen.getByText(original.dataset_id)).toBeInTheDocument();
  expect(screen.getByText(run)).toBeInTheDocument();
  expect(screen.getByText('<script>alert-title</script>')).toBeInTheDocument();
  expect(container.querySelector('img,script,a[href]')).toBeNull();
  expect(vi.mocked(api.request).mock.calls.some(([path]) => path.startsWith('http'))).toBe(false);
});

it('uses signed cursors, keeps global totals and clears the page when page size changes', async () => {
  const next = {
    ...page,
    next_cursor: null,
    total: 70,
    items: [
      {
        ...page.items[0],
        event_id: 'next-event',
        event_snapshot: {
          ...original,
          event_id: 'next-event',
          event: { ...original.event, action: 'later_observation' },
        },
      },
    ],
  };
  page.total = 70;
  page.next_cursor = 'signed+/cursor';
  vi.mocked(api.request).mockImplementation(async (path) =>
    path.includes('cursor=') ? next : page,
  );
  render(view());
  await loaded();
  fireEvent.click(screen.getByRole('button', { name: 'Następna' }));
  await screen.findByText('later_observation');
  expect(screen.queryByRole('heading', { name: original.event.action })).not.toBeInTheDocument();
  expect(requests().at(-1)![0]).toContain('cursor=signed%2B%2Fcursor');
  expect(screen.getByText('70 różnych zdarzeń w indeksie')).toBeInTheDocument();
  expect(screen.getByText('Strona 2')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Zdarzeń na stronie'), { target: { value: '5' } });
  await screen.findByRole('heading', { name: original.event.action });
  expect(requests().at(-1)![0]).toBe(`/incidents/${incidentFixture.id}/attack-timeline?limit=5`);
  expect(screen.getByText('Strona 1')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Poprzednia' })).toBeDisabled();
});

it.each(['version', 'refresh', 'case'])(
  'resets a cursor and rejects a late old page after %s changes',
  async (change) => {
    const pending = deferred<AttackTimelinePage>();
    page.next_cursor = 'old-page';
    vi.mocked(api.request).mockImplementation(async (path) =>
      path.includes('cursor=') ? pending.promise : page,
    );
    const onEvent = vi.fn();
    const component = render(view({ onEvent }));
    await loaded();
    fireEvent.click(screen.getByRole('button', { name: 'Następna' }));
    await waitFor(() => expect(requests()).toHaveLength(2));
    const signal = requests()[1][1]!.signal!;
    const incident =
      change === 'case'
        ? { ...incidentFixture, id: '60000000-0000-0000-0000-000000000002' }
        : {
            ...incidentFixture,
            version: change === 'version' ? incidentFixture.version + 1 : incidentFixture.version,
          };
    component.rerender(view({ onEvent, incident, refreshKey: change === 'refresh' ? 1 : 0 }));
    await loaded();
    expect(signal.aborted).toBe(true);
    expect(requests().at(-1)![0]).toBe(`/incidents/${incident.id}/attack-timeline?limit=25`);
    await act(async () =>
      pending.resolve({
        ...page,
        items: [
          {
            ...page.items[0],
            event_snapshot: { ...original, event: { ...original.event, action: 'stale_page' } },
          },
        ],
      }),
    );
    expect(screen.queryByText('stale_page')).not.toBeInTheDocument();
    expect(screen.getByText('Strona 1')).toBeInTheDocument();
    expect(onEvent).not.toHaveBeenCalled();
  },
);

it.each(['session', 'logout'] as const)(
  'aborts and discards a late response after %s',
  async (kind) => {
    const pending = deferred<AttackTimelinePage>();
    vi.mocked(api.request).mockReturnValue(pending.promise);
    render(view());
    await waitFor(() => expect(requests()).toHaveLength(1));
    const signal = requests()[0][1]!.signal!;
    await notify(kind);
    expect(signal.aborted).toBe(true);
    await act(async () => pending.resolve(page));
    expect(
      screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Sesja zmieniła się/)).toBeInTheDocument();
  },
);

it('checks the current account before restoring evidence after a session change', async () => {
  const me = deferred<Me>();
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/auth/me' ? me.promise : page,
  );
  render(view());
  await loaded();
  await notify('session');
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież chronologię' }));
  expect(screen.getByText('Sprawdzanie bieżącego konta…')).toBeInTheDocument();
  expect(requests()).toHaveLength(1);
  expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
  await act(async () => me.resolve(reader));
  await loaded();
  expect(requests()).toHaveLength(2);
  expect(requests().at(-1)![0]).not.toContain('cursor=');
});

it('rejects a click on still-rendered evidence in the same batch as session invalidation', async () => {
  const onEvent = vi.fn();
  render(view({ onEvent }));
  await loaded();
  const button = screen.getByRole('button', {
    name: `Otwórz oryginalne zdarzenie: ${original.event.action}`,
  });
  await act(async () => {
    listeners.forEach((listener) => listener('session'));
    fireEvent.click(button);
  });
  expect(onEvent).not.toHaveBeenCalled();
  expect(
    screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
  ).not.toBeInTheDocument();
});

it('discards old evidence clicks after the current incident version changes', async () => {
  const onEvent = vi.fn();
  const component = render(view({ onEvent }));
  await loaded();
  const oldButton = screen.getByRole('button', {
    name: `Otwórz oryginalne zdarzenie: ${original.event.action}`,
  });
  const pending = deferred<AttackTimelinePage>();
  vi.mocked(api.request).mockReturnValue(pending.promise);
  component.rerender(
    view({ incident: { ...incidentFixture, version: incidentFixture.version + 1 }, onEvent }),
  );
  fireEvent.click(oldButton);
  expect(onEvent).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
  await act(async () =>
    pending.resolve({ ...page, incident_version: incidentFixture.version + 1 }),
  );
  await loaded();
  expect(onEvent).not.toHaveBeenCalled();
});

it.each(['account', 'role', 'permission'])(
  'rejects restoring private evidence when current %s differs',
  async (change) => {
    render(view());
    await loaded();
    await notify('session');
    const me =
      change === 'account'
        ? { ...reader, id: 'other-account' }
        : change === 'role'
          ? analyst
          : {
              ...reader,
              permissions: reader.permissions.filter((value) => value !== 'events:read'),
            };
    vi.mocked(api.request).mockResolvedValue(me);
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież chronologię' }));
    await screen.findByText(/Konto lub uprawnienia zmieniły się/);
    expect(requests()).toHaveLength(1);
    expect(
      screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
    ).not.toBeInTheDocument();
  },
);

it('aborts current-account verification when another session arrives and rejects its late result', async () => {
  const me = deferred<Me>();
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/auth/me' ? me.promise : page,
  );
  render(view());
  await loaded();
  await notify('session');
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież chronologię' }));
  await waitFor(() => expect(api.request).toHaveBeenCalledWith('/auth/me', expect.anything()));
  const signal = vi.mocked(api.request).mock.calls.find(([path]) => path === '/auth/me')![1]!
    .signal!;
  await notify('session');
  expect(signal.aborted).toBe(true);
  await act(async () => me.resolve(reader));
  expect(requests()).toHaveLength(1);
  expect(
    screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
  ).not.toBeInTheDocument();
});

it('clears old evidence immediately on role removal and aborts pending requests', async () => {
  const pending = deferred<AttackTimelinePage>();
  vi.mocked(api.request).mockReturnValue(pending.promise);
  const component = render(view());
  await waitFor(() => expect(requests()).toHaveLength(1));
  const signal = requests()[0][1]!.signal!;
  component.rerender(view({ user: { ...reader, permissions: ['incidents:read'] } }));
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve(page));
  expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
  expect(screen.getByText(/Odczyt chronologii wymaga/)).toBeInTheDocument();
});

it('clears proof during case refresh without exposing stale rows or retaining a cursor', async () => {
  const component = render(view());
  await loaded();
  component.rerender(view({ paused: true }));
  expect(
    screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
  component.rerender(view({ refreshKey: 1 }));
  await loaded();
  expect(requests().at(-1)![0]).not.toContain('cursor=');
});

it.each([
  ['attack_timeline_integrity_mismatch', /Nie można potwierdzić zgodności/],
  ['attack_timeline_limit_exceeded', /Sprawa przekracza limit chronologii/],
  ['attack_timeline_page_too_large', /Wybierz mniej zdarzeń/],
] as const)('shows %s without inventing proof and can reduce page size', async (code, message) => {
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(409, code));
  render(view());
  await screen.findByText(message);
  expect(
    screen.queryByRole('list', { name: 'Chronologia zachowanych zdarzeń' }),
  ).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Zdarzeń na stronie'), { target: { value: '1' } });
  await loaded();
  expect(requests().at(-1)![0]).toContain('limit=1');
});

it('requires verified refresh of both case and chronology on fingerprint conflict', async () => {
  page.next_cursor = 'signed';
  const onIncidentRefresh = vi.fn();
  const mock = vi.mocked(api.request).getMockImplementation()!;
  vi.mocked(api.request).mockImplementation(async (path, options) => {
    if (path.includes('cursor=')) throw new ApiError(409, 'attack_timeline_changed');
    return mock(path, options);
  });
  render(view({ onIncidentRefresh }));
  await loaded();
  fireEvent.click(screen.getByRole('button', { name: 'Następna' }));
  await screen.findByText(/Sprawa, powiązane alerty lub indeks/);
  expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież sprawę i chronologię' }));
  await loaded();
  expect(onIncidentRefresh).toHaveBeenCalledOnce();
  expect(api.request).toHaveBeenCalledWith('/auth/me', expect.anything());
  expect(requests().at(-1)![0]).not.toContain('cursor=');
});

it('accepts a newer first-page version and requests explicit case refresh', async () => {
  page.incident_version++;
  const onIncidentRefresh = vi.fn();
  render(view({ onIncidentRefresh }));
  await loaded();
  expect(screen.getByText(/Chronologia pochodzi z innej wersji/)).toBeInTheDocument();
  expect(onIncidentRefresh).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież sprawę i chronologię' }));
  await waitFor(() => expect(onIncidentRefresh).toHaveBeenCalledOnce());
});

it.each([401, 403, 404, 503])(
  'shows HTTP %i and retries only after checking current authority',
  async (status) => {
    vi.mocked(api.request).mockRejectedValueOnce(
      new ApiError(
        status,
        status === 401
          ? 'unauthorized'
          : status === 403
            ? 'forbidden'
            : status === 404
              ? 'incident_not_found'
              : 'http_error',
      ),
    );
    render(view());
    await screen.findByRole('alert');
    expect(screen.queryByRole('button', { name: /Otwórz oryginalne/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież chronologię' }));
    await loaded();
    expect(api.request).toHaveBeenCalledWith('/auth/me', expect.anything());
    expect(requests()).toHaveLength(2);
  },
);
