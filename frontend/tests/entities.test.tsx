import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { App } from '../src/App';
import { EventDetail } from '../src/Events';
import { Entities } from '../src/entities/Entities';
import { EventProfiles } from '../src/entities/EventProfiles';
import { entityParams, profileFilterForEvent } from '../src/entities/filters';
import type { BackfillResult, EntityPage, EntitySummary } from '../src/entities/types';
import type { Me } from '../src/types';
import {
  entityActivity,
  entityAdmin,
  entityAlert,
  entityDetail,
  entityHost,
  entityIncident,
  entityPage,
  entityReader,
  entitySummary,
} from './entityFixtures';
import { alert, alertDetail, incidentFixture, original } from './incidentFixtures';
import { attackTimelineFixture } from './attackTimelineFixtures';

const listeners = new Set<(kind: 'logout' | 'session') => void>();
beforeEach(() => {
  listeners.clear();
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path.includes('/attack-timeline?')) return attackTimelineFixture;
    if (path.startsWith('/entities/by-event/')) return entityPage([entitySummary, entityHost]);
    if (path.startsWith(`/entities/${entitySummary.id}/events?`))
      return entityPage([entityActivity], 431);
    if (path.startsWith(`/entities/${entitySummary.id}/alerts?`))
      return entityPage([entityAlert], 8);
    if (path.startsWith(`/entities/${entitySummary.id}/incidents?`))
      return entityPage([entityIncident], 3);
    if (path.startsWith(`/entities/${entitySummary.id}/related?`))
      return entityPage([entityHost], 3);
    if (path.startsWith('/entities?')) return entityPage([entitySummary], 142);
    if (path.startsWith('/entities/')) return entityDetail;
    if (path.startsWith('/events/')) return original;
    throw new Error(`Unexpected test request: ${path}`);
  });
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/auth/me') return entityAdmin;
    if (path.startsWith('/alerts?')) return { items: [], total: 0, next_cursor: null };
    if (path === `/alerts/${alert.id}`) return alertDetail;
    if (path === `/incidents/${incidentFixture.id}`) return incidentFixture;
    return { items: [], total: 0, next_cursor: null };
  });
  vi.spyOn(api, 'post').mockResolvedValue({ items: [], total: 0, next_cursor: null });
});

function listRequests() {
  return vi.mocked(api.request).mock.calls.filter(([path]) => path.startsWith('/entities?'));
}
function parsed(path: string) {
  return new URL(`https://aegis.local${path}`).searchParams;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { resolve, promise };
}
function workspace(user: Me = entityReader, onEvent = vi.fn(), onCreateIncident = vi.fn()) {
  return render(<Entities user={user} onEvent={onEvent} onCreateIncident={onCreateIncident} />);
}
async function openProfile(user: Me = entityReader, onEvent = vi.fn()) {
  const component = workspace(user, onEvent);
  fireEvent.click(await screen.findByRole('button', { name: entitySummary.label }));
  await screen.findByRole('heading', { name: entitySummary.label });
  await screen.findByRole('table', { name: 'Aktywność profilu' });
  return component;
}
async function notify(kind: 'logout' | 'session') {
  await act(async () => listeners.forEach((listener) => listener(kind)));
}
function backfillResult(complete = false): BackfillResult {
  return {
    events: 25,
    alerts: 25,
    observations: 93,
    identity_policy: 'entity-identity-v1',
    index_status: {
      pending_events: complete ? 0 : 900,
      pending_alerts: complete ? 0 : 700,
      complete,
    },
  };
}
function incompleteList() {
  const page = entityPage<EntitySummary>([]);
  page.index_status = { pending_events: 7, pending_alerts: 3, complete: false };
  vi.mocked(api.request).mockResolvedValue(page);
  return page;
}

it.each(['events:read', 'alerts:read', 'incidents:read'])(
  'requires %s in the composite entity navigation and page permission',
  async (permission) => {
    const user = {
      ...entityReader,
      permissions: entityReader.permissions.filter((p) => p !== permission),
    };
    vi.spyOn(api, 'restore').mockResolvedValue(user);
    const app = render(<App />);
    await screen.findByRole('navigation');
    expect(screen.queryByRole('button', { name: 'Profile encji' })).not.toBeInTheDocument();
    app.unmount();
    workspace(user);
    expect(screen.getByText('Profile są niedostępne')).toBeInTheDocument();
    expect(api.request).not.toHaveBeenCalled();
  },
);

it('opens the entity navigation with a 30-day UTC live scope and server totals beyond the visible page', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(entityReader);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Profile encji' }));
  const table = await screen.findByRole('table', { name: 'Profile encji' });
  const params = parsed(listRequests()[0][0]);
  expect(params.get('mode')).toBe('live');
  expect(params.has('dataset_id') || params.has('run_id')).toBe(false);
  expect(params.get('from')).toMatch(/Z$/);
  expect(new Date(params.get('to')!).getTime() - new Date(params.get('from')!).getTime()).toBe(
    30 * 86400000,
  );
  expect(screen.getByText(/Profile w zakresie: 142/)).toBeInTheDocument();
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  expect(table).toHaveTextContent('431');
  expect(table).toHaveTextContent('Fałszywe alarmy: 2');
  expect(screen.getByText(/Nazwa lub adres nie potwierdzają tożsamości/)).toBeInTheDocument();
});

it.each([
  ['2026-02-01T00:00', '2026-01-01T00:00'],
  ['2024-01-01T00:00', '2026-01-01T00:00'],
  ['2099-01-01T00:00', '2099-01-02T00:00'],
])('rejects an invalid selected window %s to %s before querying', async (from, to) => {
  workspace();
  await screen.findByRole('table', { name: 'Profile encji' });
  fireEvent.change(screen.getByLabelText('Od · czas lokalny'), { target: { value: from } });
  fireEvent.change(screen.getByLabelText('Do · czas lokalny'), { target: { value: to } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('maksymalnie 366 dni');
  expect(listRequests()).toHaveLength(1);
});

it('requires exact replay IDs and discards them when returning to live', async () => {
  workspace();
  await screen.findByRole('table', { name: 'Profile encji' });
  fireEvent.change(screen.getByLabelText('Tryb profili'), { target: { value: 'replay' } });
  fireEvent.change(screen.getByLabelText('Dataset ID replay'), { target: { value: 'invalid' } });
  fireEvent.change(screen.getByLabelText('Run ID replay'), { target: { value: original.run_id } });
  fireEvent.submit(
    screen.getByRole('button', { name: 'Zastosuj zakres profili' }).closest('form')!,
  );
  expect(await screen.findByRole('alert')).toHaveTextContent('niezerowego Run ID');
  expect(listRequests()).toHaveLength(1);
  const run = '90000000-0000-0000-0000-000000000001';
  fireEvent.change(screen.getByLabelText('Run ID replay'), { target: { value: run } });
  fireEvent.change(screen.getByLabelText('Dataset ID replay'), {
    target: { value: original.run_id },
  });
  fireEvent.submit(
    screen.getByRole('button', { name: 'Zastosuj zakres profili' }).closest('form')!,
  );
  expect(await screen.findByRole('alert')).toHaveTextContent('niezerowego Dataset ID');
  expect(listRequests()).toHaveLength(1);
  fireEvent.change(screen.getByLabelText('Dataset ID replay'), {
    target: { value: original.dataset_id },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  await waitFor(() => expect(listRequests()).toHaveLength(2));
  expect(parsed(listRequests()[1][0]).get('dataset_id')).toBe(original.dataset_id);
  expect(parsed(listRequests()[1][0]).get('run_id')).toBe(run);
  fireEvent.change(screen.getByLabelText('Tryb profili'), { target: { value: 'live' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  await waitFor(() => expect(listRequests()).toHaveLength(3));
  const params = parsed(listRequests()[2][0]);
  expect(params.has('dataset_id') || params.has('run_id')).toBe(false);
});

it('keeps filter drafts separate, uses signed cursors and resets pagination after applying a different scope', async () => {
  vi.mocked(api.request).mockResolvedValue({
    ...entityPage([entitySummary], 142),
    next_cursor: 'signed.first',
  });
  workspace();
  await screen.findByRole('table', { name: 'Profile encji' });
  fireEvent.change(screen.getByLabelText('Nazwa lub adres'), { target: { value: 'alice' } });
  expect(listRequests()).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Następne profile' }));
  await waitFor(() => expect(listRequests()).toHaveLength(2));
  expect(parsed(listRequests()[1][0]).get('cursor')).toBe('signed.first');
  expect(parsed(listRequests()[1][0]).has('q')).toBe(false);
  await screen.findByText('Strona 2');
  fireEvent.click(screen.getByRole('button', { name: 'Poprzednie profile' }));
  await waitFor(() => expect(listRequests()).toHaveLength(3));
  expect(parsed(listRequests()[2][0]).has('cursor')).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  await waitFor(() => expect(listRequests()).toHaveLength(4));
  expect(parsed(listRequests()[3][0]).get('q')).toBe('alice');
  expect(parsed(listRequests()[3][0]).has('cursor')).toBe(false);
  expect(screen.getByText('Strona 1')).toBeInTheDocument();
});

it('clears an old list on reload, displays an access failure and allows retry', async () => {
  workspace();
  await screen.findByRole('table', { name: 'Profile encji' });
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(403, 'forbidden'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież profile' }));
  expect(screen.queryByRole('button', { name: entitySummary.label })).not.toBeInTheDocument();
  expect(await screen.findByRole('alert')).toHaveTextContent('Twoja rola');
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież profile' }));
  await screen.findByRole('table', { name: 'Profile encji' });
});

it('aborts a previous scope flight and ignores its late result', async () => {
  const stale = deferred<EntityPage<EntitySummary>>();
  vi.mocked(api.request).mockReturnValueOnce(stale.promise);
  workspace();
  await waitFor(() => expect(listRequests()).toHaveLength(1));
  const signal = listRequests()[0][1]!.signal!;
  fireEvent.change(screen.getByLabelText('Nazwa lub adres'), { target: { value: 'new scope' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  await screen.findByRole('button', { name: entitySummary.label });
  expect(signal.aborted).toBe(true);
  await act(async () =>
    stale.resolve(entityPage([{ ...entitySummary, label: 'PRIVATE OLD SCOPE' }])),
  );
  expect(screen.queryByText('PRIVATE OLD SCOPE')).not.toBeInTheDocument();
});

it.each(['session', 'logout'] as const)(
  'clears private profile results and rejects a late flight on %s',
  async (kind) => {
    const stale = deferred<EntityPage<EntitySummary>>();
    workspace();
    await screen.findByRole('table', { name: 'Profile encji' });
    vi.mocked(api.request).mockReturnValueOnce(stale.promise);
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież profile' }));
    await notify(kind);
    await act(async () => stale.resolve(entityPage([entitySummary])));
    expect(screen.queryByRole('table', { name: 'Profile encji' })).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Sesja zmieniła się');
  },
);

it('discards data after account replacement and does not query after losing a required permission', async () => {
  const stale = deferred<EntityPage<EntitySummary>>();
  vi.mocked(api.request).mockReturnValueOnce(stale.promise);
  const component = workspace();
  await waitFor(() => expect(listRequests()).toHaveLength(1));
  component.rerender(
    <Entities
      user={{ ...entityReader, id: 'another-account' }}
      onEvent={vi.fn()}
      onCreateIncident={vi.fn()}
    />,
  );
  await screen.findByRole('table', { name: 'Profile encji' });
  await act(async () =>
    stale.resolve(entityPage([{ ...entitySummary, label: 'OLD ACCOUNT DATA' }])),
  );
  expect(screen.queryByText('OLD ACCOUNT DATA')).not.toBeInTheDocument();
  component.rerender(
    <Entities
      user={{ ...entityReader, permissions: ['events:read'] }}
      onEvent={vi.fn()}
      onCreateIncident={vi.fn()}
    />,
  );
  expect(screen.getByText('Profile są niedostępne')).toBeInTheDocument();
  expect(listRequests()).toHaveLength(2);
});

it('distinguishes an incomplete empty index from absence and hides global backfill from readers', async () => {
  incompleteList();
  workspace();
  await screen.findByText('Profile oczekują na indeksowanie');
  expect(screen.getByText(/Zaległe zdarzenia: 7/)).toHaveTextContent('zaległe alerty: 3');
  expect(screen.queryByText('Brak profili w wybranym zakresie')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Uzupełnij indeks' })).not.toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});

it('performs exactly one explicitly global bounded backfill batch and keeps remaining pending counts visible', async () => {
  const page = incompleteList();
  const batch = deferred<BackfillResult>();
  vi.mocked(api.post).mockReturnValue(batch.promise);
  workspace(entityAdmin);
  const button = await screen.findByRole('button', { name: 'Uzupełnij indeks' });
  expect(screen.getByText(/Partia obejmuje zaległe dowody całego systemu/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Limit partii indeksu'), { target: { value: '100' } });
  fireEvent.click(button);
  fireEvent.click(button);
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/entities/backfill', { limit: 100 });
  expect(screen.getByRole('button', { name: 'Uzupełnianie indeksu…' })).toBeDisabled();
  await act(async () => batch.resolve(backfillResult()));
  await waitFor(() => expect(listRequests()).toHaveLength(2));
  expect(screen.getByText(/Partia: 25 zdarzeń/)).toHaveTextContent('900 zdarzeń i 700 alertów');
  expect(screen.getByText('Profile oczekują na indeksowanie')).toBeInTheDocument();
  expect(page.index_status.complete).toBe(false);
  expect(api.post).toHaveBeenCalledTimes(1);
});

it('clears backfill responses after session change and never reports an old mutation as current', async () => {
  incompleteList();
  const batch = deferred<BackfillResult>();
  vi.mocked(api.post).mockReturnValue(batch.promise);
  workspace(entityAdmin);
  fireEvent.click(await screen.findByRole('button', { name: 'Uzupełnij indeks' }));
  await notify('session');
  await act(async () => batch.resolve(backfillResult(true)));
  expect(screen.queryByText(/Partia: 25 zdarzeń/)).not.toBeInTheDocument();
  expect(
    screen
      .getAllByRole('alert')
      .every((notice) => notice.textContent?.includes('Sesja zmieniła się')),
  ).toBe(true);
  expect(listRequests()).toHaveLength(1);
});

it('shows a failed global backfill without turning a partial index into a complete result', async () => {
  incompleteList();
  vi.mocked(api.post).mockRejectedValue(new ApiError(403, 'forbidden'));
  workspace(entityAdmin);
  fireEvent.click(await screen.findByRole('button', { name: 'Uzupełnij indeks' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Twoja rola');
  expect(screen.getByText('Profile oczekują na indeksowanie')).toBeInTheDocument();
  expect(screen.queryByText(/Indeks kompletny/)).not.toBeInTheDocument();
});

it('resets an old signed list cursor after backfill and refreshes the first page without requesting the obsolete cursor', async () => {
  const page = entityPage([entitySummary], 100);
  page.next_cursor = 'before.backfill';
  page.index_status = { complete: false, pending_events: 10, pending_alerts: 5 };
  vi.mocked(api.request).mockResolvedValue(page);
  vi.mocked(api.post).mockResolvedValue(backfillResult());
  workspace(entityAdmin);
  await screen.findByRole('table', { name: 'Profile encji' });
  fireEvent.click(screen.getByRole('button', { name: 'Następne profile' }));
  await screen.findByText('Strona 2');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Uzupełnij indeks' })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Uzupełnij indeks' }));
  await waitFor(() => expect(listRequests()).toHaveLength(3));
  expect(parsed(listRequests()[2][0]).has('cursor')).toBe(false);
  expect(screen.getByText('Strona 1')).toBeInTheDocument();
});

it('restores an admin workspace only after the app verifies the changed session and ignores an earlier backfill result', async () => {
  incompleteList();
  const me = deferred<Me>();
  const batch = deferred<BackfillResult>();
  vi.spyOn(api, 'restore').mockResolvedValue(entityAdmin);
  vi.mocked(api.get).mockImplementation(async (path) =>
    path === '/auth/me' ? me.promise : { items: [], total: 0, next_cursor: null },
  );
  vi.mocked(api.post).mockImplementation(async (path) =>
    path === '/entities/backfill' ? batch.promise : { items: [], total: 0, next_cursor: null },
  );
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Profile encji' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Uzupełnij indeks' }));
  await notify('session');
  expect(screen.queryByRole('button', { name: 'Uzupełnij indeks' })).not.toBeInTheDocument();
  await act(async () => me.resolve(entityAdmin));
  expect(await screen.findByRole('button', { name: 'Uzupełnij indeks' })).toBeEnabled();
  await act(async () => batch.resolve(backfillResult(true)));
  expect(screen.queryByText(/Partia: 25 zdarzeń/)).not.toBeInTheDocument();
  expect(listRequests()).toHaveLength(2);
});

it('shows selected-window history, failed logins, observed identity and a transparent maximum of existing risk assessments', async () => {
  await openProfile();
  expect(screen.getByText('Zdarzenia w zakresie').closest('.metric')).toHaveTextContent('431');
  expect(screen.getByText('Zdarzenia z nieudanym logowaniem').closest('.metric')).toHaveTextContent(
    '31',
  );
  expect(screen.getByText('Powiązane hosty').nextSibling).toHaveTextContent('3');
  expect(screen.getByText('Pierwsza obserwacja w zakresie')).toBeInTheDocument();
  expect(screen.getByText('Podstawa łączenia obserwacji').nextSibling).toHaveTextContent(
    'source_scoped_sid',
  );
  expect(screen.getByText(/profil nie ma odrębnego obliczenia ryzyka/)).toBeInTheDocument();
  expect(screen.getByText('Alerty kwalifikujące się do oceny').nextSibling).toHaveTextContent('6');
  expect(screen.getByText('Alerty z bieżącą oceną').nextSibling).toHaveTextContent('5');
  screen
    .getAllByText('Pominięte fałszywe alarmy')
    .forEach((label) => expect(label.nextSibling).toHaveTextContent('2'));
  expect(screen.getByText('Alert z najwyższą oceną').nextSibling).toHaveTextContent(alert.id);
  expect(screen.getByText('Calculation ID').nextSibling).toHaveTextContent(
    entityDetail.risk.calculation_id!,
  );
  expect(screen.getByText(/Nie potwierdzają udanego ataku/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Opis techniki T1059.001' })).toHaveAttribute(
    'rel',
    'noopener noreferrer',
  );
});

it('does not invent zero risk or MITRE techniques for unassessed profiles', async () => {
  const detail = structuredClone(entityDetail);
  Object.assign(detail.risk, {
    score: null,
    level: null,
    alert_id: null,
    calculation_id: null,
    explanation: null,
  });
  detail.mitre.techniques = [];
  vi.mocked(api.request).mockImplementation(async (path) =>
    path.startsWith('/entities?')
      ? entityPage([entitySummary])
      : path.includes('/events?')
        ? entityPage([])
        : detail,
  );
  workspace();
  fireEvent.click(await screen.findByRole('button', { name: entitySummary.label }));
  await screen.findByText(/Brak oceny nie oznacza ryzyka równego zero/);
  expect(screen.getByText(/Brak mapowania do bieżącego katalogu/)).toBeInTheDocument();
  expect(screen.queryByRole('link', { name: /Opis techniki/ })).not.toBeInTheDocument();
});

it('opens the original activity proof and suppresses a late proof after changing collection', async () => {
  const onEvent = vi.fn();
  await openProfile(entityReader, onEvent);
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie' }));
  await waitFor(() => expect(onEvent).toHaveBeenCalledExactlyOnceWith(original));
  // Re-entering activity creates a fresh proof flight.
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  fireEvent.click(screen.getByRole('button', { name: 'Historia aktywności' }));
  await screen.findByRole('table', { name: 'Aktywność profilu' });
  const pending = deferred<typeof original>();
  vi.mocked(api.request).mockReturnValueOnce(pending.promise);
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie' }));
  await waitFor(() =>
    expect(vi.mocked(api.request).mock.calls.at(-1)![0]).toBe(`/events/${original.event_id}`),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  await act(async () => pending.resolve(original));
  expect(onEvent).toHaveBeenCalledTimes(1);
});

it.each([404, 503])(
  'keeps the PostgreSQL profile visible when original archive evidence fails with %s and supports retry',
  async (status) => {
    const onEvent = vi.fn();
    await openProfile(entityReader, onEvent);
    vi.mocked(api.request).mockRejectedValueOnce(
      new ApiError(status, status === 404 ? 'not_found' : 'archive_unavailable'),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie' }));
    await screen.findByRole('alert');
    expect(
      screen.getByText(/Otwarcie tego zdarzenia wymaga dostępnego archiwum/),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: entitySummary.label })).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Aktywność profilu' })).toBeInTheDocument();
    expect(onEvent).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie' }));
    await waitFor(() => expect(onEvent).toHaveBeenCalledExactlyOnceWith(original));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);

it('resets collection pagination when selecting another tab and reports collection failures without stale rows', async () => {
  await openProfile();
  const page = entityPage([entityAlert], 8);
  page.next_cursor = 'alerts.next.page';
  vi.mocked(api.request).mockResolvedValueOnce(page);
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  vi.mocked(api.request).mockResolvedValueOnce({ ...page, next_cursor: null });
  fireEvent.click(screen.getByRole('button', { name: 'Następne powiązania' }));
  await screen.findByText('Strona 2');
  const next = vi.mocked(api.request).mock.calls.at(-1)![0];
  expect(parsed(next).get('cursor')).toBe('alerts.next.page');
  fireEvent.click(screen.getByRole('button', { name: 'Historia aktywności' }));
  await screen.findByRole('table', { name: 'Aktywność profilu' });
  expect(parsed(vi.mocked(api.request).mock.calls.at(-1)![0]).has('cursor')).toBe(false);
  expect(screen.getByText('Strona 1')).toBeInTheDocument();
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(503, 'http_error'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież powiązania' }));
  await screen.findByRole('alert');
  expect(screen.queryByRole('table', { name: 'Aktywność profilu' })).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: entitySummary.label })).toBeInTheDocument();
});

it('keeps false positives in history with their contributing-event counts and opens full alert evidence', async () => {
  await openProfile();
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  const table = await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  expect(table).toHaveTextContent('Fałszywy alarm');
  expect(table).toHaveTextContent('Poza oceną ryzyka i MITRE profilu');
  expect(table).toHaveTextContent('2 z 5 zdarzeń alertu');
  expect(screen.getByText(/Rekordy w zakresie: 8/)).toBeInTheDocument();
  fireEvent.click(within(table).getByRole('button', { name: alert.title }));
  expect(await screen.findByText('Dlaczego powstał alert')).toBeInTheDocument();
  expect(
    screen.getByRole('button', { name: 'Otwórz zdarzenie 1: process_started' }),
  ).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Fałszywy alarm' })).not.toBeInTheDocument();
});

it('refreshes the maximum-risk projection after an authorized false-positive change instead of keeping the prior score', async () => {
  await openProfile(entityAdmin);
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  const table = await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  fireEvent.click(within(table).getByRole('button', { name: alert.title }));
  await screen.findByRole('button', { name: 'Fałszywy alarm' });
  const updated = structuredClone(entityDetail);
  Object.assign(updated.risk, {
    score: null,
    level: null,
    alert_id: null,
    calculation_id: null,
    explanation: null,
    assessed_alerts: 0,
  });
  vi.mocked(api.request).mockImplementation(async (path) =>
    path.includes('/alerts?')
      ? entityPage([entityAlert])
      : path.includes('/events?')
        ? entityPage([entityActivity])
        : updated,
  );
  vi.spyOn(api, 'patch').mockResolvedValue({
    ...alertDetail,
    status: 'false_positive',
    version: 2,
  });
  vi.mocked(api.get).mockResolvedValue({ ...alertDetail, status: 'false_positive', version: 2 });
  fireEvent.click(screen.getByRole('button', { name: 'Fałszywy alarm' }));
  await screen.findByText(/Brak oceny nie oznacza ryzyka równego zero/);
  expect(api.patch).toHaveBeenCalledExactlyOnceWith(
    `/alerts/${alert.id}`,
    { status: 'false_positive' },
    alertDetail.version,
  );
  expect(screen.queryByLabelText('Ryzyko: 72 z 100, Wysokie')).not.toBeInTheDocument();
});

it('clears open profile collections and alert evidence on authority change and starts the replacement identity on its first list page', async () => {
  const component = await openProfile(entityAdmin);
  fireEvent.click(screen.getByRole('button', { name: 'Alerty profilu' }));
  const table = await screen.findByRole('table', { name: 'Alerty powiązane z profilem' });
  const late = deferred<typeof alertDetail>();
  vi.mocked(api.get).mockReturnValueOnce(late.promise);
  fireEvent.click(within(table).getByRole('button', { name: alert.title }));
  component.rerender(
    <Entities
      user={{ ...entityReader, id: 'new-reader' }}
      onEvent={vi.fn()}
      onCreateIncident={vi.fn()}
    />,
  );
  await screen.findByRole('table', { name: 'Profile encji' });
  await act(async () => late.resolve(alertDetail));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: entitySummary.label })).not.toBeInTheDocument();
  expect(screen.queryByText('Dlaczego powstał alert')).not.toBeInTheDocument();
});

it('opens closed incidents through active links and lists related hosts using the host filter', async () => {
  await openProfile();
  fireEvent.click(screen.getByRole('button', { name: 'Incydenty profilu' }));
  const table = await screen.findByRole('table', { name: 'Incydenty powiązane z profilem' });
  expect(table).toHaveTextContent('Zamknięty');
  fireEvent.click(within(table).getByRole('button', { name: entityIncident.title }));
  await screen.findByRole('heading', { name: incidentFixture.title });
  await screen.findByText('Brak wpisów na osi czasu');
  fireEvent.click(screen.getByRole('button', { name: '← Wszystkie incydenty' }));
  await screen.findByRole('table', { name: 'Incydenty powiązane z profilem' });
  fireEvent.click(screen.getByRole('button', { name: 'Hosty w tych samych zdarzeniach' }));
  await screen.findByRole('button', { name: entityHost.label });
  const request = vi.mocked(api.request).mock.calls.find(([path]) => path.includes('/related?'))!;
  expect(parsed(request[0]).get('kind')).toBe('host');
});

it('escapes observed labels and identity metadata and blocks unsafe MITRE URLs', async () => {
  const payload = '<img src=x onerror=attack()><script>attack()</script>';
  const detail = structuredClone(entityDetail);
  detail.label = payload;
  detail.canonical_identity = { label: payload };
  detail.mitre.techniques[0].name = payload;
  detail.mitre.techniques[0].url = 'https://attack.mitre.org@evil.example/techniques/T1059/001/';
  vi.mocked(api.request).mockImplementation(async (path) =>
    path.startsWith('/entities?')
      ? entityPage([entitySummary])
      : path.includes('/events?')
        ? entityPage([])
        : detail,
  );
  const component = workspace();
  fireEvent.click(await screen.findByRole('button', { name: entitySummary.label }));
  await screen.findByRole('heading', { name: payload });
  expect(component.container.querySelector('img,script')).toBeNull();
  expect(screen.queryByRole('link', { name: /Opis techniki/ })).not.toBeInTheDocument();
});

it('resolves profiles from the authoritative event lookup while preserving field-based event searches', async () => {
  const onProfile = vi.fn();
  const onFilter = vi.fn();
  render(
    <EventDetail event={original} onClose={vi.fn()} onFilter={onFilter} onProfile={onProfile} />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'alice' }));
  expect(onFilter).toHaveBeenCalledExactlyOnceWith('user.name', 'alice');
  const button = await screen.findByRole('button', { name: /Konto LAB/ });
  fireEvent.click(button);
  expect(onProfile).toHaveBeenCalledExactlyOnceWith(entitySummary.id);
  const path = vi.mocked(api.request).mock.calls[0][0];
  expect(path).toContain(`/entities/by-event/${original.event_id}?`);
  expect(parsed(path).get('from')).toBe(new Date(original.timestamp).toISOString());
  expect(
    new Date(parsed(path).get('to')!).getTime() - new Date(parsed(path).get('from')!).getTime(),
  ).toBe(1);
});

it('opens an event profile through the app with the authoritative ID and removes list-only label and kind filters from profile requests', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(entityReader);
  vi.mocked(api.post).mockImplementation(async (path) =>
    path === '/events/search'
      ? { items: [original], total: 1, next_cursor: null }
      : { items: [], total: 0, next_cursor: null },
  );
  render(<App />);
  await screen.findByText(original.event.action);
  fireEvent.click(screen.getByRole('button', { name: new RegExp(original.event.action) }));
  fireEvent.click(await screen.findByRole('button', { name: /Konto LAB/ }));
  await screen.findByRole('heading', { name: entitySummary.label });
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  const profile = vi
    .mocked(api.request)
    .mock.calls.find(([path]) => path.startsWith(`/entities/${entitySummary.id}?`))!;
  expect(parsed(profile[0]).get('mode')).toBe('live');
  expect(new Date(parsed(profile[0]).get('from')!).getTime()).toBeLessThan(
    new Date(original.timestamp).getTime(),
  );
  fireEvent.change(screen.getByLabelText('Nazwa lub adres'), { target: { value: 'search label' } });
  fireEvent.change(screen.getByLabelText('Typ encji'), { target: { value: 'user' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres profili' }));
  fireEvent.click(await screen.findByRole('button', { name: entitySummary.label }));
  await screen.findByRole('heading', { name: entitySummary.label });
  const latest = vi
    .mocked(api.request)
    .mock.calls.filter(([path]) => path.startsWith(`/entities/${entitySummary.id}?`))
    .at(-1)!;
  expect(parsed(latest[0]).has('q') || parsed(latest[0]).has('kind')).toBe(false);
});

it('isolates replay event profiles by exact dataset and run and keeps a historical event inside the profile window', async () => {
  const replay = {
    ...original,
    mode: 'replay' as const,
    run_id: '90000000-0000-0000-0000-000000000001',
    timestamp: '2025-01-01T12:00:00.123Z',
  };
  render(<EventProfiles event={replay} onProfile={vi.fn()} />);
  await screen.findByRole('button', { name: /Konto LAB/ });
  const params = parsed(vi.mocked(api.request).mock.calls[0][0]);
  expect(params.get('dataset_id')).toBe(replay.dataset_id);
  expect(params.get('run_id')).toBe(replay.run_id);
  const profile = parsed(`/entities?${entityParams(profileFilterForEvent(replay))}`);
  expect(new Date(profile.get('from')!).getTime()).toBeLessThan(
    new Date(replay.timestamp).getTime(),
  );
  expect(new Date(profile.get('to')!).getTime()).toBeGreaterThan(
    new Date(replay.timestamp).getTime(),
  );
});

it('does not fetch profiles from a future event and does not expose profile data without the profile callback', () => {
  const future = { ...original, timestamp: '2099-01-01T00:00:00Z' };
  const component = render(<EventProfiles event={future} onProfile={vi.fn()} />);
  expect(screen.getByText('Profile wymagają przeszłego czasu zdarzenia.')).toBeInTheDocument();
  component.unmount();
  render(<EventDetail event={original} onClose={vi.fn()} onFilter={vi.fn()} />);
  expect(screen.queryByRole('region', { name: 'Profile tego zdarzenia' })).not.toBeInTheDocument();
  expect(api.request).not.toHaveBeenCalled();
});
