import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { Dashboard } from '../src/dashboard/Dashboard';
import { canReadDashboard } from '../src/dashboard/types';
import type { DashboardReport } from '../src/dashboard/types';
import { dashboardFixture } from './dashboardFixtures';

const listeners = new Set<(kind: 'session' | 'logout') => void>();
let row: DashboardReport;
beforeEach(() => {
  row = structuredClone(dashboardFixture);
  listeners.clear();
  vi.spyOn(api, 'get').mockImplementation(async () => structuredClone(row));
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
});
afterEach(() => vi.useRealTimers());
function show() {
  return render(
    <Dashboard
      onEvents={() => undefined}
      onAlerts={() => undefined}
      onIncidents={() => undefined}
    />,
  );
}
async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
}
function deferred() {
  let resolve!: (value: DashboardReport) => void;
  const promise = new Promise<DashboardReport>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

it('shows real counts, time basis, zero ingestion and unassessed risk', async () => {
  const { container } = show();
  await screen.findByText('Zdarzenia · 24 h');
  expect(screen.getByText('Zdarzenia · 24 h').parentElement).toHaveTextContent('12');
  expect(screen.getByText('Alerty · 24 h').parentElement).toHaveTextContent('3');
  expect(screen.getByText('Brak oceny')).toBeInTheDocument();
  expect(screen.getByText('0.000 zdarzeń/s')).toBeInTheDocument();
  expect(screen.getByText(/Czas przyjęcia, po deduplikacji/)).toBeInTheDocument();
  expect(container.innerHTML).not.toMatch(/NaN|Infinity/);
});
it('does not show a fabricated zero while a report is loading', async () => {
  const pending = deferred();
  vi.mocked(api.get).mockReturnValue(pending.promise);
  show();
  await flush();
  expect(screen.queryByText('Zdarzenia · 24 h')).not.toBeInTheDocument();
  await act(async () => pending.resolve(row));
  expect(screen.getByText('Zdarzenia · 24 h')).toBeInTheDocument();
});
it('shows pending indexes explicitly and renders labels as text', async () => {
  row.index_status = { pending_events: 2, indexed_events: 10, entities_partial: true };
  const label = '<img src=x onerror=attack()>';
  row.top.users = [{ id: 'user-one', label, count: 4, identity_basis: 'host_scoped' }];
  const { container } = show();
  expect(await screen.findByText(label)).toBeInTheDocument();
  expect(screen.getByText(/Rankingi encji są niepełne: 2/)).toBeInTheDocument();
  expect(container.querySelector('img')).toBeNull();
});
it('requires an exact replay scope before changing the displayed report', async () => {
  show();
  await screen.findByText('Zdarzenia · 24 h');
  const calls = vi.mocked(api.get).mock.calls.length;
  fireEvent.change(screen.getByLabelText('Dane'), { target: { value: 'replay' } });
  fireEvent.change(screen.getByLabelText('Zestaw replay'), { target: { value: 'invalid' } });
  fireEvent.change(screen.getByLabelText('Przebieg replay'), { target: { value: 'invalid' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('identyfikator');
  expect(vi.mocked(api.get).mock.calls).toHaveLength(calls);
});
it('sends fixed UTC time, false-positive choice and exact replay IDs', async () => {
  show();
  await screen.findByText('Zdarzenia · 24 h');
  fireEvent.change(screen.getByLabelText('Dane'), { target: { value: 'replay' } });
  fireEvent.change(screen.getByLabelText('Zestaw replay'), {
    target: { value: '10000000-0000-0000-0000-000000000001' },
  });
  fireEvent.change(screen.getByLabelText('Przebieg replay'), {
    target: { value: '20000000-0000-0000-0000-000000000002' },
  });
  fireEvent.change(screen.getByLabelText('Koniec okna (UTC)'), {
    target: { value: '2026-10-01T12:00' },
  });
  fireEvent.click(screen.getByLabelText('Uwzględnij fałszywe alarmy'));
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  await flush();
  const path = vi.mocked(api.get).mock.calls.at(-1)![0];
  const params = new URL(`http://localhost${path}`).searchParams;
  expect(params.get('mode')).toBe('replay');
  expect(params.get('to')).toBe('2026-10-01T12:00:00Z');
  expect(params.get('run_id')).toBe('20000000-0000-0000-0000-000000000002');
  expect(params.get('include_false_positives')).toBe('true');
});
it('keeps the last good report with a stale warning on temporary failure', async () => {
  show();
  await screen.findByText('Zdarzenia · 24 h');
  vi.mocked(api.get).mockRejectedValue(new ApiError(503, 'unavailable'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież Dashboard' }));
  expect(await screen.findByText(/Wyświetlane dane są nieaktualne/)).toBeInTheDocument();
  expect(screen.getByText('Zdarzenia · 24 h')).toBeInTheDocument();
});
it('clears old data and stops polling after revoked permission', async () => {
  vi.useFakeTimers();
  show();
  await flush();
  vi.mocked(api.get).mockRejectedValue(new ApiError(403, 'forbidden'));
  await act(async () => vi.advanceTimersByTimeAsync(10_000));
  expect(screen.queryByText('Zdarzenia · 24 h')).not.toBeInTheDocument();
  const calls = vi.mocked(api.get).mock.calls.length;
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(vi.mocked(api.get).mock.calls).toHaveLength(calls);
});
it('polls only after the prior request finishes and can be paused', async () => {
  vi.useFakeTimers();
  show();
  await flush();
  const pending = deferred();
  vi.mocked(api.get).mockReturnValue(pending.promise);
  await act(async () => vi.advanceTimersByTimeAsync(10_000));
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(api.get).toHaveBeenCalledTimes(2);
  await act(async () => pending.resolve(row));
  fireEvent.click(screen.getByLabelText('Automatyczne odświeżanie co 10 sekund'));
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(api.get).toHaveBeenCalledTimes(2);
});
it('suspends polling while the page is hidden and resumes on visibility', async () => {
  vi.useFakeTimers();
  show();
  await flush();
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
  fireEvent(document, new Event('visibilitychange'));
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(api.get).toHaveBeenCalledTimes(1);
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
  fireEvent(document, new Event('visibilitychange'));
  await act(async () => vi.advanceTimersByTimeAsync(10_000));
  expect(api.get).toHaveBeenCalledTimes(2);
});
it('discards in-flight results after a session change', async () => {
  const pending = deferred();
  vi.mocked(api.get).mockReturnValue(pending.promise);
  show();
  await flush();
  await act(async () => {
    listeners.forEach((listener) => listener('session'));
  });
  await act(async () => pending.resolve(row));
  expect(screen.queryByText('Zdarzenia · 24 h')).not.toBeInTheDocument();
  expect(screen.getByText(/Sesja się zmieniła/)).toBeInTheDocument();
});
it('discards the previous scope response after applying another window', async () => {
  const first = deferred();
  const second = deferred();
  vi.mocked(api.get).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  show();
  await flush();
  fireEvent.change(screen.getByLabelText('Koniec okna (UTC)'), {
    target: { value: '2026-10-01T12:00' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  await flush();
  await act(async () => first.resolve(row));
  expect(screen.queryByText('Zdarzenia · 24 h')).not.toBeInTheDocument();
  await act(async () => second.resolve({ ...row, counts: { ...row.counts, events_24h: 93 } }));
  expect(screen.getByText('Zdarzenia · 24 h').parentElement).toHaveTextContent('93');
});
it('requires every read permission for the aggregate dashboard', () => {
  const permissions = ['events:read', 'alerts:read', 'incidents:read', 'detections:read'];
  const user = { id: 'reader', username: 'reader', role: 'read_only' as const, permissions };
  expect(canReadDashboard(user)).toBe(true);
  for (const missing of permissions)
    expect(
      canReadDashboard({ ...user, permissions: permissions.filter((p) => p !== missing) }),
    ).toBe(false);
});
