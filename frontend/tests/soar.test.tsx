import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import type { Me } from '../src/types';
import type { Playbook, Run, Targets } from '../src/soar/types';
import { actionLabel } from '../src/soar/types';
import { Soar, AlertSoar } from '../src/soar/Soar';
import { RunDetails } from '../src/soar/RunDetails';
import { useSigmaScope } from '../src/sigma/useSigmaScope';

const actor: Me = {
  id: '10000000-0000-0000-0000-000000000001',
  username: 'analyst',
  role: 'soc_manager',
  permissions: [
    'playbooks:read',
    'playbooks:run',
    'playbooks:manage',
    'events:read',
    'alerts:read',
    'incidents:read',
    'incidents:edit',
    'intelligence:read',
    'intelligence:manage',
  ],
};
const bookId = '20000000-0000-0000-0000-000000000001';
const alertId = '30000000-0000-0000-0000-000000000001';
const runId = '40000000-0000-0000-0000-000000000001';
const eventId = '50000000-0000-0000-0000-000000000001';
const zero = '00000000-0000-0000-0000-000000000000';
const at = '2026-10-08T08:00:00Z';
let books: Playbook[];
let row: Run;
let me: Me;
let targets: Targets;
let failStart: boolean;
const listeners = new Set<(kind: 'logout' | 'session') => void>();

beforeEach(() => {
  listeners.clear();
  me = structuredClone(actor);
  failStart = false;
  const definition = {
    schema_version: 1 as const,
    title: 'Obsługa alertu',
    description: 'Lokalny plan',
    steps: [
      { id: 'case', action: 'create_incident' },
      { id: 'notice', action: 'notify_analyst' },
      { id: 'block', action: 'simulate_block_ip' },
    ],
  };
  books = [
    {
      id: bookId,
      version: 2,
      enabled: true,
      latest_revision: 1,
      published_revision: 1,
      definition,
      published_definition: definition,
      required_permissions: ['playbooks:run', 'incidents:edit'],
    },
  ];
  targets = {
    alert_id: alertId,
    title: 'Zaobserwowany alert',
    anchor_event_id: eventId,
    mode: 'live',
    dataset_id: '60000000-0000-0000-0000-000000000001',
    data_run_id: zero,
    items: [
      {
        event_id: eventId,
        timestamp: at,
        source_ip: '192.0.2.1',
        destination_ip: '198.51.100.1',
        host: 'host',
      },
    ],
  };
  row = {
    id: runId,
    alert_id: alertId,
    playbook_id: bookId,
    revision: 1,
    definition,
    state: 'completed',
    created_at: at,
    started_at: at,
    finished_at: at,
    deadline_at: at,
    next_attempt_at: at,
    requested_by: actor.id,
    mode: 'live',
    dataset_id: targets.dataset_id,
    data_run_id: zero,
    replay_of: null,
    error_code: null,
    context: {
      event_id: eventId,
      ip_field: 'source',
      ip: '192.0.2.1',
      host: 'host',
      alert_title: targets.title,
    },
    steps: definition.steps.map((step, index) => ({
      ...step,
      position: index,
      state: 'completed',
      attempts: 1,
      error_code: null,
      not_executed_reason: null,
      started_at: at,
      finished_at: at,
      output:
        index === 2
          ? { simulated: true, reason: 'SIMULATION: IP 192.0.2.1 zostałby zablokowany.' }
          : { local_effect: true, reason: 'Zapisano lokalnie.' },
      history: [
        { number: 1, outcome: 'completed', started_at: at, finished_at: at, error_code: null },
      ],
    })),
  };
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  vi.spyOn(api, 'request').mockImplementation(async (path, options) => {
    if (path === '/auth/me') return me;
    if (path === '/playbooks/actions')
      return {
        actions: Object.entries(actionLabel).map(([id, label]) => ({
          id,
          label,
          required_permission: 'playbooks:run',
        })),
      };
    if (path === '/playbooks') return options?.method ? books[0] : { items: books };
    if (path.startsWith('/playbook-targets/')) return targets;
    if (path === `/playbooks/${bookId}/runs`) {
      if (failStart) throw new Error('Połączenie przerwane');
      return row;
    }
    if (path.startsWith(`/playbooks/${bookId}`)) return books[0];
    if (path === `/playbook-runs/${runId}/cancel`) {
      row.state = 'cancelled';
      return row;
    }
    if (path === `/playbook-runs/${runId}`) return structuredClone(row);
    if (path.startsWith('/playbook-runs?')) return { items: [row], next_cursor: null };
    if (path.startsWith('/soar-notifications')) return { items: [], next_cursor: null };
    throw new Error(`Unexpected request ${path}`);
  });
});

async function launchView(user = actor) {
  render(<AlertSoar user={user} alertId={alertId} />);
  fireEvent.click(screen.getByRole('button', { name: 'Procedury SOAR dla alertu' }));
  await screen.findByLabelText('Opublikowana procedura');
  fireEvent.change(screen.getByLabelText('Opublikowana procedura'), { target: { value: bookId } });
}
function startCalls() {
  return vi.mocked(api.request).mock.calls.filter(([path]) => path === `/playbooks/${bookId}/runs`);
}
async function start() {
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom w trybie SIMULATION' }));
}
function Detail({ user = actor }: { user?: Me }) {
  const scope = useSigmaScope();
  return (
    <RunDetails
      id={runId}
      user={user}
      scope={scope}
      books={books}
      onRun={vi.fn()}
      onClose={vi.fn()}
    />
  );
}

it('shows real catalog and publication state without automatic writes', async () => {
  render(<Soar user={actor} />);
  expect(await screen.findByRole('heading', { name: 'Obsługa alertu' })).toBeInTheDocument();
  expect(screen.getByText(/Ostatnia wersja: 1/)).toBeInTheDocument();
  expect(vi.mocked(api.request).mock.calls.every(([, options]) => !options?.method)).toBe(true);
});

it.each(['playbooks:read', 'events:read', 'alerts:read', 'incidents:read', 'intelligence:read'])(
  'does not expose SOAR without %s',
  async (permission) => {
    render(
      <Soar user={{ ...actor, permissions: actor.permissions.filter((p) => p !== permission) }} />,
    );
    await act(async () => undefined);
    expect(api.request).not.toHaveBeenCalled();
  },
);

it('shows an honest empty catalog', async () => {
  books = [];
  render(<Soar user={actor} />);
  expect(await screen.findByRole('heading', { name: 'Brak procedur' })).toBeInTheDocument();
});

it('readers can inspect procedures but have no edit or run controls', async () => {
  const reader: Me = {
    ...actor,
    role: 'read_only',
    permissions: actor.permissions.filter(
      (p) =>
        !['playbooks:manage', 'playbooks:run', 'incidents:edit', 'intelligence:manage'].includes(p),
    ),
  };
  render(<Soar user={reader} />);
  await screen.findByRole('heading', { name: 'Obsługa alertu' });
  expect(screen.queryByRole('button', { name: 'Nowa procedura' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Opublikuj/ })).not.toBeInTheDocument();
});

it('requires an explicit plan review and sends simulation with verified event and idempotency key', async () => {
  await launchView();
  expect(screen.getByRole('button', { name: 'Uruchom w trybie SIMULATION' })).toBeDisabled();
  expect(
    screen.getByText(/Blokada IP, izolacja hosta i webhook są wyłącznie symulacją/),
  ).toBeInTheDocument();
  await start();
  await screen.findByRole('heading', { name: 'Przebieg procedury' });
  expect(startCalls()).toHaveLength(1);
  const options = startCalls()[0][1]!;
  expect(JSON.parse(options.body as string)).toEqual({
    revision: 1,
    alert_id: alertId,
    event_id: eventId,
    ip_field: 'source',
    execution_mode: 'simulation',
    replay_of: null,
  });
  expect(new Headers(options.headers).get('Idempotency-Key')).toMatch(/^[a-f0-9-]{36}$/);
  const paths = vi.mocked(api.request).mock.calls.map(([path]) => path);
  expect(paths.indexOf('/auth/me')).toBeLessThan(paths.indexOf(`/playbooks/${bookId}/runs`));
});

it('keeps the same idempotency key after an ambiguous failed response', async () => {
  failStart = true;
  await launchView();
  await start();
  expect(await screen.findByRole('alert')).toHaveTextContent('Połączenie przerwane');
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom w trybie SIMULATION' }));
  await waitFor(() => expect(startCalls()).toHaveLength(2));
  expect(new Headers(startCalls()[0][1]?.headers).get('Idempotency-Key')).toBe(
    new Headers(startCalls()[1][1]?.headers).get('Idempotency-Key'),
  );
});

it('changing the IP resets explicit review', async () => {
  await launchView();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.change(screen.getByLabelText('Adres do analizy'), { target: { value: 'destination' } });
  expect(screen.getByRole('checkbox')).not.toBeChecked();
  expect(startCalls()).toHaveLength(0);
});

it('does not offer unpublished or disabled versions', async () => {
  books[0].enabled = false;
  await launchView();
  expect(screen.getByText(/Brak dostępnej opublikowanej procedury/)).toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});

it('rejects an authority change before sending a mutation', async () => {
  await launchView();
  me = { ...actor, role: 'read_only', permissions: [] };
  await start();
  expect(await screen.findByRole('alert')).toHaveTextContent('Uprawnienia zmieniły się');
  expect(startCalls()).toHaveLength(0);
});

it.each(['logout', 'session'] as const)('hides workflow data on %s', async (kind) => {
  await launchView();
  await act(async () => listeners.forEach((listener) => listener(kind)));
  expect(screen.getByText(/Sesja zmieniła się/)).toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});

it('stores drafts without publishing or starting them', async () => {
  render(<Soar user={actor} />);
  await screen.findByRole('heading', { name: 'Obsługa alertu' });
  fireEvent.click(screen.getByRole('button', { name: 'Nowa procedura' }));
  fireEvent.change(screen.getByLabelText('Nazwa'), { target: { value: 'Nowy plan' } });
  fireEvent.submit(screen.getByRole('button', { name: 'Zapisz wersję roboczą' }).closest('form')!);
  await waitFor(() =>
    expect(
      vi
        .mocked(api.request)
        .mock.calls.some(([path, options]) => path === '/playbooks' && options?.method === 'POST'),
    ).toBe(true),
  );
  expect(
    vi
      .mocked(api.request)
      .mock.calls.some(([path]) => path.endsWith('/publish') || path.endsWith('/runs')),
  ).toBe(false);
});

it('publishes a chosen version with an optimistic concurrency check', async () => {
  books[0].published_revision = null;
  books[0].published_definition = null;
  render(<Soar user={actor} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Opublikuj wersję 1' }));
  await waitFor(() =>
    expect(vi.mocked(api.request).mock.calls.some(([path]) => path.endsWith('/publish'))).toBe(
      true,
    ),
  );
  const call = vi.mocked(api.request).mock.calls.find(([path]) => path.endsWith('/publish'))!;
  expect(new Headers(call[1]?.headers).get('If-Match')).toBe('"2"');
  expect(JSON.parse(call[1]?.body as string)).toEqual({ revision: 1 });
});

it('shows simulation output separately from actual local effects', async () => {
  render(<Detail />);
  expect(
    await screen.findByText('SIMULATION: IP 192.0.2.1 zostałby zablokowany.'),
  ).toBeInTheDocument();
  expect(screen.getAllByText('Zapisano w aplikacji')).toHaveLength(2);
  expect(screen.queryByRole('button', { name: 'Zatrzymaj dalsze kroki' })).not.toBeInTheDocument();
});

it('can cancel only an active authorized run', async () => {
  row.state = 'running';
  row.finished_at = null;
  render(<Detail />);
  fireEvent.click(await screen.findByRole('button', { name: 'Zatrzymaj dalsze kroki' }));
  expect(await screen.findByText('Anulowano')).toBeInTheDocument();
  expect(vi.mocked(api.request).mock.calls.some(([path]) => path.endsWith('/cancel'))).toBe(true);
});

it('an analyst cannot cancel somebody else’s run', async () => {
  row.state = 'running';
  const other = {
    ...actor,
    id: 'other',
    permissions: actor.permissions.filter((p) => p !== 'playbooks:manage'),
  };
  render(<Detail user={other} />);
  await screen.findByText('W trakcie');
  expect(screen.queryByRole('button', { name: 'Zatrzymaj dalsze kroki' })).not.toBeInTheDocument();
});

it('manual replay displays a new plan and retains the old run reference', async () => {
  row.state = 'failed';
  render(<Detail />);
  fireEvent.click(await screen.findByRole('button', { name: 'Przejrzyj plan ponowienia' }));
  await screen.findByLabelText('Opublikowana procedura');
  expect(screen.getByText(/To nowe wykonanie/)).toBeInTheDocument();
  await start();
  await waitFor(() => expect(startCalls()).toHaveLength(1));
  expect(JSON.parse(startCalls()[0][1]?.body as string).replay_of).toBe(runId);
});

it('history starts in live and requires applying a complete replay scope', async () => {
  render(<Soar user={actor} />);
  fireEvent.click(screen.getByRole('button', { name: 'Historia wykonań' }));
  await screen.findByText(/Wyświetlony zakres: live/);
  fireEvent.change(screen.getByLabelText('Dane'), { target: { value: 'replay' } });
  fireEvent.change(screen.getByLabelText('Dataset'), { target: { value: targets.dataset_id } });
  fireEvent.change(screen.getByLabelText('Przebieg danych'), { target: { value: runId } });
  fireEvent.submit(screen.getByRole('button', { name: 'Zastosuj zakres' }).closest('form')!);
  await waitFor(() =>
    expect(
      vi
        .mocked(api.request)
        .mock.calls.some(
          ([path]) =>
            path ===
            `/playbook-runs?mode=replay&dataset_id=${targets.dataset_id}&data_run_id=${runId}`,
        ),
    ).toBe(true),
  );
});
