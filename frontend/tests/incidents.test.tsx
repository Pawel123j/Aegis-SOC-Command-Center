import { dashboardFixture } from './dashboardFixtures';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { App } from '../src/App';
import { AlertPicker } from '../src/incidents/AlertPicker';
import { CreateIncident } from '../src/incidents/CreateIncident';
import { IncidentDetails } from '../src/incidents/IncidentDetails';
import { Incidents } from '../src/incidents/Incidents';
import { IncidentWorkflow } from '../src/incidents/IncidentWorkflow';
import { incidentsApi } from '../src/incidents/api';
import { permittedStatuses } from '../src/incidents/labels';
import type { IncidentDetail } from '../src/incidents/types';
import { attackTimelineFixture } from './attackTimelineFixtures';
import {
  alert,
  alertDetail,
  analyst,
  incidentFixture,
  manager,
  original,
  reader,
  timestamp,
} from './incidentFixtures';

let incident: IncidentDetail;
beforeEach(() => {
  incident = structuredClone(incidentFixture);
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path.includes('/attack-timeline?'))
      return { ...attackTimelineFixture, incident_version: incident.version };
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path.startsWith('/dashboard')) return dashboardFixture;
    if (path.includes('/timeline?'))
      return { items: incident.timeline, next_cursor: null, total: incident.timeline.length };
    if (path.includes('/notes?'))
      return { items: incident.notes, next_cursor: null, total: incident.notes.length };
    if (path.includes('/evidence?')) return { items: [], next_cursor: null, total: 0 };
    if (path === '/incidents/assignees') return { items: [analyst] };
    if (path.startsWith('/incidents?')) return { items: [incident], total: 1, next_cursor: null };
    if (path.startsWith('/incidents/')) return incident;
    if (path.startsWith('/alerts?')) return { items: [alert], total: 1, next_cursor: null };
    if (path.startsWith('/alerts/')) return alertDetail;
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.spyOn(api, 'post').mockImplementation(async (path) =>
    path === '/events/search'
      ? { items: [], total: 0, next_cursor: null }
      : { ...incident, version: incident.version + 1 },
  );
  vi.spyOn(api, 'patch').mockImplementation(async (_path, body, version) => {
    incident = { ...incident, ...(body as object), version: version + 1 };
    return incident;
  });
  vi.spyOn(api, 'delete').mockResolvedValue(incident);
});

it('shows real cases to viewers with uncomputed scores and no mutation controls', async () => {
  render(<Incidents user={reader} onEvent={() => undefined} onInitialConsumed={() => undefined} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Otwórz incydent' }));
  await screen.findByText('Sprawdź wykonane polecenie.');
  expect(screen.getAllByText('Nie obliczono')).toHaveLength(3);
  expect(screen.queryByRole('button', { name: 'Powiąż alert' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Dodaj notatkę' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Status incydentu')).not.toBeInTheDocument();
  expect(api.patch).not.toHaveBeenCalled();
  expect(vi.mocked(api.get).mock.calls.some(([path]) => path === '/incidents/assignees')).toBe(
    false,
  );
});

it('exposes incident navigation to a viewer without exposing future modules', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(reader);
  vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /Incydenty/ }));
  expect(await screen.findByRole('button', { name: 'Otwórz incydent' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Nowy incydent' })).not.toBeInTheDocument();
  expect(
    screen.queryByRole('button', { name: /SOAR|Threat Intelligence|Encje/ }),
  ).not.toBeInTheDocument();
});

it('preserves incident drafts on a same-user cross-tab refresh and clears them on authority change', async () => {
  const get = vi.mocked(api.get).getMockImplementation()!;
  let me = analyst;
  vi.mocked(api.get).mockImplementation(async (path) => (path === '/auth/me' ? me : get(path)));
  vi.spyOn(api, 'restore').mockResolvedValue(analyst);
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /Incydenty/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Nowy incydent' }));
  fireEvent.change(screen.getByLabelText('Tytuł incydentu'), {
    target: { value: 'Niezapisane ustalenia' },
  });
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(screen.getByLabelText('Tytuł incydentu')).toHaveValue('Niezapisane ustalenia');
  me = reader;
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(screen.queryByLabelText('Tytuł incydentu')).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Obraz sytuacji SOC' })).toBeInTheDocument();
});

it('selects live alerts from multiple pages without pagination submitting the create form', async () => {
  const get = vi.mocked(api.get).getMockImplementation()!;
  const second = {
    ...alert,
    id: '50000000-0000-0000-0000-000000000002',
    title: 'Sesja root',
    dataset_id: 'other-dataset',
  };
  vi.mocked(api.get).mockImplementation(async (path) => {
    if (path.startsWith('/alerts?'))
      return path.includes('cursor=next')
        ? { items: [second], total: 2, next_cursor: null }
        : { items: [alert], total: 2, next_cursor: 'next' };
    return get(path);
  });
  render(<CreateIncident onClose={() => undefined} onCreated={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Tytuł incydentu'), {
    target: { value: 'Analiza wielu źródeł' },
  });
  fireEvent.click(await screen.findByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Następna' }));
  await screen.findByText('Sesja root');
  expect(api.post).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button', { name: 'Utwórz incydent' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      '/incidents',
      expect.objectContaining({ alert_ids: [alert.id, second.id] }),
      expect.anything(),
    ),
  );
});

it('retains exact creation receipt after a network failure and rotates it after a form change', async () => {
  vi.mocked(api.post).mockRejectedValue(new ApiError(0, 'network_error'));
  render(<CreateIncident onClose={() => undefined} onCreated={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Tytuł incydentu'), { target: { value: 'Nowa sprawa' } });
  const submit = screen.getByRole('button', { name: 'Utwórz incydent' });
  fireEvent.click(submit);
  await screen.findByRole('alert');
  fireEvent.click(submit);
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(submit).toBeEnabled());
  const calls = vi.mocked(api.post).mock.calls;
  expect(calls[1]).toEqual(calls[0]);
  expect(calls[0][1]).toMatchObject({ title: 'Nowa sprawa', alert_ids: [] });
  expect(calls[0][2]?.['Idempotency-Key']).toMatch(/^[0-9a-f-]{36}$/);
  fireEvent.change(screen.getByLabelText('Tytuł incydentu'), {
    target: { value: 'Zmieniona sprawa' },
  });
  fireEvent.click(submit);
  await waitFor(() => expect(api.post).toHaveBeenCalledTimes(3));
  expect(calls[2][2]?.['Idempotency-Key']).not.toBe(calls[0][2]?.['Idempotency-Key']);
});

it('keeps unsaved fields on a version conflict and requires explicit refresh before another write', async () => {
  vi.mocked(api.patch).mockRejectedValueOnce(new ApiError(412, 'version_conflict'));
  render(
    <IncidentDetails
      id={incident.id}
      user={analyst}
      onBack={() => undefined}
      onEvent={() => undefined}
    />,
  );
  const title = await screen.findByLabelText('Tytuł incydentu');
  fireEvent.change(title, { target: { value: 'Ustalenie analityka' } });
  const submit = screen.getByRole('button', { name: 'Zapisz opis, wagę i tagi' });
  fireEvent.click(submit);
  expect(await screen.findByRole('alert')).toHaveTextContent('Odśwież');
  expect(title).toHaveValue('Ustalenie analityka');
  expect(submit).toBeDisabled();
  expect(api.patch).toHaveBeenCalledWith(
    `/incidents/${incident.id}`,
    { title: 'Ustalenie analityka' },
    4,
  );
  incident = { ...incident, title: 'Zmiana drugiego analityka', version: 5 };
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież szczegóły' }));
  await waitFor(() =>
    expect(screen.getByLabelText('Tytuł incydentu')).toHaveValue('Zmiana drugiego analityka'),
  );
  fireEvent.change(screen.getByLabelText('Tytuł incydentu'), {
    target: { value: 'Nowe ustalenie' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz opis, wagę i tagi' }));
  await waitFor(() =>
    expect(api.patch).toHaveBeenLastCalledWith(
      `/incidents/${incident.id}`,
      { title: 'Nowe ustalenie' },
      5,
    ),
  );
});

it('offers the permitted status graph and requires a reason to resolve a case', async () => {
  const mutate = vi.fn(async (operation: (version: number) => Promise<IncidentDetail>) =>
    operation(4),
  );
  render(<IncidentWorkflow incident={incident} user={analyst} disabled={false} mutate={mutate} />);
  const status = screen.getByLabelText('Status incydentu');
  expect(within(status).queryByRole('option', { name: 'Zamknięty' })).not.toBeInTheDocument();
  expect(within(status).queryByRole('option', { name: 'Opanowany' })).not.toBeInTheDocument();
  fireEvent.change(status, { target: { value: 'resolved' } });
  const reason = screen.getByLabelText('Uzasadnienie zmiany statusu');
  expect(reason).toBeRequired();
  expect(reason).toHaveAttribute('maxlength', '1000');
  fireEvent.change(reason, { target: { value: '   ' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zmień status' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Podaj uzasadnienie');
  expect(mutate).not.toHaveBeenCalled();
  fireEvent.change(reason, { target: { value: 'Potwierdzono legalne działanie administratora.' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zmień status' }));
  await waitFor(() =>
    expect(api.patch).toHaveBeenCalledWith(
      `/incidents/${incident.id}`,
      {
        status: 'resolved',
        status_reason: 'Potwierdzono legalne działanie administratora.',
      },
      4,
    ),
  );
  expect(permittedStatuses('resolved', analyst.permissions)).toEqual(['closed']);
  expect(permittedStatuses('closed', analyst.permissions)).toEqual([]);
  expect(permittedStatuses('closed', manager.permissions)).toEqual(['investigating']);
});

it('uses the newly returned case version for the next note without erasing a draft description', async () => {
  render(
    <IncidentDetails
      id={incident.id}
      user={analyst}
      onBack={() => undefined}
      onEvent={() => undefined}
    />,
  );
  const description = await screen.findByLabelText('Opis incydentu');
  fireEvent.change(description, { target: { value: 'Niezapisany opis' } });
  fireEvent.click(screen.getByRole('button', { name: 'Przypisz do mnie' }));
  await waitFor(() =>
    expect(api.patch).toHaveBeenCalledWith(
      `/incidents/${incident.id}`,
      { owner_id: analyst.id },
      4,
    ),
  );
  await waitFor(() => expect(screen.getByRole('button', { name: 'Dodaj notatkę' })).toBeEnabled());
  fireEvent.change(screen.getByLabelText('Nowa notatka'), {
    target: { value: 'Weryfikacja rozpoczęta' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj notatkę' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      `/incidents/${incident.id}/notes`,
      { body: 'Weryfikacja rozpoczęta' },
      { 'If-Match': '"5"' },
    ),
  );
  expect(description).toHaveValue('Niezapisany opis');
});

it('filters replay attachments by dataset and run while live attachments can span datasets', async () => {
  const { rerender } = render(
    <AlertPicker selected={[]} onSelect={() => undefined} scope={incident} />,
  );
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/alerts?limit=50&mode=live'));
  rerender(
    <AlertPicker
      key="replay"
      selected={[]}
      onSelect={() => undefined}
      scope={{ ...incident, mode: 'replay', dataset_id: original.dataset_id, run_id: 'replay-run' }}
    />,
  );
  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith(
      `/alerts?limit=50&mode=replay&dataset_id=${original.dataset_id}&run_id=replay-run`,
    ),
  );
});

it('opens the preserved original event from a detached alert timeline and escapes analyst notes', async () => {
  incident.timeline = [
    {
      id: 'timeline-one',
      kind: 'alert_detached',
      occurred_at: timestamp,
      actor: analyst,
      data: {
        alert_id: alert.id,
        event_id: original.event_id,
        event_timestamp: timestamp,
        title: alert.title,
      },
    },
  ];
  incident.notes = [
    { id: 'note-one', body: '<script>unsafe()</script>', created_at: timestamp, author: analyst },
  ];
  const onEvent = vi.fn();
  const { container } = render(
    <IncidentDetails id={incident.id} user={reader} onBack={() => undefined} onEvent={onEvent} />,
  );
  fireEvent.click(await screen.findByRole('button', { name: 'Otwórz zdarzenie z osi czasu' }));
  await waitFor(() => expect(onEvent).toHaveBeenCalledWith(original));
  expect(api.get).toHaveBeenCalledWith(`/alerts/${alert.id}`);
  expect(await screen.findByText('<script>unsafe()</script>')).toBeInTheDocument();
  expect(container.querySelector('script')).toBeNull();
});

it('preserves actor authority, If-Match and idempotency headers across all case write contracts', async () => {
  vi.mocked(api.post).mockRestore();
  vi.mocked(api.delete).mockRestore();
  const request = vi.spyOn(api, 'request').mockResolvedValue(incident);
  await incidentsApi.create(
    { title: 'Sprawa', description: '', severity: 'high', alert_ids: [], tags: [] },
    'receipt-key',
  );
  expect(request).toHaveBeenLastCalledWith(
    '/incidents',
    expect.objectContaining({ method: 'POST', headers: { 'Idempotency-Key': 'receipt-key' } }),
  );
  await incidentsApi.attach(incident.id, alert.id, 7);
  expect(request).toHaveBeenLastCalledWith(
    `/incidents/${incident.id}/alerts`,
    expect.objectContaining({
      method: 'POST',
      headers: { 'If-Match': '"7"' },
      body: JSON.stringify({ alert_id: alert.id }),
    }),
  );
  await incidentsApi.detach(incident.id, alert.id, 8);
  expect(request).toHaveBeenLastCalledWith(`/incidents/${incident.id}/alerts/${alert.id}`, {
    method: 'DELETE',
    headers: { 'If-Match': '"8"' },
  });
  await incidentsApi.note(incident.id, 'Notatka', 9);
  expect(request).toHaveBeenLastCalledWith(
    `/incidents/${incident.id}/notes`,
    expect.objectContaining({ method: 'POST', headers: { 'If-Match': '"9"' } }),
  );
});
