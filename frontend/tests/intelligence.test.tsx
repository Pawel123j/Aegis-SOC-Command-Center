import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { App } from '../src/App';
import { Alerts } from '../src/Alerts';
import { EventDetail } from '../src/Events';
import { EventIntelligence } from '../src/intelligence/EventIntelligence';
import { Intelligence } from '../src/intelligence/Intelligence';
import type { Ioc, IocLookupResult, IocPage } from '../src/intelligence/types';
import { alert, alertDetail, original, reader } from './incidentFixtures';
import {
  eventIocProof,
  intelligenceManager,
  intelligenceAdmin,
  intelligenceReader,
  ioc,
  iocHistory,
  iocLookup,
  iocPage,
  iocProviders,
} from './intelligenceFixtures';

const listeners = new Set<(kind: 'logout' | 'session') => void>();
beforeEach(() => {
  listeners.clear();
  vi.spyOn(api, 'subscribe').mockImplementation((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  vi.spyOn(api, 'request').mockImplementation(async (path) => {
    if (path === '/intelligence/providers') return iocProviders;
    if (path.startsWith('/intelligence/iocs?')) return iocPage;
    if (path.startsWith(`/intelligence/iocs/${ioc.id}/history`)) return iocHistory;
    if (path === `/intelligence/iocs/${ioc.id}`) return ioc;
    if (path.startsWith('/intelligence/events/')) return eventIocProof;
    throw new Error(`Unexpected test request: ${path}`);
  });
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/auth/me') return intelligenceManager;
    if (path === `/intelligence/iocs/${ioc.id}`)
      return { ...ioc, version: 3, revision: 3, source: 'Nowsze źródło' };
    if (path.startsWith('/alerts?'))
      return { items: [{ ...alert, detection_type: 'intelligence' }], total: 1, next_cursor: null };
    if (path === `/alerts/${alert.id}`) return { ...alertDetail, detection_type: 'intelligence' };
    return { items: [], total: 0, next_cursor: null };
  });
  vi.spyOn(api, 'post').mockImplementation(async (path) => {
    if (path === '/intelligence/lookup') return iocLookup;
    if (path === '/intelligence/iocs') return ioc;
    if (path === '/intelligence/import') return { items: [ioc], created: 1, unchanged: 0 };
    return { items: [], total: 0, next_cursor: null };
  });
  vi.spyOn(api, 'patch').mockResolvedValue({ ...ioc, revision: 2, version: 2 });
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function workspace(user = intelligenceReader) {
  return render(<Intelligence user={user} />);
}
function listRequests() {
  return vi
    .mocked(api.request)
    .mock.calls.filter(([path]) => path.startsWith('/intelligence/iocs?'));
}
function params(path: string) {
  return new URL(`https://aegis.local${path}`).searchParams;
}
async function notify(kind: 'session' | 'logout') {
  await act(async () => listeners.forEach((listener) => listener(kind)));
}
async function details(user = intelligenceReader) {
  const component = workspace(user);
  fireEvent.click(await screen.findByRole('button', { name: ioc.value }));
  await screen.findByRole('heading', { name: 'Szczegóły wskaźnika' });
  return component;
}
async function create() {
  workspace(intelligenceManager);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj IOC' }));
  return screen.getByLabelText('Wartość wskaźnika');
}
async function importer() {
  workspace(intelligenceManager);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Importuj IOC' }));
  return screen.getByLabelText('Wskaźniki IOC · tablica JSON');
}
function submitEditor() {
  fireEvent.submit(screen.getByRole('button', { name: 'Zapisz IOC' }).closest('form')!);
}

it('gates navigation and all catalogue requests on intelligence read permission', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(reader);
  const app = render(<App />);
  await screen.findByRole('navigation');
  expect(screen.queryByRole('button', { name: 'Threat Intelligence' })).not.toBeInTheDocument();
  app.unmount();
  workspace(reader);
  expect(screen.getByText('Katalog IOC jest niedostępny')).toBeInTheDocument();
  expect(api.request).not.toHaveBeenCalled();
});
it('opens a bounded local catalogue, shows complete server totals and declares provider network isolation', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(intelligenceReader);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Threat Intelligence' }));
  const table = await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  expect(screen.getByText(/Wskaźniki w zakresie: 275/)).toBeInTheDocument();
  expect(params(listRequests()[0][0]).get('limit')).toBe('25');
  expect(screen.getByText('Lokalny katalog IOC')).toBeInTheDocument();
  expect(screen.getByText(/Bez połączeń zewnętrznych/)).toBeInTheDocument();
  expect(screen.getByText(/Dopasowanie nie potwierdza ataku/)).toBeInTheDocument();
});
it('allows read-only lookup and history while hiding all create, import and edit controls', async () => {
  await details();
  expect(screen.queryByRole('button', { name: 'Dodaj IOC' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Importuj IOC' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Edytuj IOC' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię IOC' }));
  await screen.findByText('Rewizja 2');
  expect(api.post).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
});
it('sends literal filters with kind, reputation, active and limit only after applying the draft', async () => {
  workspace();
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.change(screen.getByLabelText('Szukaj wartości lub źródła'), {
    target: { value: '%_"literal' },
  });
  fireEvent.change(screen.getByLabelText('Rodzaj wskaźnika'), { target: { value: 'url' } });
  fireEvent.change(screen.getByLabelText('Reputacja w katalogu'), {
    target: { value: 'malicious' },
  });
  fireEvent.change(screen.getByLabelText('Stan wskaźnika'), { target: { value: 'false' } });
  fireEvent.change(screen.getByLabelText('IOC na stronę'), { target: { value: '100' } });
  expect(listRequests()).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj filtry IOC' }));
  await waitFor(() => expect(listRequests()).toHaveLength(2));
  const query = params(listRequests()[1][0]);
  expect(Object.fromEntries(query)).toEqual({
    limit: '100',
    q: '%_"literal',
    kind: 'url',
    reputation: 'malicious',
    active: 'false',
  });
});
it('uses a signed cursor and resets pagination when the catalogue filters change', async () => {
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/intelligence/providers'
      ? iocProviders
      : { ...iocPage, next_cursor: 'signed.ioc.page' },
  );
  workspace();
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Następne IOC' }));
  await screen.findByText('Strona IOC 2');
  expect(params(listRequests()[1][0]).get('cursor')).toBe('signed.ioc.page');
  fireEvent.change(screen.getByLabelText('Stan wskaźnika'), { target: { value: 'true' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj filtry IOC' }));
  await screen.findByText('Strona IOC 1');
  expect(params(listRequests()[2][0]).has('cursor')).toBe(false);
});
it('clears stale rows during reload, distinguishes a failure from an empty catalogue and permits retry', async () => {
  workspace();
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  vi.mocked(api.request).mockRejectedValueOnce(new ApiError(503, 'http_error'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież katalog IOC' }));
  expect(screen.queryByRole('table', { name: 'Wskaźniki IOC' })).not.toBeInTheDocument();
  await screen.findByRole('alert');
  expect(screen.queryByText('Brak wskaźników w tym zakresie')).not.toBeInTheDocument();
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/intelligence/providers' ? iocProviders : { ...iocPage, items: [], total: 0 },
  );
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież katalog IOC' }));
  await screen.findByText('Brak wskaźników w tym zakresie');
  expect(screen.getByText(/Pusty wynik nie potwierdza bezpieczeństwa/)).toBeInTheDocument();
});
it('aborts and rejects an older list flight after the filter scope changes', async () => {
  const late = deferred<IocPage>();
  vi.mocked(api.request).mockReturnValueOnce(late.promise);
  workspace();
  await waitFor(() => expect(listRequests()).toHaveLength(1));
  const signal = listRequests()[0][1]!.signal!;
  fireEvent.change(screen.getByLabelText('Szukaj wartości lub źródła'), {
    target: { value: 'fresh' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj filtry IOC' }));
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  expect(signal.aborted).toBe(true);
  await act(async () =>
    late.resolve({ ...iocPage, items: [{ ...ioc, value: 'PRIVATE OLD IOC' }] }),
  );
  expect(screen.queryByText('PRIVATE OLD IOC')).not.toBeInTheDocument();
});
it('looks up one normalized value, includes an inactive declaration and keeps unknown confidence explicit', async () => {
  vi.mocked(api.post).mockResolvedValueOnce({ ...iocLookup, item: { ...ioc, active: false } });
  workspace();
  fireEvent.change(screen.getByLabelText('Wartość do sprawdzenia'), {
    target: { value: ' 192.0.2.10 ' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Sprawdź IOC' }));
  await screen.findByRole('button', { name: 'Otwórz znaleziony IOC' });
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/intelligence/lookup', {
    type: 'ip',
    value: ioc.value,
  });
  expect(screen.getByText(/Deklarowana pewność: nieznana/)).toBeInTheDocument();
  expect(screen.getByText('Wyłączony')).toBeInTheDocument();
});
it('does not treat an absent lookup result as evidence of safety', async () => {
  vi.mocked(api.post).mockResolvedValueOnce({ ...iocLookup, found: false, item: null });
  workspace();
  fireEvent.change(screen.getByLabelText('Wartość do sprawdzenia'), {
    target: { value: '192.0.2.123' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Sprawdź IOC' }));
  await screen.findByText(/Brak wpisu w lokalnym katalogu/);
  expect(screen.getByText(/To nie potwierdza bezpieczeństwa adresu ani pliku/)).toBeInTheDocument();
});
it('invalidates an exact-lookup flight as soon as the value or type changes', async () => {
  const late = deferred<IocLookupResult>();
  vi.mocked(api.post).mockReturnValueOnce(late.promise);
  workspace();
  fireEvent.change(screen.getByLabelText('Wartość do sprawdzenia'), {
    target: { value: ioc.value },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Sprawdź IOC' }));
  fireEvent.change(screen.getByLabelText('Typ do sprawdzenia'), { target: { value: 'domain' } });
  fireEvent.change(screen.getByLabelText('Wartość do sprawdzenia'), {
    target: { value: 'example.test' },
  });
  await act(async () => late.resolve(iocLookup));
  expect(screen.queryByRole('button', { name: 'Otwórz znaleziony IOC' })).not.toBeInTheDocument();
});
it.each([
  ['ip', '192.0.2.123'],
  ['domain', 'example.test'],
  ['url', 'https://example.test/a'],
  ['hash', 'a'.repeat(64)],
])('creates a %s declaration with null confidence and no remote lookup', async (type, value) => {
  const input = await create();
  fireEvent.change(screen.getByLabelText('Typ IOC'), { target: { value: type } });
  fireEvent.change(input, { target: { value } });
  fireEvent.change(screen.getByLabelText('Źródło deklaracji'), {
    target: { value: 'Własna analiza' },
  });
  submitEditor();
  await waitFor(() => expect(api.post).toHaveBeenCalled());
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/intelligence/iocs', {
    type,
    value,
    source: 'Własna analiza',
    reputation: 'unknown',
    confidence: null,
    active: true,
    description: '',
    tags: [],
    first_seen: null,
    last_seen: null,
  });
});
it.each(['101', '3.5'])(
  'rejects invalid declared confidence %s before writing and preserves the draft',
  async (confidence) => {
    const input = await create();
    fireEvent.change(input, { target: { value: ioc.value } });
    fireEvent.change(screen.getByLabelText('Źródło deklaracji'), { target: { value: ioc.source } });
    fireEvent.change(screen.getByLabelText('Pewność deklarowana · opcjonalna'), {
      target: { value: confidence },
    });
    submitEditor();
    expect(await screen.findByRole('alert')).toHaveTextContent('liczbą całkowitą od 0 do 100');
    expect(api.post).not.toHaveBeenCalled();
    expect(input).toHaveValue(ioc.value);
  },
);
it('patches metadata with the existing version while immutable type and value stay read-only', async () => {
  await details(intelligenceManager);
  fireEvent.click(screen.getByRole('button', { name: 'Edytuj IOC' }));
  expect(screen.getByLabelText('Typ IOC')).toBeDisabled();
  expect(screen.getByLabelText('Wartość wskaźnika')).toHaveAttribute('readonly');
  fireEvent.click(screen.getByLabelText('Aktywny wskaźnik'));
  submitEditor();
  await waitFor(() => expect(api.patch).toHaveBeenCalled());
  const [path, metadata, version] = vi.mocked(api.patch).mock.calls[0];
  expect(path).toBe(`/intelligence/iocs/${ioc.id}`);
  expect(version).toBe(1);
  expect(metadata).toMatchObject({ active: false, confidence: null, source: ioc.source });
  expect(metadata).not.toHaveProperty('type');
  expect(metadata).not.toHaveProperty('value');
});
it('preserves an edit after version conflict and requires explicit refresh before using the newer version', async () => {
  await details(intelligenceManager);
  fireEvent.click(screen.getByRole('button', { name: 'Edytuj IOC' }));
  const source = screen.getByLabelText('Źródło deklaracji');
  fireEvent.change(source, { target: { value: 'Mój zachowany szkic' } });
  vi.mocked(api.patch).mockRejectedValueOnce(new ApiError(412, 'version_conflict'));
  submitEditor();
  await screen.findByRole('alert');
  expect(source).toHaveValue('Mój zachowany szkic');
  expect(screen.getByRole('button', { name: 'Zapisz IOC' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież wersję IOC' }));
  await screen.findByText(/Wersja do zapisu: 3/);
  expect(source).toHaveValue('Mój zachowany szkic');
  submitEditor();
  await waitFor(() => expect(api.patch).toHaveBeenCalledTimes(2));
  expect(vi.mocked(api.patch).mock.calls[1][2]).toBe(3);
});
it.each([
  ['2026-10-01T12:00:00.123456Z', '2026-10-01T12:00:00.123789Z'],
  ['2026-10-01T12:00:00Z', '2026-10-01T12:00:00.000789Z'],
])(
  'preserves exact dates %s / %s and literal comma tags when changing only the source',
  async (firstSeen, lastSeen) => {
    const originalIoc = {
      ...ioc,
      first_seen: firstSeen,
      last_seen: lastSeen,
      tags: ['literal,comma', 'one more tag'],
    };
    vi.mocked(api.request).mockImplementation(async (path) => {
      if (path === `/intelligence/iocs/${ioc.id}`) return originalIoc;
      if (path === '/intelligence/providers') return iocProviders;
      if (path.startsWith('/intelligence/iocs?')) return iocPage;
      throw new Error(`Unexpected test request: ${path}`);
    });
    await details(intelligenceManager);
    fireEvent.click(screen.getByRole('button', { name: 'Edytuj IOC' }));
    fireEvent.change(screen.getByLabelText('Źródło deklaracji'), {
      target: { value: 'Nowe źródło' },
    });
    submitEditor();
    await waitFor(() => expect(api.patch).toHaveBeenCalled());
    expect(vi.mocked(api.patch).mock.calls[0][1]).toMatchObject({
      source: 'Nowe źródło',
      first_seen: originalIoc.first_seen,
      last_seen: originalIoc.last_seen,
      tags: originalIoc.tags,
    });
  },
);
it('accepts literal commas inside edited tags separated by lines', async () => {
  await create();
  fireEvent.change(screen.getByLabelText('Wartość wskaźnika'), { target: { value: ioc.value } });
  fireEvent.change(screen.getByLabelText('Źródło deklaracji'), { target: { value: ioc.source } });
  fireEvent.change(screen.getByLabelText('Tagi IOC · jeden w wierszu'), {
    target: { value: 'literal,comma\nsecond tag' },
  });
  submitEditor();
  await waitFor(() => expect(api.post).toHaveBeenCalled());
  expect(vi.mocked(api.post).mock.calls[0][1]).toMatchObject({
    tags: ['literal,comma', 'second tag'],
  });
});
it('shows immutable history documents, hashes and an explicit unknown source confidence', async () => {
  await details();
  expect(screen.getByText('Pewność deklarowana przez źródło').nextSibling).toHaveTextContent(
    'Nieznana',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię IOC' }));
  await screen.findByText('Rewizja 2');
  expect(screen.getByText(`SHA-256: ${'b'.repeat(64)}`)).toBeInTheDocument();
  expect(screen.getByText(`SHA-256: ${ioc.document_sha256}`)).toBeInTheDocument();
  expect(screen.getByText(/Zmiany i wyłączenie zachowują poprzednie rewizje/)).toBeInTheDocument();
});
it.each([
  'broken JSON',
  '{}',
  '[]',
  JSON.stringify(
    Array.from({ length: 101 }, () => ({ type: 'ip', value: ioc.value, source: ioc.source })),
  ),
])('rejects a malformed or out-of-bounds import before sending any items', async (text) => {
  const input = await importer();
  fireEvent.change(input, { target: { value: text } });
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz partię IOC' }));
  await screen.findByRole('alert');
  expect(api.post).not.toHaveBeenCalled();
  expect(input).toHaveValue(text);
});
it('bounds the complete UTF-8 import body before sending it', async () => {
  const input = await importer();
  fireEvent.change(input, {
    target: {
      value: JSON.stringify([{ type: 'url', value: 'ż'.repeat(524288), source: ioc.source }]),
    },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz partię IOC' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('najwyżej 1 MiB');
  expect(api.post).not.toHaveBeenCalled();
});
it('sends exactly one bounded import and reports created and unchanged counts from the atomic result', async () => {
  const input = await importer();
  const batch = deferred<{ items: Ioc[]; created: number; unchanged: number }>();
  vi.mocked(api.post).mockReturnValueOnce(batch.promise);
  const entries = [{ type: 'ip', value: ioc.value, source: ioc.source }];
  fireEvent.change(input, { target: { value: JSON.stringify(entries) } });
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz partię IOC' }));
  fireEvent.click(screen.getByRole('button', { name: 'Importowanie IOC…' }));
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/intelligence/import', { items: entries });
  await act(async () => batch.resolve({ items: [ioc], created: 1, unchanged: 3 }));
  await screen.findByText('Partia przyjęta: 1 nowych IOC; 3 bez zmian.');
});
it.each([409, 422])(
  'keeps the import draft on server rejection %s without presenting a partial success',
  async (status) => {
    const input = await importer();
    const text = JSON.stringify([{ type: 'ip', value: ioc.value, source: ioc.source }]);
    fireEvent.change(input, { target: { value: text } });
    vi.mocked(api.post).mockRejectedValueOnce(
      new ApiError(status, 'ioc_conflict', undefined, 'Cała partia została odrzucona.'),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Zapisz partię IOC' }));
    await screen.findByRole('alert');
    expect(input).toHaveValue(text);
    expect(screen.queryByText(/Partia przyjęta/)).not.toBeInTheDocument();
  },
);
it.each(['session', 'logout'] as const)(
  'rejects late catalogue data and blocks mutation controls after %s',
  async (kind) => {
    const late = deferred<IocPage>();
    vi.mocked(api.request).mockReturnValueOnce(late.promise);
    workspace(intelligenceManager);
    await waitFor(() => expect(listRequests()).toHaveLength(1));
    await notify(kind);
    await act(async () => late.resolve(iocPage));
    expect(screen.queryByRole('table', { name: 'Wskaźniki IOC' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Dodaj IOC' })).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent('Sesja zmieniła się');
  },
);
it('rejects an older mutation result after session change and resumes the same-account draft only after checking authority', async () => {
  const input = await create();
  fireEvent.change(input, { target: { value: ioc.value } });
  fireEvent.change(screen.getByLabelText('Źródło deklaracji'), {
    target: { value: 'Zachowany szkic' },
  });
  const late = deferred<Ioc>();
  vi.mocked(api.post).mockReturnValueOnce(late.promise);
  submitEditor();
  await notify('session');
  await act(async () => late.resolve(ioc));
  expect(screen.queryByText(/Zachowano IOC/)).not.toBeInTheDocument();
  expect(input).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież katalog IOC' }));
  await waitFor(() => expect(input).toBeEnabled());
  expect(screen.getByLabelText('Źródło deklaracji')).toHaveValue('Zachowany szkic');
  expect(api.get).toHaveBeenCalledWith('/auth/me');
});
it('clears management drafts after permission loss and discards the previous authority response', async () => {
  const component = workspace(intelligenceManager);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj IOC' }));
  fireEvent.change(screen.getByLabelText('Wartość wskaźnika'), {
    target: { value: 'PRIVATE DRAFT' },
  });
  component.rerender(<Intelligence user={intelligenceReader} />);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  expect(screen.queryByLabelText('Wartość wskaźnika')).not.toBeInTheDocument();
  expect(screen.queryByText('PRIVATE DRAFT')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Dodaj IOC' })).not.toBeInTheDocument();
});
it('renders IOC URLs, source metadata and history as text without links or executable markup', async () => {
  const payload = '<img src=x onerror=attack()><script>attack()</script>';
  const url = 'https://evil.example/payload';
  const value = {
    ...ioc,
    type: 'url' as const,
    value: url,
    canonical_value: url,
    source: payload,
    description: payload,
    tags: [payload],
  };
  vi.mocked(api.request).mockImplementation(async (path) =>
    path === '/intelligence/providers'
      ? iocProviders
      : path.startsWith('/intelligence/iocs?')
        ? { ...iocPage, items: [value] }
        : value,
  );
  const component = workspace();
  fireEvent.click(await screen.findByRole('button', { name: url }));
  await screen.findByRole('heading', { name: url });
  expect(component.container.querySelector('img,script')).toBeNull();
  expect(component.container.querySelector('a[href]')).toBeNull();
  expect(component.container).toHaveTextContent(payload);
});
it('labels an intelligence alert while preserving its original proof and source-declaration limits', async () => {
  const onEvent = vi.fn();
  render(<Alerts user={intelligenceReader} onEvent={onEvent} onCreateIncident={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  await screen.findByText(/Dopasowano zachowaną deklarację lokalnego katalogu IOC/);
  expect(screen.getAllByText('Threat Intelligence')).toHaveLength(2);
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 1: process_started' }));
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(original);
});

it('shows a frozen IOC declaration in alert reasoning without looking up a newer catalogue revision', async () => {
  const proof = structuredClone(eventIocProof);
  proof.matches[0].revision_snapshot.reputation = 'malicious';
  proof.matches[0].revision_snapshot.confidence = 91;
  vi.mocked(api.get).mockImplementation(async (path) =>
    path.startsWith('/alerts?')
      ? { items: [{ ...alert, detection_type: 'intelligence' }], total: 1, next_cursor: null }
      : { ...alertDetail, detection_type: 'intelligence', reason: proof },
  );
  render(<Alerts user={intelligenceReader} onEvent={vi.fn()} onCreateIncident={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  const region = await screen.findByRole('region', {
    name: 'Deklaracje IOC zachowane przy alercie',
  });
  expect(region).toHaveTextContent('Dawna deklaracja źródła');
  expect(region).toHaveTextContent('91/100');
  expect(region).toHaveTextContent(ioc.document_sha256);
  expect(vi.mocked(api.get).mock.calls.every(([path]) => !path.startsWith('/intelligence/'))).toBe(
    true,
  );
});

it.each(['events:read', 'intelligence:read'])(
  'does not fetch event intelligence without %s',
  async (permission) => {
    render(
      <EventIntelligence
        eventId={original.event_id}
        user={{
          ...intelligenceReader,
          permissions: intelligenceReader.permissions.filter((value) => value !== permission),
        }}
      />,
    );
    expect(
      screen.queryByRole('region', { name: 'Utrwalone dopasowania IOC' }),
    ).not.toBeInTheDocument();
    expect(api.request).not.toHaveBeenCalled();
  },
);
it('shows frozen unknown and clean declarations without substituting current catalogue reputation or inventing confidence', async () => {
  const proof = structuredClone(eventIocProof);
  const clean = structuredClone(proof.matches[0]);
  clean.id = '92000000-0000-0000-0000-000000000002';
  clean.field = 'destination.ip';
  clean.revision_snapshot.reputation = 'clean';
  clean.revision_snapshot.confidence = 0;
  proof.matches.push(clean);
  proof.match_count = 2;
  vi.mocked(api.request).mockResolvedValue(proof);
  render(<EventIntelligence eventId={original.event_id} user={intelligenceReader} />);
  await screen.findByText(/Zachowane dopasowania: 2/);
  expect(screen.getByText('Nieznana', { selector: '.badge' })).toBeInTheDocument();
  expect(screen.getByText('Czysty według źródła')).toBeInTheDocument();
  expect(screen.getAllByText('Dawna deklaracja źródła')).toHaveLength(2);
  expect(screen.getByText('0/100')).toBeInTheDocument();
  expect(screen.getByText('Nieznana', { selector: 'dd' })).toBeInTheDocument();
  expect(screen.getAllByText('Zachowana rewizja IOC')[0].nextSibling).toHaveTextContent('1');
  expect(screen.getByText('SHA-256 znormalizowanego zdarzenia').nextSibling).toHaveTextContent(
    eventIocProof.document_sha256,
  );
  expect(api.get).not.toHaveBeenCalled();
  expect(api.post).not.toHaveBeenCalled();
});
it('keeps pending event analysis explicit and refreshes only by reading without creating a match', async () => {
  vi.mocked(api.request).mockResolvedValue({
    ...eventIocProof,
    status: 'pending',
    matches: [],
    match_count: 0,
    evaluated_at: null,
  });
  render(<EventIntelligence eventId={original.event_id} user={intelligenceReader} />);
  await screen.findByText(/Dopasowania jeszcze nie zostały utrwalone/);
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież dopasowania IOC' }));
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2));
  expect(
    vi
      .mocked(api.request)
      .mock.calls.every(([path]) => path === `/intelligence/events/${original.event_id}`),
  ).toBe(true);
  expect(api.post).not.toHaveBeenCalled();
  expect(screen.queryByText(/Nie dopasowano aktywnych IOC/)).not.toBeInTheDocument();
});
it('shows evaluated zero matches as a completed observation without declaring the event safe', async () => {
  vi.mocked(api.request).mockResolvedValue({ ...eventIocProof, matches: [], match_count: 0 });
  render(<EventIntelligence eventId={original.event_id} user={intelligenceReader} />);
  await screen.findByText(/Zachowane dopasowania: 0/);
  expect(screen.getByText(/To nie potwierdza bezpieczeństwa zdarzenia/)).toBeInTheDocument();
  expect(screen.queryByText(/Dopasowania jeszcze nie zostały utrwalone/)).not.toBeInTheDocument();
});
it.each([401, 404, 409, 503])(
  'reports frozen event-proof failure %s and permits retry without fallback analysis',
  async (status) => {
    vi.mocked(api.request).mockRejectedValueOnce(
      new ApiError(
        status,
        status === 409 ? 'intelligence_evidence_integrity_mismatch' : 'http_error',
      ),
    );
    render(<EventIntelligence eventId={original.event_id} user={intelligenceReader} />);
    await screen.findByRole('alert');
    expect(screen.queryByText(/Zachowane dopasowania:/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież dopasowania IOC' }));
    await screen.findByText(/Zachowane dopasowania: 1/);
    expect(api.post).not.toHaveBeenCalled();
  },
);
it('rejects late event intelligence after choosing a different original event', async () => {
  const late = deferred<typeof eventIocProof>();
  vi.mocked(api.request).mockReturnValueOnce(late.promise);
  const component = render(
    <EventIntelligence eventId={original.event_id} user={intelligenceReader} />,
  );
  await waitFor(() => expect(api.request).toHaveBeenCalledTimes(1));
  const nextId = '20000000-0000-0000-0000-000000000002';
  component.rerender(<EventIntelligence eventId={nextId} user={intelligenceReader} />);
  await screen.findByText(/Zachowane dopasowania: 1/);
  const old = structuredClone(eventIocProof);
  old.matches[0].revision_snapshot.source = 'PRIVATE PREVIOUS EVENT';
  await act(async () => late.resolve(old));
  expect(screen.queryByText('PRIVATE PREVIOUS EVENT')).not.toBeInTheDocument();
  expect(vi.mocked(api.request).mock.calls.at(-1)![0]).toBe(`/intelligence/events/${nextId}`);
});
it.each(['session', 'logout'] as const)(
  'clears frozen event matches after %s and ignores the old response',
  async (kind) => {
    render(<EventIntelligence eventId={original.event_id} user={intelligenceReader} />);
    await screen.findByText(/Zachowane dopasowania: 1/);
    const late = deferred<typeof eventIocProof>();
    vi.mocked(api.request).mockReturnValueOnce(late.promise);
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież dopasowania IOC' }));
    await notify(kind);
    await act(async () => late.resolve(eventIocProof));
    expect(screen.queryByText(/Zachowane dopasowania:/)).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Sesja zmieniła się');
  },
);
it('integrates intelligence evidence only when the event detail receives an authorized current account', async () => {
  const component = render(<EventDetail event={original} onClose={vi.fn()} onFilter={vi.fn()} />);
  expect(
    screen.queryByRole('region', { name: 'Utrwalone dopasowania IOC' }),
  ).not.toBeInTheDocument();
  component.rerender(
    <EventDetail
      event={original}
      onClose={vi.fn()}
      onFilter={vi.fn()}
      intelligenceUser={intelligenceReader}
    />,
  );
  await screen.findByText(/Zachowane dopasowania: 1/);
  component.rerender(
    <EventDetail event={original} onClose={vi.fn()} onFilter={vi.fn()} intelligenceUser={reader} />,
  );
  expect(
    screen.queryByRole('region', { name: 'Utrwalone dopasowania IOC' }),
  ).not.toBeInTheDocument();
});

it.each([
  intelligenceReader,
  {
    ...intelligenceReader,
    role: 'soc_analyst' as const,
    permissions: [...intelligenceReader.permissions, 'intelligence:propose'],
  },
  intelligenceManager,
])('hides older-event backfill from the $role role without system management', async (user) => {
  workspace(user);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  expect(
    screen.queryByRole('button', { name: 'Przeanalizuj jedną partię IOC' }),
  ).not.toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});

it('runs one explicitly global 25-event backfill batch and never loops automatically over the remaining events', async () => {
  const batch = deferred<{
    events: number;
    matches: number;
    remaining: number;
    alerts_created: 0;
    evaluator_version: string;
  }>();
  vi.mocked(api.post).mockReturnValueOnce(batch.promise);
  workspace(intelligenceAdmin);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  expect(screen.getByText(/Nigdy nie nadpisuje starszych dopasowań/)).toHaveTextContent(
    'nie tworzy historycznych alertów i nie przelicza ryzyka',
  );
  fireEvent.click(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' }));
  fireEvent.click(screen.getByRole('button', { name: 'Analizowanie partii IOC…' }));
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/intelligence/backfill', { limit: 25 });
  expect(screen.getByRole('button', { name: 'Analizowanie partii IOC…' })).toBeDisabled();
  await act(async () =>
    batch.resolve({
      events: 25,
      matches: 3,
      remaining: 70,
      alerts_created: 0,
      evaluator_version: 'intelligence-match-v1',
    }),
  );
  expect(await screen.findByText(/Zbadane zdarzenia: 25/)).toHaveTextContent(
    'pozostało bez analizy: 70',
  );
  expect(screen.getByText(/Zbadane zdarzenia: 25/)).toHaveTextContent('Utworzone alerty: 0');
  expect(api.post).toHaveBeenCalledTimes(1);
});

it.each(['session', 'logout'] as const)(
  'ignores a backfill response from the previous %s authority and disables the action',
  async (kind) => {
    const batch = deferred<{
      events: number;
      matches: number;
      remaining: number;
      alerts_created: 0;
      evaluator_version: string;
    }>();
    vi.mocked(api.post).mockReturnValueOnce(batch.promise);
    workspace(intelligenceAdmin);
    await screen.findByRole('table', { name: 'Wskaźniki IOC' });
    fireEvent.click(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' }));
    await notify(kind);
    await act(async () =>
      batch.resolve({
        events: 25,
        matches: 3,
        remaining: 0,
        alerts_created: 0,
        evaluator_version: 'intelligence-match-v1',
      }),
    );
    expect(screen.queryByText(/Zbadane zdarzenia: 25/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' })).toBeDisabled();
    expect(api.post).toHaveBeenCalledTimes(1);
  },
);

it('does not present a failed older-event batch as a completed analysis and supports explicit retry', async () => {
  vi.mocked(api.post).mockRejectedValueOnce(new ApiError(503, 'http_error'));
  workspace(intelligenceAdmin);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' }));
  await screen.findByRole('alert');
  expect(screen.queryByText(/Zbadane zdarzenia:/)).not.toBeInTheDocument();
  vi.mocked(api.post).mockResolvedValueOnce({
    events: 0,
    matches: 0,
    remaining: 0,
    alerts_created: 0,
    evaluator_version: 'intelligence-match-v1',
  });
  fireEvent.click(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' }));
  await screen.findByText(/Zbadane zdarzenia: 0/);
  expect(api.post).toHaveBeenCalledTimes(2);
});

it('removes backfill controls and ignores the pending admin result after permission loss', async () => {
  const batch = deferred<{
    events: number;
    matches: number;
    remaining: number;
    alerts_created: 0;
    evaluator_version: string;
  }>();
  vi.mocked(api.post).mockReturnValueOnce(batch.promise);
  const component = workspace(intelligenceAdmin);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  fireEvent.click(screen.getByRole('button', { name: 'Przeanalizuj jedną partię IOC' }));
  component.rerender(<Intelligence user={intelligenceReader} />);
  await screen.findByRole('table', { name: 'Wskaźniki IOC' });
  await act(async () =>
    batch.resolve({
      events: 25,
      matches: 3,
      remaining: 0,
      alerts_created: 0,
      evaluator_version: 'intelligence-match-v1',
    }),
  );
  expect(
    screen.queryByRole('button', { name: 'Przeanalizuj jedną partię IOC' }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(/Zbadane zdarzenia: 25/)).not.toBeInTheDocument();
});
