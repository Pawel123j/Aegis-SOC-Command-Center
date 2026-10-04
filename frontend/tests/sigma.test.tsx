import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { Detections } from '../src/detections/Detections';
import { SigmaRules } from '../src/sigma/SigmaRules';
import { original, reader } from './incidentFixtures';
import {
  sigmaAnalyst,
  sigmaCapabilities,
  sigmaManager,
  sigmaReader,
  sigmaResult,
  sigmaRule,
  sigmaValidation,
  sigmaYaml,
} from './sigmaFixtures';

beforeEach(() => {
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/sigma/capabilities') return sigmaCapabilities;
    if (path === '/sigma/rules') return { items: [sigmaRule] };
    if (path.startsWith('/sigma/rules/')) return sigmaRule;
    if (path === '/auth/me') return sigmaManager;
    if (path === '/correlations/status') return { counts: {}, scopes: [], scopes_truncated: false };
    return { items: [], next_cursor: null };
  });
  vi.spyOn(api, 'post').mockImplementation(async (path) => {
    if (path === '/sigma/validate') return sigmaValidation;
    if (path === '/sigma/test') return sigmaResult;
    return sigmaRule;
  });
  vi.spyOn(api, 'patch').mockResolvedValue({ ...sigmaRule, enabled: true, version: 2 });
});

async function openImport() {
  fireEvent.click(await screen.findByRole('button', { name: 'Import Sigma Rule' }));
  return screen.getByLabelText('Definicja Sigma (YAML)');
}
async function validate(yaml = sigmaYaml) {
  fireEvent.change(screen.getByLabelText('Definicja Sigma (YAML)'), { target: { value: yaml } });
  fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
  return screen.findByRole('region', { name: 'Podgląd zweryfikowanej reguły' });
}
async function openDetails() {
  fireEvent.click(
    await screen.findByRole('button', { name: `Przejrzyj Sigma: ${sigmaRule.title}` }),
  );
  return screen.findByText('Wersja definicji 1 · wersja stanu 1 · Wyłączona');
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function utf8Buffer(value: string): ArrayBuffer {
  return new TextEncoder().encode(value).buffer;
}

it('does not fetch Sigma data or expose controls without detection read permission', async () => {
  render(<SigmaRules user={reader} onEvent={vi.fn()} />);
  expect(screen.getByText('Reguły Sigma są niedostępne')).toBeInTheDocument();
  expect(api.get).not.toHaveBeenCalled();
  expect(api.post).not.toHaveBeenCalled();
});

it('loads Sigma only on first opening and preserves a draft across detection tabs and keyboard navigation', async () => {
  render(<Detections user={sigmaManager} onEvent={vi.fn()} />);
  await waitFor(() => expect(api.get).toHaveBeenCalled());
  expect(vi.mocked(api.get).mock.calls.every(([path]) => !path.startsWith('/sigma/'))).toBe(true);
  const single = screen.getByRole('tab', { name: 'Pojedyncze zdarzenia' });
  fireEvent.keyDown(single, { key: 'End' });
  const sigma = screen.getByRole('tab', { name: 'Sigma' });
  expect(sigma).toHaveFocus();
  const input = await openImport();
  fireEvent.change(input, { target: { value: 'unfinished draft' } });
  fireEvent.keyDown(sigma, { key: 'ArrowRight' });
  expect(single).toHaveFocus();
  fireEvent.keyDown(single, { key: 'ArrowLeft' });
  expect(screen.getByLabelText('Definicja Sigma (YAML)')).toHaveValue('unfinished draft');
});

it('shows supported source aliases, operators and exact size limits from capabilities', async () => {
  render(<SigmaRules user={sigmaReader} onEvent={vi.fn()} />);
  fireEvent.click(await screen.findByText('Obsługiwany zakres Sigma i pola logów'));
  expect(screen.getByText(/Definicja do 64 KiB; test do 25 zdarzeń/)).toBeInTheDocument();
  expect(screen.getByText(/katalog do 100 reguł; historia do 20 wersji/)).toBeInTheDocument();
  expect(screen.getByText(/equals, contains, startswith, endswith/)).toBeInTheDocument();
  expect(screen.getByText(/"Image": "process.executable"/)).toBeInTheDocument();
});

it('distinguishes an empty Sigma catalogue from a failed fetch', async () => {
  vi.mocked(api.get).mockImplementation(async (path) =>
    path === '/sigma/capabilities' ? sigmaCapabilities : { items: [] },
  );
  render(<SigmaRules user={sigmaReader} onEvent={vi.fn()} />);
  await screen.findByText('Brak reguł Sigma');
  expect(screen.getByText(/Brak reguł nie potwierdza/)).toBeInTheDocument();
  vi.mocked(api.get).mockRejectedValue(new ApiError(503, 'rules_unavailable'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('chwilowo niedostępny');
  expect(screen.queryByText('Brak reguł Sigma')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Sprawdź YAML/ })).toBeDisabled();
});

it('allows read-only YAML validation while hiding persistence, publication and test controls', async () => {
  render(<SigmaRules user={sigmaReader} onEvent={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Sprawdź YAML Sigma' }));
  await validate();
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/sigma/validate', { yaml: sigmaYaml });
  expect(
    screen.queryByRole('button', { name: 'Importuj wyłączoną regułę' }),
  ).not.toBeInTheDocument();
  await openDetails();
  expect(screen.queryByRole('button', { name: 'Włącz Sigma' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Uruchom test Sigma' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Dodaj wersję Sigma' })).not.toBeInTheDocument();
});

it('validates before import and requires revalidation after editing the previewed source', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  const save = screen.getByRole('button', { name: 'Importuj wyłączoną regułę' });
  expect(save).toBeDisabled();
  await validate();
  expect(save).toBeEnabled();
  fireEvent.change(input, { target: { value: sigmaYaml + '\n# edited' } });
  expect(save).toBeDisabled();
  expect(
    screen.queryByRole('region', { name: 'Podgląd zweryfikowanej reguły' }),
  ).not.toBeInTheDocument();
  expect(api.post).toHaveBeenCalledTimes(1);
});

it('imports the validated YAML as disabled without silently publishing it', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openImport();
  await validate();
  fireEvent.click(screen.getByRole('button', { name: 'Importuj wyłączoną regułę' }));
  await screen.findByText('Zachowana definicja 1. Reguła: wyłączona.');
  expect(api.post).toHaveBeenLastCalledWith('/sigma/rules', { yaml: sigmaYaml }, {});
  expect(api.patch).not.toHaveBeenCalled();
});

it('reports exact duplicate import using the returned current enabled state', async () => {
  vi.mocked(api.post).mockImplementation(async (path) =>
    path === '/sigma/validate' ? sigmaValidation : { ...sigmaRule, enabled: true, version: 4 },
  );
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openImport();
  await validate();
  fireEvent.click(screen.getByRole('button', { name: 'Importuj wyłączoną regułę' }));
  await screen.findByText('Zachowana definicja 1. Reguła: aktywna.');
  expect(api.patch).not.toHaveBeenCalled();
});

it('keeps the YAML draft when a different definition already uses the Sigma UUID', async () => {
  vi.mocked(api.post).mockImplementation(async (path) => {
    if (path === '/sigma/validate') return sigmaValidation;
    throw new ApiError(409, 'sigma_rule_exists');
  });
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  await validate();
  fireEvent.click(screen.getByRole('button', { name: 'Importuj wyłączoną regułę' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Otwórz ją i zapisz nową wersję');
  expect(input).toHaveValue(sigmaYaml);
  expect(api.patch).not.toHaveBeenCalled();
});

it('rejects blank and over-limit multibyte YAML before contacting the API', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  for (const yaml of ['   ', 'ą'.repeat(32769)]) {
    fireEvent.change(input, { target: { value: yaml } });
    fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
    await screen.findByRole('alert');
  }
  expect(screen.getByRole('alert')).toHaveTextContent('64 KiB');
  expect(api.post).not.toHaveBeenCalled();
});

it('accepts a file at the UTF-8 byte boundary and ignores a late file read after manual edits', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  const fileInput = screen.getByLabelText('Plik Sigma YAML');
  const boundary = { size: 65536, arrayBuffer: async () => utf8Buffer('ą'.repeat(32768)) };
  fireEvent.change(fileInput, { target: { files: [boundary] } });
  await waitFor(() => expect(input).toHaveValue('ą'.repeat(32768)));
  const late = deferred<ArrayBuffer>();
  fireEvent.change(fileInput, {
    target: { files: [{ size: 10, arrayBuffer: () => late.promise }] },
  });
  fireEvent.change(input, { target: { value: 'new draft' } });
  await act(async () => late.resolve(utf8Buffer('old file')));
  expect(input).toHaveValue('new draft');
});

it('rejects oversized files without reading or submitting them', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openImport();
  const arrayBuffer = vi.fn();
  fireEvent.change(screen.getByLabelText('Plik Sigma YAML'), {
    target: { files: [{ size: 65537, arrayBuffer }] },
  });
  expect(await screen.findByRole('alert')).toHaveTextContent('64 KiB');
  expect(arrayBuffer).not.toHaveBeenCalled();
  expect(api.post).not.toHaveBeenCalled();
});

it('escapes server validation details and untrusted rule metadata', async () => {
  const unsafe = '<img src=x onerror=unsafe()>';
  vi.mocked(api.get).mockImplementation(async (path) =>
    path === '/sigma/capabilities'
      ? sigmaCapabilities
      : { items: [{ ...sigmaRule, title: unsafe, description: unsafe }] },
  );
  vi.mocked(api.post).mockRejectedValue(
    new ApiError(422, 'sigma_condition_invalid', 'request-1', unsafe),
  );
  const { container } = render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await screen.findByRole('heading', { name: unsafe });
  await openImport();
  fireEvent.change(screen.getByLabelText('Definicja Sigma (YAML)'), {
    target: { value: sigmaYaml },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(unsafe);
  expect(screen.getByRole('alert')).toHaveTextContent('request-1');
  expect(container.querySelector('img')).toBeNull();
  expect(container.querySelector('script')).toBeNull();
});

it('sends the displayed optimistic version and blocks publishing again after a conflict', async () => {
  vi.mocked(api.patch).mockRejectedValueOnce(new ApiError(412, 'version_conflict'));
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Włącz Sigma' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Odśwież');
  expect(api.patch).toHaveBeenCalledWith(`/sigma/rules/${sigmaRule.id}`, { enabled: true }, 1);
  expect(screen.getByRole('button', { name: 'Włącz Sigma' })).toBeDisabled();
  vi.mocked(api.get).mockImplementation(async (path) =>
    path === '/sigma/capabilities' ? sigmaCapabilities : { items: [{ ...sigmaRule, version: 3 }] },
  );
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Włącz Sigma' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Włącz Sigma' }));
  await waitFor(() =>
    expect(api.patch).toHaveBeenLastCalledWith(
      `/sigma/rules/${sigmaRule.id}`,
      { enabled: true },
      3,
    ),
  );
});

it('shows immutable history and keeps author references as text', async () => {
  render(<SigmaRules user={sigmaReader} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.click(screen.getByText('Historia definicji Sigma (1)'));
  expect(screen.getByText('Definicja 1 · bieżąca')).toBeInTheDocument();
  expect(screen.getByText(/nie wersję definicji/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Pochodzenie reguły Sigma'));
  expect(screen.getByText(sigmaRule.references[0])).toBeInTheDocument();
  expect(screen.queryByRole('link', { name: sigmaRule.references[0] })).not.toBeInTheDocument();
});

it('adds a new immutable definition with If-Match and reports its automatically disabled state', async () => {
  const next = { ...sigmaRule, revision: 2, version: 5, enabled: false };
  vi.mocked(api.post).mockImplementation(async (path) =>
    path === '/sigma/validate' ? sigmaValidation : next,
  );
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj wersję Sigma' }));
  await validate(sigmaYaml + '# revised\n');
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' }));
  await screen.findByText('Zachowana definicja 2. Reguła: wyłączona.');
  expect(api.post).toHaveBeenLastCalledWith(
    `/sigma/rules/${sigmaRule.id}/versions`,
    { yaml: sigmaYaml + '# revised\n' },
    { 'If-Match': '"1"' },
  );
  expect(api.patch).not.toHaveBeenCalled();
});

it('preserves the revision draft through a conflict and uses explicitly refreshed version for retry', async () => {
  vi.mocked(api.post).mockImplementation(async (path) => {
    if (path === '/sigma/validate') return sigmaValidation;
    throw new ApiError(412, 'version_conflict');
  });
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj wersję Sigma' }));
  const draft = sigmaYaml + '# my draft\n';
  await validate(draft);
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' }));
  await screen.findByRole('alert');
  expect(screen.getByLabelText('Definicja Sigma (YAML)')).toHaveValue(draft);
  expect(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' })).toBeDisabled();
  vi.mocked(api.get).mockResolvedValueOnce({ ...sigmaRule, version: 4, revision: 2 });
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież wersję do zapisu' }));
  await screen.findByText('Zmiana użyje wersji stanu 4. Ostatnia definicja: 2.');
  expect(screen.getByLabelText('Definicja Sigma (YAML)')).toHaveValue(draft);
  expect(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' })).toBeDisabled();
  await validate(draft);
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenLastCalledWith(
      `/sigma/rules/${sigmaRule.id}/versions`,
      { yaml: draft },
      { 'If-Match': '"4"' },
    ),
  );
});

it('runs an isolated analyst test against the retained YAML and opens submitted evidence', async () => {
  const onEvent = vi.fn();
  render(<SigmaRules user={sigmaAnalyst} onEvent={onEvent} />);
  await openDetails();
  fireEvent.change(screen.getByLabelText('Zdarzenia Sigma (JSON array)'), {
    target: { value: JSON.stringify([original]) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom test Sigma' }));
  await screen.findByText('Dopasowania Sigma: 1');
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/sigma/test', {
    yaml: sigmaYaml,
    events: [original],
  });
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz zdarzenie 1: process_started' }));
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(original);
  expect(api.patch).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: 'Dodaj wersję Sigma' })).not.toBeInTheDocument();
});

it('blocks invalid, empty, excessive-count and excessive-byte test input before transmission', async () => {
  render(<SigmaRules user={sigmaAnalyst} onEvent={vi.fn()} />);
  await openDetails();
  const input = screen.getByLabelText('Zdarzenia Sigma (JSON array)');
  for (const value of [
    '{',
    '{}',
    '[]',
    JSON.stringify(Array(26).fill(original)),
    JSON.stringify([{ ...original, raw_event: 'ą'.repeat(524289) }]),
  ]) {
    fireEvent.change(input, { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: 'Uruchom test Sigma' }));
    await screen.findByRole('alert');
  }
  expect(screen.getByRole('alert')).toHaveTextContent('1024 KiB');
  expect(api.post).not.toHaveBeenCalled();
});

it('distinguishes a valid no-match result from missing submitted evidence and definition mismatch', async () => {
  vi.mocked(api.post)
    .mockResolvedValueOnce({ ...sigmaResult, matches: [] })
    .mockResolvedValueOnce({ ...sigmaResult, matches: [{ event_id: 'missing', reason: {} }] })
    .mockResolvedValueOnce({
      ...sigmaResult,
      definition: { ...sigmaRule, source_sha256: 'c'.repeat(64) },
    });
  render(<SigmaRules user={sigmaAnalyst} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.change(screen.getByLabelText('Zdarzenia Sigma (JSON array)'), {
    target: { value: JSON.stringify([original]) },
  });
  const run = screen.getByRole('button', { name: 'Uruchom test Sigma' });
  fireEvent.click(run);
  await screen.findByText('Dopasowania Sigma: 0');
  fireEvent.click(run);
  await screen.findByText('Dowód nie jest dostępny w przesłanym zestawie.');
  expect(screen.queryByRole('button', { name: /Otwórz zdarzenie/ })).not.toBeInTheDocument();
  fireEvent.click(run);
  expect(await screen.findByRole('alert')).toHaveTextContent('innej definicji Sigma');
  expect(screen.queryByText('Dopasowania Sigma: 1')).not.toBeInTheDocument();
});

it('discards a late validation response after a session change while retaining the same-user draft', async () => {
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  const late = deferred<typeof sigmaValidation>();
  vi.mocked(api.post).mockReturnValueOnce(late.promise);
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  fireEvent.change(input, { target: { value: sigmaYaml } });
  fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
  await act(async () => subscribe.mock.calls[0][0]('session'));
  await act(async () => late.resolve(sigmaValidation));
  expect(
    screen.queryByRole('region', { name: 'Podgląd zweryfikowanej reguły' }),
  ).not.toBeInTheDocument();
  expect(input).toHaveValue(sigmaYaml);
  expect(screen.getByRole('button', { name: 'Waliduj YAML' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Waliduj YAML' })).toBeEnabled());
  expect(api.get).toHaveBeenCalledWith('/auth/me');
  expect(screen.getByRole('button', { name: 'Importuj wyłączoną regułę' })).toBeDisabled();
});

it('preserves a revision editor draft through a same-user session refresh', async () => {
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj wersję Sigma' }));
  const input = screen.getByLabelText('Definicja Sigma (YAML)');
  fireEvent.change(input, { target: { value: 'revision draft' } });
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(input).toHaveValue('revision draft');
  expect(screen.getByRole('button', { name: 'Waliduj YAML' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Waliduj YAML' })).toBeEnabled());
  expect(screen.getByLabelText('Definicja Sigma (YAML)')).toHaveValue('revision draft');
});

it('refuses to resume mutation controls when auth refresh reports a changed role', async () => {
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openImport();
  await act(async () => subscribe.mock.calls[0][0]('session'));
  vi.mocked(api.get).mockResolvedValueOnce(sigmaReader);
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  await waitFor(() =>
    expect(
      screen
        .getAllByRole('alert')
        .some((alert) => alert.textContent?.includes('Konto lub uprawnienia zmieniły')),
    ).toBe(true),
  );
  expect(screen.getByRole('button', { name: 'Waliduj YAML' })).toBeDisabled();
  expect(api.post).not.toHaveBeenCalled();
});

it('clears import drafts and ignores late responses after user permission changes', async () => {
  const late = deferred<typeof sigmaValidation>();
  vi.mocked(api.post).mockReturnValueOnce(late.promise);
  const { rerender } = render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openImport();
  fireEvent.change(screen.getByLabelText('Definicja Sigma (YAML)'), {
    target: { value: sigmaYaml },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
  rerender(<SigmaRules user={sigmaReader} onEvent={vi.fn()} />);
  await act(async () => late.resolve(sigmaValidation));
  expect(screen.queryByLabelText('Definicja Sigma (YAML)')).not.toBeInTheDocument();
  expect(
    screen.queryByRole('region', { name: 'Podgląd zweryfikowanej reguły' }),
  ).not.toBeInTheDocument();
  expect(await screen.findByRole('button', { name: 'Sprawdź YAML Sigma' })).toBeEnabled();
});

it('does not reopen a closed details panel after a late revision save', async () => {
  const late = deferred<typeof sigmaRule>();
  vi.mocked(api.post).mockImplementation(async (path) =>
    path === '/sigma/validate' ? sigmaValidation : late.promise,
  );
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.click(screen.getByRole('button', { name: 'Dodaj wersję Sigma' }));
  await validate(sigmaYaml + '# update');
  fireEvent.click(screen.getByRole('button', { name: 'Zapisz nową wersję Sigma' }));
  fireEvent.click(screen.getByRole('button', { name: 'Zamknij regułę Sigma' }));
  await act(async () => late.resolve({ ...sigmaRule, revision: 2 }));
  expect(screen.queryByRole('button', { name: 'Zamknij regułę Sigma' })).not.toBeInTheDocument();
  expect(screen.queryByText(/Zachowana definicja 2/)).not.toBeInTheDocument();
});

it('does not display test results returned after the session has changed', async () => {
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  const late = deferred<typeof sigmaResult>();
  vi.mocked(api.post).mockReturnValueOnce(late.promise);
  render(<SigmaRules user={sigmaAnalyst} onEvent={vi.fn()} />);
  await openDetails();
  fireEvent.change(screen.getByLabelText('Zdarzenia Sigma (JSON array)'), {
    target: { value: JSON.stringify([original]) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Uruchom test Sigma' }));
  await act(async () => subscribe.mock.calls[0][0]('logout'));
  await act(async () => late.resolve(sigmaResult));
  expect(screen.queryByText('Dopasowania Sigma: 1')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Otwórz zdarzenie/ })).not.toBeInTheDocument();
});

it('preserves the isolated test draft across a verified same-user session refresh', async () => {
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  vi.mocked(api.get).mockImplementation(async (path) => {
    if (path === '/auth/me') return sigmaAnalyst;
    if (path === '/sigma/capabilities') return sigmaCapabilities;
    if (path === '/sigma/rules') return { items: [sigmaRule] };
    return sigmaRule;
  });
  render(<SigmaRules user={sigmaAnalyst} onEvent={vi.fn()} />);
  await openDetails();
  const draft = JSON.stringify([original]);
  fireEvent.change(screen.getByLabelText('Zdarzenia Sigma (JSON array)'), {
    target: { value: draft },
  });
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(screen.queryByLabelText('Zdarzenia Sigma (JSON array)')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież reguły Sigma' }));
  expect(await screen.findByLabelText('Zdarzenia Sigma (JSON array)')).toHaveValue(draft);
  expect(api.post).not.toHaveBeenCalled();
});

it('ignores an older file read when the user selects a second file', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  const late = deferred<ArrayBuffer>();
  const fileInput = screen.getByLabelText('Plik Sigma YAML');
  fireEvent.change(fileInput, {
    target: { files: [{ size: 10, arrayBuffer: () => late.promise }] },
  });
  fireEvent.change(fileInput, {
    target: { files: [{ size: 12, arrayBuffer: async () => utf8Buffer('second file') }] },
  });
  await waitFor(() => expect(input).toHaveValue('second file'));
  await act(async () => late.resolve(utf8Buffer('first file')));
  expect(input).toHaveValue('second file');
});

it('rejects invalid UTF-8 file bytes without replacing characters or changing the draft', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  fireEvent.change(input, { target: { value: sigmaYaml } });
  const invalid = new Uint8Array([0x74, 0x69, 0x74, 0x6c, 0x65, 0x3a, 0x20, 0xc3, 0x28]);
  fireEvent.change(screen.getByLabelText('Plik Sigma YAML'), {
    target: { files: [{ size: invalid.byteLength, arrayBuffer: async () => invalid.buffer }] },
  });
  expect(await screen.findByRole('alert')).toHaveTextContent('poprawnie zakodowany w UTF-8');
  expect(input).toHaveValue(sigmaYaml);
  expect(screen.getByRole('button', { name: 'Importuj wyłączoną regułę' })).toBeDisabled();
  expect(api.post).not.toHaveBeenCalled();
});

it('preserves valid Polish characters and emoji from a UTF-8 file through API validation', async () => {
  render(<SigmaRules user={sigmaManager} onEvent={vi.fn()} />);
  const input = await openImport();
  const yaml = sigmaYaml.replace('PowerShell sample', 'Zażółć gęślą jaźń 🛡️');
  const bytes = utf8Buffer(yaml);
  fireEvent.change(screen.getByLabelText('Plik Sigma YAML'), {
    target: { files: [{ size: bytes.byteLength, arrayBuffer: async () => bytes }] },
  });
  await waitFor(() => expect(input).toHaveValue(yaml));
  fireEvent.click(screen.getByRole('button', { name: 'Waliduj YAML' }));
  await screen.findByRole('region', { name: 'Podgląd zweryfikowanej reguły' });
  expect(api.post).toHaveBeenCalledExactlyOnceWith('/sigma/validate', { yaml });
});
