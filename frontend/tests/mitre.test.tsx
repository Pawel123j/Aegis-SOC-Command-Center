import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { Alerts } from '../src/Alerts';
import { App } from '../src/App';
import { Correlations } from '../src/detections/Correlations';
import { SingleEventRules } from '../src/detections/SingleEventRules';
import { IncidentSummary } from '../src/incidents/IncidentSummary';
import { MitreCoverage } from '../src/mitre/MitreCoverage';
import { MitreMapping } from '../src/mitre/MitreMapping';
import type { MitreCoverage as Coverage } from '../src/mitre/types';
import { alert, alertDetail, incidentFixture } from './incidentFixtures';
import { correlationRule } from './correlationFixtures';
import { incidentMitreMapping, mitreCoverage, mitreMapping, mitreReader } from './mitreFixtures';

beforeEach(() => {
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path.startsWith('/mitre/coverage?')) return mitreCoverage;
    if (path.startsWith('/alerts?')) return { items: [alert], total: 1, next_cursor: null };
    if (path === `/alerts/${alert.id}`) return { ...alertDetail, mitre_mapping: mitreMapping };
    if (path === '/detections')
      return {
        items: [
          {
            ...(alertDetail.rule_snapshot as object),
            id: 'powershell',
            title: 'Suspicious PowerShell',
            mitre_mapping: mitreMapping,
            enabled: true,
            version: 1,
          },
        ],
        next_cursor: null,
      };
    if (path === '/correlations') return { items: [correlationRule], next_cursor: null };
    if (path === '/correlations/status') return { counts: {}, scopes: [], scopes_truncated: false };
    if (path.startsWith('/correlations/'))
      return { ...correlationRule, mitre_mapping: mitreMapping };
    return { items: [], total: 0, next_cursor: null };
  });
  vi.spyOn(api, 'post').mockResolvedValue({ items: [], total: 0, next_cursor: null });
  vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
});

function coverageRequests() {
  return vi.mocked(api.get).mock.calls.filter(([path]) => path.startsWith('/mitre/coverage?'));
}

it.each(['detections:read', 'alerts:read', 'incidents:read'])(
  'requires %s along with the other coverage permissions',
  async (permission) => {
    const user = {
      ...mitreReader,
      permissions: mitreReader.permissions.filter((value) => value !== permission),
    };
    vi.spyOn(api, 'restore').mockResolvedValue(user);
    const app = render(<App />);
    await screen.findByRole('navigation');
    expect(screen.queryByRole('button', { name: 'MITRE ATT&CK' })).not.toBeInTheDocument();
    app.unmount();
    render(<MitreCoverage user={user} />);
    expect(screen.getByText('Pokrycie ATT&CK jest niedostępne')).toBeInTheDocument();
    expect(coverageRequests()).toHaveLength(0);
  },
);

it('opens a composite-gated navigation page and requests the last 30 days live without false positives', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(mitreReader);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'MITRE ATT&CK' }));
  await screen.findByRole('table', { name: 'Pokrycie technik ATT&CK' });
  const params = new URL(`https://aegis.local${coverageRequests()[0][0]}`).searchParams;
  expect(params.get('mode')).toBe('live');
  expect(params.get('include_false_positives')).toBe('false');
  expect(params.has('dataset_id') || params.has('run_id')).toBe(false);
  expect(new Date(params.get('to')!).getTime() - new Date(params.get('from')!).getTime()).toBe(
    30 * 86400000,
  );
});

it('shows distinct server counters, named tactics, subtechniques, provenance and candidate limits', async () => {
  render(<MitreCoverage user={mitreReader} />);
  const table = await screen.findByRole('table', { name: 'Pokrycie technik ATT&CK' });
  const row = within(table)
    .getByRole('rowheader', { name: /PowerShell/ })
    .closest('tr')!;
  expect(row).toHaveTextContent('T1059.001');
  expect(row).toHaveTextContent('Podtechnika · nadrzędna T1059');
  expect(row).toHaveTextContent('Execution · TA0002');
  expect(
    within(row)
      .getAllByRole('cell')
      .map((cell) => cell.textContent),
  ).toEqual(['Execution · TA0002', '2', '1', '3', '2']);
  const total = screen.getByText('Alerty w zakresie').closest('.metric')!;
  expect(total).toHaveTextContent('9');
  expect(screen.getByText('Alerty z innym katalogiem').nextSibling).toHaveTextContent('2');
  expect(screen.getByText(/Nie potwierdza udanego ataku/)).toBeInTheDocument();
  expect(screen.getByText(/Ten widok nie zmienia punktacji ryzyka/)).toBeInTheDocument();
  expect(screen.getByText(/suma wierszy może przekraczać/)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Źródło katalogu' })).toHaveAttribute(
    'rel',
    'noopener noreferrer',
  );
  expect(screen.getByText(mitreCoverage.catalogue.attribution!)).toBeInTheDocument();
});

it('keeps configured rules visible with an empty observation result', async () => {
  const empty = structuredClone(mitreCoverage);
  Object.assign(empty.summary, {
    eligible_alerts: 0,
    mapped_alerts: 0,
    unmapped_alerts: 0,
    legacy_alerts: 0,
    other_catalogue_alerts: 0,
    incidents: 0,
    observed_techniques: 0,
    observed_tactics: 0,
  });
  empty.techniques.forEach((item) => {
    item.alert_count = 0;
    item.incident_count = 0;
  });
  empty.tactics.forEach((item) => {
    item.alert_count = 0;
    item.incident_count = 0;
  });
  vi.mocked(api.get).mockResolvedValue(empty);
  render(<MitreCoverage user={mitreReader} />);
  await screen.findByText('Brak alertów w wybranym zakresie');
  expect(screen.getByText(/Pusty wynik nie potwierdza bezpieczeństwa/)).toBeInTheDocument();
  expect(screen.getByRole('rowheader', { name: /PowerShell/ })).toBeInTheDocument();
  expect(screen.getByText('Techniki we włączonych regułach').closest('.metric')).toHaveTextContent(
    '1',
  );
});

it('defaults to configured or observed techniques, permits uncovered search and bounds table pages', async () => {
  const many = structuredClone(mitreCoverage);
  many.techniques.push(
    ...Array.from({ length: 28 }, (_, index) => ({
      ...many.techniques[1],
      id: `T${2000 + index}`,
      name: `Uncovered ${index}`,
    })),
  );
  vi.mocked(api.get).mockResolvedValue(many);
  render(<MitreCoverage user={mitreReader} />);
  const table = await screen.findByRole('table', { name: 'Pokrycie technik ATT&CK' });
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  fireEvent.click(screen.getByLabelText('Pokaż także techniki bez reguł i obserwacji'));
  expect(within(table).getAllByRole('row')).toHaveLength(26);
  fireEvent.click(screen.getByRole('button', { name: 'Następne techniki' }));
  expect(within(table).getAllByRole('row')).toHaveLength(6);
  fireEvent.change(screen.getByLabelText('Szukaj techniki lub ID'), {
    target: { value: 'T1059.001' },
  });
  expect(within(table).getAllByRole('row')).toHaveLength(2);
  expect(screen.getByText('Strona 1 · techniki: 1')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Taktyka techniki'), { target: { value: 'TA0001' } });
  expect(screen.getByText('Brak technik dla tych filtrów')).toBeInTheDocument();
});

it('validates time and replay scope before requesting a result', async () => {
  render(<MitreCoverage user={mitreReader} />);
  await screen.findByText('PowerShell');
  const original = coverageRequests().length;
  const from = screen.getByLabelText('Od · czas lokalny');
  const to = screen.getByLabelText('Do · czas lokalny');
  for (const [start, end] of [
    ['2026-02-01T00:00', '2026-01-01T00:00'],
    ['2024-01-01T00:00', '2026-01-01T00:00'],
    ['2099-01-01T00:00', '2099-01-02T00:00'],
  ]) {
    fireEvent.change(from, { target: { value: start } });
    fireEvent.change(to, { target: { value: end } });
    fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('maksymalnie 366 dni');
  }
  fireEvent.change(from, { target: { value: '2026-01-01T00:00' } });
  fireEvent.change(to, { target: { value: '2026-01-02T00:00' } });
  fireEvent.change(screen.getByLabelText('Tryb obserwacji'), { target: { value: 'replay' } });
  fireEvent.change(screen.getByLabelText('Dataset ID replay'), { target: { value: 'invalid' } });
  fireEvent.change(screen.getByLabelText('Run ID replay'), {
    target: { value: '00000000-0000-0000-0000-000000000000' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('niezerowego Run ID');
  expect(coverageRequests()).toHaveLength(original);
});

it('sends the exact replay dataset and run with an explicit false-positive choice and removes replay IDs in live', async () => {
  render(<MitreCoverage user={mitreReader} />);
  await screen.findByText('PowerShell');
  fireEvent.change(screen.getByLabelText('Tryb obserwacji'), { target: { value: 'replay' } });
  const dataset = '40000000-0000-0000-0000-000000000001';
  const run = '50000000-0000-0000-0000-000000000001';
  fireEvent.change(screen.getByLabelText('Dataset ID replay'), { target: { value: dataset } });
  fireEvent.change(screen.getByLabelText('Run ID replay'), { target: { value: run } });
  fireEvent.click(screen.getByLabelText('Uwzględnij fałszywe alarmy'));
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  await waitFor(() => expect(coverageRequests()).toHaveLength(2));
  let params = new URL(`https://aegis.local${coverageRequests().at(-1)![0]}`).searchParams;
  expect(params.get('mode')).toBe('replay');
  expect(params.get('dataset_id')).toBe(dataset);
  expect(params.get('run_id')).toBe(run);
  expect(params.get('include_false_positives')).toBe('true');
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Zastosuj zakres' })).toBeEnabled(),
  );
  fireEvent.change(screen.getByLabelText('Tryb obserwacji'), { target: { value: 'live' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  await waitFor(() => expect(coverageRequests()).toHaveLength(3));
  params = new URL(`https://aegis.local${coverageRequests().at(-1)![0]}`).searchParams;
  expect(params.has('dataset_id') || params.has('run_id')).toBe(false);
});

it('clears an earlier result during reload, displays access failures and permits retry', async () => {
  render(<MitreCoverage user={mitreReader} />);
  await screen.findByText('PowerShell');
  vi.mocked(api.get).mockRejectedValueOnce(new ApiError(403, 'forbidden'));
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież pokrycie' }));
  expect(screen.queryByText('PowerShell')).not.toBeInTheDocument();
  expect(await screen.findByRole('alert')).toHaveTextContent('Twoja rola');
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież pokrycie' }));
  await screen.findByText('PowerShell');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('ignores a stale response when observation scope changes', async () => {
  let old!: (data: Coverage) => void;
  vi.mocked(api.get).mockReturnValueOnce(
    new Promise<Coverage>((resolve) => {
      old = resolve;
    }),
  );
  render(<MitreCoverage user={mitreReader} />);
  await waitFor(() => expect(coverageRequests()).toHaveLength(1));
  // A session notification invalidates the initial flight and allows a new scoped request.
  await act(async () => vi.mocked(api.subscribe).mock.calls[0][0]('session'));
  fireEvent.change(screen.getByLabelText('Od · czas lokalny'), {
    target: { value: '2026-01-01T00:00' },
  });
  fireEvent.change(screen.getByLabelText('Do · czas lokalny'), {
    target: { value: '2026-01-02T00:00' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Zastosuj zakres' }));
  await screen.findByText('PowerShell');
  const stale = structuredClone(mitreCoverage);
  stale.techniques[0].name = 'STALE PRIVATE RESPONSE';
  await act(async () => old(stale));
  expect(screen.queryByText('STALE PRIVATE RESPONSE')).not.toBeInTheDocument();
  expect(screen.getByText('PowerShell')).toBeInTheDocument();
});

it.each(['session', 'logout'] as const)(
  'clears coverage and blocks stale flight data on %s',
  async (kind) => {
    let resolve!: (data: Coverage) => void;
    render(<MitreCoverage user={mitreReader} />);
    await screen.findByText('PowerShell');
    vi.mocked(api.get).mockReturnValueOnce(
      new Promise<Coverage>((done) => {
        resolve = done;
      }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Odśwież pokrycie' }));
    await act(async () => vi.mocked(api.subscribe).mock.calls[0][0](kind));
    expect(screen.queryByText('PowerShell')).not.toBeInTheDocument();
    await act(async () => resolve(mitreCoverage));
    expect(screen.queryByText('PowerShell')).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Sesja zmieniła się');
  },
);

it('remounts isolated coverage when the account changes and discards the previous account response', async () => {
  let resolve!: (data: Coverage) => void;
  vi.mocked(api.get).mockReturnValueOnce(
    new Promise<Coverage>((done) => {
      resolve = done;
    }),
  );
  const component = render(<MitreCoverage user={mitreReader} />);
  await waitFor(() => expect(coverageRequests()).toHaveLength(1));
  component.rerender(<MitreCoverage user={{ ...mitreReader, id: 'another-user' }} />);
  await screen.findByText('PowerShell');
  const old = structuredClone(mitreCoverage);
  old.techniques[0].name = 'PRIVATE OLD ACCOUNT';
  await act(async () => resolve(old));
  expect(screen.queryByText('PRIVATE OLD ACCOUNT')).not.toBeInTheDocument();
});

it('escapes catalogue and mapping metadata and rejects executable or off-origin source links', async () => {
  const payload = '<img src=x onerror=attack()><script>attack()</script>';
  const data = structuredClone(mitreCoverage);
  data.catalogue.source_url = 'javascript:attack()';
  data.catalogue.license_url = 'https://malicious.example/license';
  data.catalogue.attribution = payload;
  data.techniques[0].name = payload;
  vi.mocked(api.get).mockResolvedValue(data);
  const component = render(<MitreCoverage user={mitreReader} />);
  await screen.findByRole('table', { name: 'Pokrycie technik ATT&CK' });
  expect(component.container).toHaveTextContent(payload);
  expect(component.container.querySelector('img,script')).toBeNull();
  expect(screen.queryByRole('link', { name: 'Źródło katalogu' })).not.toBeInTheDocument();
  expect(screen.queryByRole('link', { name: 'Warunki użycia danych' })).not.toBeInTheDocument();
  component.unmount();
  const mapping = structuredClone(mitreMapping);
  mapping.techniques[0].name = payload;
  mapping.reason = payload;
  const mapped = render(<MitreMapping mapping={mapping} />);
  expect(mapped.container).toHaveTextContent(payload);
  expect(mapped.container.querySelector('img,script')).toBeNull();
});

it.each(['unmapped', 'legacy_unmapped'] as const)(
  'displays %s explicitly without inventing a technique',
  (status) => {
    render(
      <MitreMapping
        mapping={{
          ...mitreMapping,
          status,
          techniques: [],
          catalogue_version: null,
          catalogue_hash: null,
        }}
      />,
    );
    expect(screen.queryByText('PowerShell')).not.toBeInTheDocument();
    expect(
      screen.getByText(
        status === 'legacy_unmapped'
          ? 'Starszy alert nie ma zachowanego, zweryfikowanego mapowania ATT&CK.'
          : 'Brak zweryfikowanego mapowania ATT&CK.',
      ),
    ).toBeInTheDocument();
  },
);

it('shows resolved current mapping names on single-event and correlation rule details', async () => {
  const single = render(<SingleEventRules user={mitreReader} />);
  expect(await screen.findByText('PowerShell')).toBeInTheDocument();
  expect(screen.getByText('Execution · TA0002')).toBeInTheDocument();
  single.unmount();
  render(<Correlations user={mitreReader} onEvent={() => undefined} />);
  fireEvent.click(
    await screen.findByRole('button', { name: `Przejrzyj regułę: ${correlationRule.title}` }),
  );
  expect(await screen.findByText('PowerShell')).toBeInTheDocument();
});

it('shows frozen alert mapping names while preserving event evidence and risk detail', async () => {
  render(
    <Alerts user={mitreReader} onEvent={() => undefined} onCreateIncident={() => undefined} />,
  );
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  const mapping = await screen.findByRole('region', { name: 'Powiązanie z MITRE ATT&CK' });
  expect(mapping).toHaveTextContent('PowerShell');
  expect(mapping).toHaveTextContent('T1059.001');
  expect(mapping).toHaveTextContent('Execution · TA0002');
  expect(screen.getByText('Dlaczego powstał alert')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Ocena ryzyka' })).toBeInTheDocument();
});

it('shows incident mapping names and explicitly reports excluded, unmapped and legacy alerts', () => {
  render(
    <IncidentSummary incident={{ ...incidentFixture, mitre_mapping: incidentMitreMapping }} />,
  );
  const mapping = screen.getByRole('region', { name: 'MITRE ATT&CK incydentu' });
  expect(mapping).toHaveTextContent('PowerShell');
  expect(mapping).toHaveTextContent('bez mapowania: 1');
  expect(mapping).toHaveTextContent('starsze: 1');
  expect(mapping).toHaveTextContent('pominięte fałszywe alarmy: 1');
  expect(mapping).toHaveTextContent('katalog 19.2');
});
