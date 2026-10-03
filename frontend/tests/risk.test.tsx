import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api, ApiError } from '../src/api';
import { Alerts } from '../src/Alerts';
import { App } from '../src/App';
import { IncidentDetails } from '../src/incidents/IncidentDetails';
import { AlertRiskButton } from '../src/risk/AlertRiskButton';
import { RiskExplanation } from '../src/risk/RiskExplanation';
import { RiskPanel } from '../src/risk/RiskPanel';
import { RiskScore } from '../src/risk/RiskScore';
import type { RiskLevel } from '../src/risk/levels';
import type { RiskHistory } from '../src/risk/types';
import { alert, alertDetail, incidentFixture, reader } from './incidentFixtures';
import { riskCalculation, riskPolicy } from './riskFixtures';

const scoredAlert = {
  ...alert,
  risk_score: 73,
  risk_level: 'high' as const,
  risk_calculation_id: riskCalculation.id,
};
const scoredDetail = { ...alertDetail, ...scoredAlert, risk_explanation: riskCalculation };
beforeEach(() => {
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path === '/risk/policy') return riskPolicy;
    if (path.startsWith(`/alerts/${alert.id}/risk`))
      return { current: riskCalculation, history: [riskCalculation], history_truncated: false };
    if (path === `/alerts/${alert.id}`) return scoredDetail;
    if (path.startsWith('/alerts?')) return { items: [scoredAlert], total: 1, next_cursor: null };
    if (path.includes('/timeline?') || path.includes('/notes?') || path.includes('/evidence?'))
      return { items: [], total: 0, next_cursor: null };
    if (path === `/incidents/${incidentFixture.id}`) return incidentFixture;
    if (path === '/auth/me') return reader;
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.spyOn(api, 'post').mockResolvedValue({ items: [], total: 0, next_cursor: null });
});

it.each<[number, RiskLevel, string]>([
  [0, 'low', 'Niskie'],
  [29, 'low', 'Niskie'],
  [30, 'medium', 'Średnie'],
  [59, 'medium', 'Średnie'],
  [60, 'high', 'Wysokie'],
  [79, 'high', 'Wysokie'],
  [80, 'critical', 'Krytyczne'],
  [100, 'critical', 'Krytyczne'],
])('labels risk boundary %i with its priority level', (score, level, name) => {
  render(<RiskScore score={score} />);
  expect(screen.getByLabelText(`Ryzyko: ${score} z 100, ${name}`)).toHaveTextContent(
    `${score} / 100`,
  );
  expect(screen.getByText(name)).toHaveClass(level);
});

it('distinguishes a calculated zero from an unavailable result', () => {
  render(
    <>
      <RiskScore score={null} />
      <RiskScore score={0} level="low" />
    </>,
  );
  expect(screen.getByText('Nie obliczono')).toBeInTheDocument();
  expect(screen.getByLabelText('Ryzyko: 0 z 100, Niskie')).toBeInTheDocument();
});

it('shows saved points, limits, clipping and unknown contexts without treating unknowns as clean', () => {
  render(<RiskExplanation calculation={riskCalculation} />);
  const table = screen.getByRole('table', { name: 'Składniki oceny ryzyka' });
  expect(within(table).getByText('+55')).toBeInTheDocument();
  expect(within(table).getByText('73')).toBeInTheDocument();
  const confidence = within(table).getByText('Reputacja IOC').closest('tr')!;
  expect(confidence).toHaveTextContent('—');
  expect(confidence).toHaveTextContent('Brak danych');
  expect(screen.getAllByText('Nie dotyczy').length).toBeGreaterThan(0);
  expect(screen.getByText('Reputacja wskaźników zagrożeń')).toBeInTheDocument();
  expect(screen.getByText(/Nie jest prawdopodobieństwem ataku/)).toBeInTheDocument();
  expect(
    screen.getByText(/Brak danych nie oznacza, że źródło jest bezpieczne/),
  ).toBeInTheDocument();
});

it('escapes untrusted explanations and preserved context values', () => {
  const payload = '<img src=x onerror=attack()><script>attack()</script>';
  const calculation = structuredClone(riskCalculation);
  calculation.components[0].reason = payload;
  calculation.components[0].details = { raw: payload };
  const { container } = render(<RiskExplanation calculation={calculation} />);
  expect(container).toHaveTextContent(payload);
  expect(container.querySelector('img,script')).toBeNull();
});

it('shows a saved simulation sum above 100 and its explicit clipping adjustment', () => {
  const calculation = structuredClone(riskCalculation);
  calculation.score = 100;
  calculation.level = 'critical';
  calculation.raw_score = 115;
  calculation.clipping = -15;
  const ioc = calculation.components.find((component) => component.code === 'I')!;
  Object.assign(ioc, {
    points: 15,
    status: 'known',
    reason: 'Potwierdzona reputacja z zapisanej symulacji.',
  });
  calculation.components.push(
    ...[
      { code: 'A', label: 'Krytyczność hosta', points: 15, maximum: 15 },
      { code: 'U', label: 'Znaczenie konta', points: 10, maximum: 10 },
      { code: 'T', label: 'Potwierdzone taktyki', points: 2, maximum: 6 },
    ].map((component) => ({
      ...component,
      status: 'known' as const,
      reason: 'Wersjonowany kontekst symulacji.',
      evidence_ids: [alert.event_id],
      details: {},
    })),
  );
  calculation.missing_contexts = ['detection_confidence', 'confirmed_history'];
  render(<RiskExplanation calculation={calculation} />);
  const table = screen.getByRole('table', { name: 'Składniki oceny ryzyka' });
  expect(within(table).getByText('115')).toBeInTheDocument();
  expect(within(table).getByText('-15')).toBeInTheDocument();
  expect(screen.getByLabelText('Ryzyko: 100 z 100, Krytyczne')).toBeInTheDocument();
});

it('fetches bounded history only on demand, separates the current assessment and discloses truncation', async () => {
  const previous = {
    ...riskCalculation,
    id: '70000000-0000-0000-0000-000000000002',
    score: 55,
    level: 'medium' as const,
    subject_revision: 1,
    raw_score: 55,
    clipping: 0,
    components: riskCalculation.components.map((component) =>
      component.code === 'D'
        ? component
        : { ...component, points: 0, status: 'not_applicable' as const },
    ),
  };
  vi.mocked(api.get).mockResolvedValue({
    current: riskCalculation,
    history: [riskCalculation, previous],
    history_truncated: true,
  });
  render(<RiskPanel subject="alert" id={alert.id} initial={riskCalculation} />);
  expect(api.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię ryzyka' }));
  expect(
    await screen.findByText(
      'Pokazano najnowsze 10 obliczeń. Starsze wyniki pozostają w historii systemu.',
    ),
  ).toBeInTheDocument();
  expect(api.get).toHaveBeenCalledWith(`/alerts/${alert.id}/risk?limit=10`);
  expect(
    screen.getAllByRole('listitem').some((item) => item.textContent?.includes('wersja oceny 1')),
  ).toBe(true);
  expect(screen.getAllByText('Uzasadnienie historycznej oceny')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Zwiń historię ryzyka' }));
  expect(screen.queryByText('Historia ocen ryzyka')).not.toBeInTheDocument();
});

it('reports a history access error and permits an explicit retry', async () => {
  vi.mocked(api.get).mockRejectedValueOnce(new ApiError(403, 'forbidden'));
  render(<RiskPanel subject="alert" id={alert.id} initial={riskCalculation} />);
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię ryzyka' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Twoja rola');
  expect(screen.getByLabelText('Ryzyko: 73 z 100, Wysokie')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież historię ryzyka' }));
  expect(await screen.findByText('Brak wcześniejszych ocen.')).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps the detail score consistent and marks a newer history result until explicit refresh', async () => {
  const newer = {
    ...riskCalculation,
    id: '70000000-0000-0000-0000-000000000003',
    score: 0,
    level: 'low' as const,
    raw_score: 0,
    clipping: 0,
    subject_revision: 3,
    components: riskCalculation.components.map((component) => ({
      ...component,
      points: 0,
      status: 'not_applicable' as const,
      reason: 'Alert został wyłączony z oceny.',
    })),
    confidence_status: 'not_applicable' as const,
    signal_units: [],
    missing_contexts: [],
    excluded_alert_ids: [alert.id],
  };
  vi.mocked(api.get).mockResolvedValue({
    current: newer,
    history: [newer, riskCalculation],
    history_truncated: false,
  });
  const onRefresh = vi.fn();
  const { rerender } = render(
    <RiskPanel subject="alert" id={alert.id} initial={riskCalculation} onRefresh={onRefresh} />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię ryzyka' }));
  expect(await screen.findByText('Nowsza ocena')).toBeInTheDocument();
  expect(screen.getAllByLabelText('Ryzyko: 73 z 100, Wysokie')).toHaveLength(1);
  expect(screen.getAllByLabelText('Ryzyko: 0 z 100, Niskie')).toHaveLength(2);
  fireEvent.click(screen.getByRole('button', { name: 'Odśwież szczegóły alertu' }));
  expect(onRefresh).toHaveBeenCalledTimes(1);
  rerender(<RiskPanel subject="alert" id={alert.id} initial={newer} onRefresh={onRefresh} />);
  expect(screen.queryByText('Nowsza ocena')).not.toBeInTheDocument();
  expect(screen.queryByLabelText('Ryzyko: 73 z 100, Wysokie')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Ryzyko: 0 z 100, Niskie')).toBeInTheDocument();
});

it('ignores an old history response when the subject changes and clears previous history', async () => {
  let resolve!: (value: RiskHistory) => void;
  vi.mocked(api.get).mockReturnValue(
    new Promise<RiskHistory>((done) => {
      resolve = done;
    }),
  );
  const { rerender } = render(
    <RiskPanel subject="alert" id={alert.id} initial={riskCalculation} />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Pokaż historię ryzyka' }));
  expect(screen.getByRole('status')).toBeInTheDocument();
  rerender(<RiskPanel subject="incident" id="another-case" initial={null} />);
  await act(async () =>
    resolve({ current: riskCalculation, history: [riskCalculation], history_truncated: true }),
  );
  expect(screen.getByText('Ocena nie została obliczona')).toBeInTheDocument();
  expect(screen.queryByLabelText('Ryzyko: 73 z 100, Wysokie')).not.toBeInTheDocument();
  expect(screen.queryByText('Historia ocen ryzyka')).not.toBeInTheDocument();
});

it('loads policy from the API only when permitted and requested', async () => {
  const { rerender } = render(
    <RiskPanel subject="alert" id={alert.id} initial={riskCalculation} />,
  );
  expect(screen.queryByRole('button', { name: 'Zasady punktacji' })).not.toBeInTheDocument();
  rerender(<RiskPanel subject="alert" id={alert.id} initial={riskCalculation} canReadPolicy />);
  expect(api.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Zasady punktacji' }));
  expect(await screen.findByRole('table', { name: 'Poziomy priorytetu' })).toHaveTextContent(
    '80–100',
  );
  expect(api.get).toHaveBeenCalledWith('/risk/policy');
  expect(screen.getByRole('table', { name: 'Limity składników' })).toHaveTextContent('55');
});

it('shows risk in alert lists and the analysis dialog for a single-event alert', async () => {
  render(<Alerts user={reader} onEvent={() => undefined} onCreateIncident={() => undefined} />);
  expect(await screen.findByLabelText('Ryzyko: 73 z 100, Wysokie')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Analizuj' }));
  const dialog = await screen.findByRole('dialog');
  expect(await within(dialog).findByText('Wysoka waga detekcji.')).toBeInTheDocument();
  expect(
    within(dialog).queryByRole('button', { name: 'Zasady punktacji' }),
  ).not.toBeInTheDocument();
  expect(within(dialog).queryByRole('button', { name: 'Potwierdź alert' })).not.toBeInTheDocument();
});

it('makes linked single-event alert risk accessible without opening its evidence', async () => {
  const onEvent = vi.fn();
  render(
    <IncidentDetails
      id={incidentFixture.id}
      user={reader}
      onBack={() => undefined}
      onEvent={onEvent}
    />,
  );
  fireEvent.click(
    await screen.findByRole('button', { name: `Ocena ryzyka alertu: ${alert.title}` }),
  );
  const dialog = await screen.findByRole('dialog');
  expect(await within(dialog).findByText('Wysoka waga detekcji.')).toBeInTheDocument();
  expect(onEvent).not.toHaveBeenCalled();
  expect(api.get).toHaveBeenCalledWith(`/alerts/${alert.id}`);
});

it('shows dialog loading, fetch failure, and retry without exposing an unavailable result', async () => {
  vi.mocked(api.get).mockRejectedValueOnce(new ApiError(503, 'risk_unavailable'));
  render(<AlertRiskButton alertId={alert.id} title={alert.title} />);
  fireEvent.click(screen.getByRole('button', { name: `Ocena ryzyka alertu: ${alert.title}` }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Usługa jest chwilowo niedostępna');
  expect(screen.queryByText('Wysoka waga detekcji.')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Ponów pobranie oceny' }));
  expect(await screen.findByText('Wysoka waga detekcji.')).toBeInTheDocument();
});

it('discards in-flight risk data when authentication authority changes', async () => {
  let resolve!: (value: RiskHistory) => void;
  const get = vi.mocked(api.get).getMockImplementation()!;
  let me = reader;
  vi.mocked(api.get).mockImplementation((path) => {
    if (path === '/auth/me') return Promise.resolve(me);
    if (path.startsWith(`/alerts/${alert.id}/risk`))
      return new Promise<RiskHistory>((done) => {
        resolve = done;
      });
    return get(path);
  });
  vi.spyOn(api, 'restore').mockResolvedValue(reader);
  const subscribe = vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: 'Alerty' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Pokaż historię ryzyka' }));
  me = { ...reader, id: 'another-user', username: 'another-user', permissions: ['events:read'] };
  await act(async () => subscribe.mock.calls[0][0]('session'));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  await act(async () =>
    resolve({ current: riskCalculation, history: [riskCalculation], history_truncated: true }),
  );
  await waitFor(() =>
    expect(screen.getByRole('heading', { name: 'Obraz sytuacji' })).toBeInTheDocument(),
  );
  expect(screen.queryByText('Historia ocen ryzyka')).not.toBeInTheDocument();
});
