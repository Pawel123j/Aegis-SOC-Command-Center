import { fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api } from '../src/api';
import { Alerts } from '../src/Alerts';
import { IncidentAlerts } from '../src/incidents/IncidentAlerts';
import { RiskPolicy } from '../src/risk/RiskPolicy';
import type { RiskCalculation, RiskComponent } from '../src/risk/types';
import type { AlertDetail } from '../src/types';
import { alertDetail, incidentFixture, original } from './incidentFixtures';
import { riskCalculation, riskPolicy } from './riskFixtures';
import { sigmaReader, sigmaRule, sigmaYaml } from './sigmaFixtures';

const sigmaRisk: RiskCalculation = {
  ...riskCalculation,
  id: '70000000-0000-0000-0000-000000000003',
  subject_revision: 3,
  policy_version: 'risk-policy-v3',
  score: 45,
  level: 'medium',
  raw_score: 45,
  signal_units: [],
  input_snapshot: {
    source_alerts: [
      {
        sigma_revision_id: sigmaRule.revision_id,
        sigma_source_sha256: sigmaRule.source_sha256,
        sigma_compiled_sha256: sigmaRule.compiled_sha256,
      },
    ],
    severity_baselines: [{ severity: 'high', evidence_ids: [original.event_id] }],
  },
  components: riskCalculation.components.map((component): RiskComponent => ({
    ...component,
    points: component.code === 'D' ? 45 : 0,
    status: component.code === 'D' ? 'known' : 'unknown',
    evidence_ids: component.code === 'D' ? [original.event_id] : [],
    details: component.code === 'D' ? { severity: 'high' } : {},
    reason:
      component.code === 'D'
        ? 'Zadeklarowany poziom Sigma określa podstawowy priorytet.'
        : 'Brak potwierdzonego niezależnego zachowania.',
  })),
};
const sigmaAlert: AlertDetail = {
  ...alertDetail,
  title: sigmaRule.title,
  detection_type: 'sigma',
  rule_id: `sigma:${sigmaRule.id}`,
  rule_version: '1',
  evaluator_version: sigmaRule.evaluator_version,
  risk_score: 45,
  risk_level: 'medium',
  risk_explanation: sigmaRisk,
  mitre_mapping: sigmaRule.mitre_mapping,
  rule_snapshot: {
    id: `sigma:${sigmaRule.id}`,
    version: '1',
    revision_id: sigmaRule.revision_id,
    source_sha256: sigmaRule.source_sha256,
    compiled_sha256: sigmaRule.compiled_sha256,
    evaluator_version: sigmaRule.evaluator_version,
    definition_yaml: sigmaYaml,
  },
  reason: {
    summary: 'Zdarzenie spełnia obsługiwany warunek reguły Sigma; wymaga oceny analityka.',
  },
};

beforeEach(() => {
  vi.spyOn(api, 'get').mockImplementation(async (path) => {
    if (path.startsWith('/alerts?')) return { items: [sigmaAlert], next_cursor: null, total: 1 };
    if (path.includes('/risk?'))
      return {
        current: sigmaRisk,
        history: [sigmaRisk, riskCalculation],
        history_truncated: false,
      };
    if (path === '/risk/policy')
      return {
        ...riskPolicy,
        version: 'risk-policy-v3',
        sigma: 'Declared Sigma severity contributes D only.',
      };
    return sigmaAlert;
  });
});

it('identifies Sigma alerts and preserves rule provenance, declared-severity risk and original evidence', async () => {
  const onEvent = vi.fn();
  render(<Alerts user={sigmaReader} onEvent={onEvent} onCreateIncident={vi.fn()} />);
  expect(await screen.findByText('Sigma')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Analizuj' }));
  const dialog = await screen.findByRole('dialog', { name: sigmaAlert.title });
  await within(dialog).findByText('risk-policy-v3');
  expect(within(dialog).getByText('Sigma')).toBeInTheDocument();
  expect(
    within(dialog).getByText(/nie potwierdza pewności ani niezależnego zachowania/),
  ).toBeInTheDocument();
  expect(within(dialog).getByText('+45')).toBeInTheDocument();
  for (const label of ['Niezależne sygnały', 'Zdarzenia skorelowane']) {
    const row = within(dialog).getByText(label).closest('tr')!;
    expect(within(row).getByText('—')).toBeInTheDocument();
  }
  fireEvent.click(within(dialog).getByText('Snapshot reguły'));
  const frozen = within(dialog).getByText('Snapshot reguły').closest('details')!;
  expect(within(frozen).getByText(/"revision_id":/)).toHaveTextContent(sigmaRule.revision_id);
  expect(within(frozen).getByText(/"revision_id":/)).toHaveTextContent(sigmaRule.source_sha256);
  fireEvent.click(
    within(dialog).getByText('Zachowany zapis obliczenia, dowodów i sumy kontrolnej'),
  );
  const input = within(dialog)
    .getByText('Zachowany zapis obliczenia, dowodów i sumy kontrolnej')
    .closest('details')!;
  expect(within(input).getByText(/"severity_baselines":/)).toHaveTextContent(
    sigmaRule.compiled_sha256,
  );
  fireEvent.click(
    within(dialog).getByRole('button', { name: 'Otwórz zdarzenie 1: process_started' }),
  );
  expect(onEvent).toHaveBeenCalledExactlyOnceWith(original);
});

it('reads a retained v2 historical calculation alongside a Sigma v3 calculation', async () => {
  render(<Alerts user={sigmaReader} onEvent={vi.fn()} onCreateIncident={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Analizuj' }));
  const dialog = await screen.findByRole('dialog', { name: sigmaAlert.title });
  fireEvent.click(await within(dialog).findByRole('button', { name: 'Pokaż historię ryzyka' }));
  fireEvent.click(await within(dialog).findByText('Uzasadnienie historycznej oceny'));
  expect(within(dialog).getByText('risk-policy-v2')).toBeInTheDocument();
  expect(within(dialog).getByText('risk-policy-v3')).toBeInTheDocument();
  expect(within(dialog).getByText('+55')).toBeInTheDocument();
});

it('labels a linked Sigma alert and opens its original single-event proof from an incident', async () => {
  const onEvent = vi.fn();
  render(
    <IncidentAlerts
      incident={{ ...incidentFixture, related_alerts: [sigmaAlert] }}
      editable={false}
      disabled={false}
      mutate={vi.fn()}
      onEvent={onEvent}
      riskReadable={false}
      policyReadable={false}
    />,
  );
  expect(screen.getByText('Sigma')).toBeInTheDocument();
  expect(screen.getByText(sigmaRule.title)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Otwórz dowód' }));
  await vi.waitFor(() => expect(onEvent).toHaveBeenCalledExactlyOnceWith(original));
});

it('renders the v3 policy contract and retained Sigma contribution metadata without assuming v2', async () => {
  render(<RiskPolicy />);
  fireEvent.click(screen.getByRole('button', { name: 'Zasady punktacji' }));
  await screen.findByText('Polityka oceny ryzyka');
  fireEvent.click(await screen.findByText('Wersja i zachowany zapis polityki'));
  expect(screen.getByText(/"version": "risk-policy-v3"/)).toHaveTextContent(
    'Declared Sigma severity contributes D only.',
  );
});
