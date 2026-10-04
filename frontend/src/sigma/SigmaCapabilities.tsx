import { JsonView } from '../components';
import type { SigmaCapabilities as Capabilities } from './types';

export function SigmaCapabilities({ capabilities }: { capabilities: Capabilities }) {
  return (
    <details className="sigma-guidance">
      <summary>Obsługiwany zakres Sigma i pola logów</summary>
      <p>
        Każda reguła wymaga title, id UUID, logsource i detection.condition. Pola odnoszą się do
        pełnego znormalizowanego rekordu. Warunki łączą AND, OR i NOT z nawiasami.
      </p>
      <p>
        Operatory: {capabilities.operators.join(', ')}. Warunki logiczne:{' '}
        {capabilities.boolean_operators.join(', ')}. Definicja do{' '}
        {capabilities.max_yaml_bytes / 1024} KiB; test do {capabilities.max_test_events} zdarzeń;
        katalog do {capabilities.max_rules} reguł; historia do {capabilities.max_revisions} wersji.
      </p>
      <h3>Obsługiwane logsource</h3>
      <JsonView value={capabilities.logsources} />
      <h3>Dostępne pola</h3>
      <p className="mono sigma-fields">{capabilities.fields.join(', ')}</p>
      <h3>Ograniczenia</h3>
      <ul>
        {capabilities.limitations.map((limitation, index) => (
          <li key={index}>{limitation}</li>
        ))}
      </ul>
      <p className="muted">Wersja silnika: {capabilities.evaluator_version}</p>
    </details>
  );
}
