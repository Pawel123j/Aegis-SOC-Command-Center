import { Badge } from '../components';
import type { IncidentMitreMapping, MitreMapping as Mapping, MitreTechnique } from './types';
import './mitre.css';

function Techniques({ techniques }: { techniques: MitreTechnique[] }) {
  return (
    <ul className="mitre-mapping-list">
      {techniques.map((technique, index) => (
        <li key={`${technique.id}/${index}`}>
          <strong>{technique.name}</strong> <span className="mono">{technique.id}</span>
          <div className="mitre-tactic-labels">
            {technique.tactics.map((tactic) => (
              <Badge key={tactic.id}>
                {tactic.name} · {tactic.id}
              </Badge>
            ))}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function MitreMapping({ mapping }: { mapping: Mapping | undefined }) {
  return (
    <section className="mitre-mapping" aria-label="Powiązanie z MITRE ATT&CK">
      <h3>MITRE ATT&CK</h3>
      <p>Powiązanie z katalogiem opisuje możliwe zachowanie. Nie potwierdza ataku ani zamiaru.</p>
      {mapping?.status === 'mapped' ? (
        <>
          <Techniques techniques={mapping.techniques} />
          <p className="muted">Katalog: {mapping.catalogue_version}</p>
        </>
      ) : (
        <p className="notice">
          {mapping?.status === 'legacy_unmapped'
            ? 'Starszy alert nie ma zachowanego, zweryfikowanego mapowania ATT&CK.'
            : 'Brak zweryfikowanego mapowania ATT&CK.'}
        </p>
      )}
      {mapping && (
        <details>
          <summary>Pochodzenie mapowania ATT&CK</summary>
          <p>{mapping.reason}</p>
          <dl className="facts">
            <dt>Wersja katalogu</dt>
            <dd>{mapping.catalogue_version ?? 'Nieznana'}</dd>
            <dt>SHA-256 katalogu</dt>
            <dd className="mono">{mapping.catalogue_hash ?? 'Nieznany'}</dd>
            <dt>Wersja mapowania</dt>
            <dd>{mapping.mapping_version ?? 'Nieznana'}</dd>
            <dt>SHA-256 mapowania</dt>
            <dd className="mono">{mapping.mapping_hash ?? 'Nieznany'}</dd>
          </dl>
        </details>
      )}
    </section>
  );
}

export function IncidentMitre({ mapping }: { mapping: IncidentMitreMapping | undefined }) {
  return (
    <section className="mitre-mapping" aria-label="MITRE ATT&CK incydentu">
      <h3>MITRE ATT&CK incydentu</h3>
      <p>
        Powiązania pochodzą z aktywnie dołączonych alertów, z pominięciem fałszywych alarmów.
        Opisują możliwe zachowania i nie potwierdzają ataku ani zamiaru.
      </p>
      {mapping ? (
        <>
          {mapping.techniques.length ? (
            <Techniques techniques={mapping.techniques} />
          ) : (
            <p className="muted">Brak zweryfikowanych technik w powiązanych alertach.</p>
          )}
          <p className="muted">
            Alerty z mapowaniem: {mapping.mapped_alerts} · bez mapowania: {mapping.unmapped_alerts}{' '}
            · starsze: {mapping.legacy_alerts} · pominięte fałszywe alarmy:{' '}
            {mapping.excluded_false_positive_alerts}
          </p>
          <details>
            <summary>Katalogi zachowanych mapowań</summary>
            <ul className="mitre-mapping-list">
              {mapping.techniques.map((technique, index) => (
                <li key={`${technique.catalogue_hash}/${technique.id}/${index}`}>
                  {technique.id} · katalog {technique.catalogue_version}
                  <small className="mono">{technique.catalogue_hash}</small>
                </li>
              ))}
            </ul>
          </details>
        </>
      ) : (
        <p className="muted">Mapowanie ATT&CK nie jest dostępne.</p>
      )}
    </section>
  );
}
