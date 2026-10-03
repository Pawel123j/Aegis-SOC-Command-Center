import { useState } from 'react';
import type { FormEvent } from 'react';
import { Empty, ErrorNotice, Loading, Metric, Panel } from '../components';
import type { Me } from '../types';
import { time } from '../utilities';
import { coveragePath, initialCoverageFilter } from './filters';
import type { CoverageFilter } from './filters';
import { canReadMitreCoverage } from './permissions';
import type { CoverageTechnique, MitreCatalogue, MitreCoverage as Coverage } from './types';
import { useCoverage } from './useCoverage';
import './mitre.css';

export function MitreCoverage({ user }: { user: Me }) {
  if (!canReadMitreCoverage(user)) {
    return (
      <Empty title="Pokrycie ATT&CK jest niedostępne">
        Wymaga dostępu do reguł, alertów i incydentów.
      </Empty>
    );
  }
  return <CoveragePage key={`${user.id}/${user.role}/${user.permissions.join(',')}`} />;
}

function CoveragePage() {
  const [filter, setFilter] = useState(initialCoverageFilter);
  const [path, setPath] = useState(() => coveragePath(filter));
  const [formError, setFormError] = useState<unknown>(null);
  const resource = useCoverage(path);
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const next = coveragePath(filter);
      setFormError(null);
      if (next === path) void resource.reload();
      else setPath(next);
    } catch (failure) {
      setFormError(failure);
    }
  }
  function field<K extends keyof CoverageFilter>(name: K, value: CoverageFilter[K]) {
    setFilter((current) => ({ ...current, [name]: value }));
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>MITRE ATT&CK Coverage</h2>
          <p>Sprawdź powiązania reguł oraz zachowane alerty i incydenty w wybranym zakresie.</p>
        </div>
        <button disabled={resource.pending} onClick={() => void resource.reload()}>
          Odśwież pokrycie
        </button>
      </div>
      <p className="notice">
        Powiązanie z taktyką lub techniką wskazuje możliwe zachowanie. Nie potwierdza udanego ataku
        ani zamiaru. Ten widok nie zmienia punktacji ryzyka.
      </p>
      <Panel title="Zakres obserwacji">
        <form onSubmit={submit}>
          <div className="form-row mitre-filters">
            <label>
              Tryb obserwacji
              <select
                value={filter.mode}
                onChange={(event) => field('mode', event.target.value as 'live' | 'replay')}
              >
                <option value="live">Live</option>
                <option value="replay">Replay</option>
              </select>
            </label>
            <label>
              Od · czas lokalny
              <input
                type="datetime-local"
                required
                value={filter.from}
                onChange={(event) => field('from', event.target.value)}
              />
            </label>
            <label>
              Do · czas lokalny
              <input
                type="datetime-local"
                required
                value={filter.to}
                onChange={(event) => field('to', event.target.value)}
              />
            </label>
          </div>
          {filter.mode === 'replay' && (
            <div className="form-row mitre-filters">
              <label>
                Dataset ID replay
                <input
                  required
                  maxLength={36}
                  value={filter.dataset_id}
                  onChange={(event) => field('dataset_id', event.target.value)}
                  placeholder="UUID zestawu danych"
                />
              </label>
              <label>
                Run ID replay
                <input
                  required
                  maxLength={36}
                  value={filter.run_id}
                  onChange={(event) => field('run_id', event.target.value)}
                  placeholder="UUID sesji replay"
                />
              </label>
            </div>
          )}
          <div className="button-row mitre-filter-actions">
            <label className="check-label">
              <input
                type="checkbox"
                checked={filter.include_false_positives}
                onChange={(event) => field('include_false_positives', event.target.checked)}
              />
              Uwzględnij fałszywe alarmy
            </label>
            <button className="primary" disabled={resource.pending}>
              Zastosuj zakres
            </button>
          </div>
          <p className="muted">
            Domyślnie ostatnie 30 dni live; maksymalnie 366 dni. Replay obejmuje jeden zestaw i
            jedną sesję. Liczy się czas zdarzenia alertu, od początku zakresu włącznie do końca
            wyłącznie.
          </p>
          <ErrorNotice error={formError} />
        </form>
      </Panel>
      <div aria-busy={resource.pending} aria-live="polite">
        <ErrorNotice error={resource.error} />
        {resource.pending && <Loading />}
        {resource.data && !resource.error && <CoverageResult data={resource.data} />}
      </div>
    </>
  );
}

function CoverageResult({ data }: { data: Coverage }) {
  const { summary, scope } = data;
  return (
    <>
      <p className="mitre-scope">
        Wynik: {scope.mode === 'live' ? 'Live' : 'Replay'} · {time(scope.from)} – {time(scope.to)} ·{' '}
        {scope.include_false_positives ? 'z fałszywymi alarmami' : 'bez fałszywych alarmów'}
      </p>
      {scope.mode === 'replay' && (
        <p className="mono mitre-scope">
          Dataset ID: {scope.dataset_id} · Run ID: {scope.run_id}
        </p>
      )}
      <div className="metrics">
        <Metric
          label="Alerty w zakresie"
          value={summary.eligible_alerts}
          note="Różne alerty spełniające filtry"
        />
        <Metric
          label="Incydenty w zakresie"
          value={summary.incidents}
          note="Z aktywnie dołączonym alertem w zakresie"
        />
        <Metric
          label="Zaobserwowane techniki"
          value={summary.observed_techniques}
          note="Z mapowaniem do tego katalogu"
        />
        <Metric
          label="Zaobserwowane taktyki"
          value={summary.observed_tactics}
          note="Możliwe powiązania ATT&CK"
        />
      </div>
      {summary.eligible_alerts === 0 && (
        <Empty title="Brak alertów w wybranym zakresie">
          Poniżej pozostaje katalog możliwości reguł. Pusty wynik nie potwierdza bezpieczeństwa
          środowiska.
        </Empty>
      )}
      <Panel title="Kompletność mapowania obserwacji">
        <dl className="facts">
          <dt>Alerty mapowane do tego katalogu</dt>
          <dd>{summary.mapped_alerts}</dd>
          <dt>Alerty bez mapowania</dt>
          <dd>{summary.unmapped_alerts}</dd>
          <dt>Starsze alerty bez zachowanego mapowania</dt>
          <dd>{summary.legacy_alerts}</dd>
          <dt>Alerty z innym katalogiem</dt>
          <dd>{summary.other_catalogue_alerts}</dd>
          <dt>Pominięte fałszywe alarmy</dt>
          <dd>{summary.excluded_false_positive_alerts}</dd>
        </dl>
        <p className="muted">
          Każdy alert i incydent jest liczony raz w danym wierszu. Ten sam rekord może mieć kilka
          powiązań ATT&CK, dlatego suma wierszy może przekraczać łączne liczniki. Rozwiązane alerty
          i zamknięte incydenty pozostają uwzględnione; odpięte powiązania są pomijane.
        </p>
      </Panel>
      <Panel title="Aktualny katalog reguł">
        <div className="metrics">
          <Metric
            label="Techniki w regułach"
            value={summary.configured_techniques}
            note="Bieżące definicje, także wyłączone"
          />
          <Metric
            label="Techniki we włączonych regułach"
            value={summary.enabled_techniques}
            note="Możliwości aktualnie włączonych reguł"
          />
          <Metric
            label="Taktyki w regułach"
            value={summary.configured_tactics}
            note="Bieżące powiązania katalogowe"
          />
          <Metric
            label="Taktyki we włączonych regułach"
            value={summary.enabled_tactics}
            note="Niezależnie od alertów w zakresie"
          />
        </div>
        <p className="muted">
          Włączenie reguły opisuje jej bieżącą konfigurację. Nie dowodzi, że wykryje każdy wariant
          techniki. Zachowane obserwacje mogą pochodzić ze starszej wersji reguły.
        </p>
      </Panel>
      <Panel title="Taktyki ATT&CK">
        <div className="table-wrap">
          <table aria-label="Pokrycie taktyk ATT&CK">
            <thead>
              <tr>
                <th>Taktyka</th>
                <th>Reguły w katalogu</th>
                <th>Włączone reguły</th>
                <th>Alerty</th>
                <th>Incydenty</th>
              </tr>
            </thead>
            <tbody>
              {data.tactics.map((tactic) => (
                <tr key={tactic.id}>
                  <th scope="row">
                    {tactic.name}
                    <small className="mono">{tactic.id}</small>
                  </th>
                  <td>{tactic.configured_rule_count}</td>
                  <td>{tactic.enabled_rule_count}</td>
                  <td>{tactic.alert_count}</td>
                  <td>{tactic.incident_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <TechniqueTable
        key={`${scope.mode}/${scope.from}/${scope.to}/${scope.dataset_id}/${scope.run_id}/${scope.include_false_positives}`}
        data={data}
      />
      <CatalogueSource catalogue={data.catalogue} />
    </>
  );
}

function TechniqueTable({ data }: { data: Coverage }) {
  const [search, setSearch] = useState('');
  const [tactic, setTactic] = useState('');
  const [all, setAll] = useState(false);
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(25);
  const text = search.trim().toLocaleLowerCase();
  const rows = data.techniques.filter(
    (technique) =>
      (all ||
        technique.configured_rule_count > 0 ||
        technique.alert_count > 0 ||
        technique.incident_count > 0) &&
      (!tactic || technique.tactic_ids.includes(tactic)) &&
      (!text || `${technique.id} ${technique.name}`.toLocaleLowerCase().includes(text)),
  );
  const currentPage = Math.min(page, Math.max(0, Math.ceil(rows.length / size) - 1));
  const visible = rows.slice(currentPage * size, (currentPage + 1) * size);
  return (
    <Panel title="Techniki ATT&CK">
      <div className="form-row mitre-filters">
        <label>
          Szukaj techniki lub ID
          <input
            maxLength={120}
            value={search}
            onChange={(event) => {
              setSearch(event.target.value);
              setPage(0);
            }}
          />
        </label>
        <label>
          Taktyka techniki
          <select
            value={tactic}
            onChange={(event) => {
              setTactic(event.target.value);
              setPage(0);
            }}
          >
            <option value="">Wszystkie taktyki</option>
            {data.tactics.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} · {item.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          Wiersze na stronę
          <select
            value={size}
            onChange={(event) => {
              setSize(Number(event.target.value));
              setPage(0);
            }}
          >
            {[25, 50, 100].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="check-label mitre-catalogue-toggle">
        <input
          type="checkbox"
          checked={all}
          onChange={(event) => {
            setAll(event.target.checked);
            setPage(0);
          }}
        />
        Pokaż także techniki bez reguł i obserwacji
      </label>
      <p className="muted">
        Domyślnie pokazano techniki przypisane do reguł lub obecne w obserwacjach. Technika
        nadrzędna i podtechnika mają osobne liczniki.
      </p>
      {visible.length ? (
        <div className="table-wrap">
          <table aria-label="Pokrycie technik ATT&CK">
            <thead>
              <tr>
                <th>Technika</th>
                <th>Taktyki</th>
                <th>Reguły w katalogu</th>
                <th>Włączone reguły</th>
                <th>Alerty</th>
                <th>Incydenty</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((technique) => (
                <TechniqueRow key={technique.id} technique={technique} data={data} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="Brak technik dla tych filtrów">
          Zmień wyszukiwanie lub pokaż pełny katalog.
        </Empty>
      )}
      <div className="pagination">
        <span>
          Strona {currentPage + 1} · techniki: {rows.length}
        </span>
        <div>
          <button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>
            Poprzednie techniki
          </button>
          <button
            disabled={(currentPage + 1) * size >= rows.length}
            onClick={() => setPage(currentPage + 1)}
          >
            Następne techniki
          </button>
        </div>
      </div>
    </Panel>
  );
}

function TechniqueRow({ technique, data }: { technique: CoverageTechnique; data: Coverage }) {
  const tacticNames = technique.tactic_ids.map((id) => {
    const item = data.tactics.find((tactic) => tactic.id === id);
    return item ? `${item.name} · ${id}` : id;
  });
  return (
    <tr>
      <th scope="row">
        {technique.name}
        <small className="mono">{technique.id}</small>
        {technique.is_subtechnique && <small>Podtechnika · nadrzędna {technique.parent_id}</small>}
      </th>
      <td>
        {tacticNames.map((name) => (
          <small key={name}>{name}</small>
        ))}
      </td>
      <td>{technique.configured_rule_count}</td>
      <td>{technique.enabled_rule_count}</td>
      <td>{technique.alert_count}</td>
      <td>{technique.incident_count}</td>
    </tr>
  );
}

function trustedSource(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
      return null;
    if (url.hostname === 'attack.mitre.org') return url.href;
    if (
      ['github.com', 'raw.githubusercontent.com'].includes(url.hostname) &&
      url.pathname.startsWith('/mitre-attack/attack-stix-data/')
    )
      return url.href;
  } catch {
    /* Source metadata remains plain text when it is not a trusted URL. */
  }
  return null;
}

function CatalogueSource({ catalogue }: { catalogue: MitreCatalogue }) {
  const source = trustedSource(catalogue.source_url);
  const license = catalogue.license_url ? trustedSource(catalogue.license_url) : null;
  return (
    <Panel title="Pochodzenie katalogu ATT&CK">
      <p>
        Enterprise ATT&CK · wersja {catalogue.version} · {catalogue.tactics_count} aktywnych taktyk{' '}
        · {catalogue.techniques_count} aktywnych technik i podtechnik.
      </p>
      {catalogue.attribution && <p>{catalogue.attribution}</p>}
      <p className="mitre-source-links">
        {source ? (
          <a href={source} target="_blank" rel="noopener noreferrer">
            Źródło katalogu
          </a>
        ) : (
          'Źródło katalogu w metadanych poniżej.'
        )}
        {license && (
          <a href={license} target="_blank" rel="noopener noreferrer">
            Warunki użycia danych
          </a>
        )}
      </p>
      <details>
        <summary>Wersja i sumy kontrolne źródła</summary>
        <dl className="facts">
          <dt>Domena</dt>
          <dd>{catalogue.domain}</dd>
          <dt>SHA-256 katalogu</dt>
          <dd className="mono">{catalogue.sha256}</dd>
          <dt>Źródło</dt>
          <dd className="mono">{catalogue.source_url}</dd>
          <dt>SHA-256 źródła</dt>
          <dd className="mono">{catalogue.source_sha256}</dd>
          <dt>Wersja źródła</dt>
          <dd className="mono">{catalogue.source_commit}</dd>
          {catalogue.license_url && (
            <>
              <dt>Warunki użycia</dt>
              <dd className="mono">{catalogue.license_url}</dd>
            </>
          )}
        </dl>
      </details>
    </Panel>
  );
}
