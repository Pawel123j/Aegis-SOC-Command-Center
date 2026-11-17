import { useState } from 'react';
import type { FormEvent } from 'react';
import { Badge, Empty, ErrorNotice, Loading, Metric, Panel } from '../components';
import { time } from '../utilities';
import type { Category, DashboardReport, EntityRank } from './types';
import { useDashboard } from './useDashboard';
import './dashboard.css';

function Distribution({ title, rows }: { title: string; rows: Category[] }) {
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  return (
    <Panel title={title}>
      <p className="muted">{total} alertów w wybranym zakresie</p>
      <ul className="dashboard-bars" aria-label={title}>
        {rows.map((row) => (
          <li key={row.id}>
            <div>
              <span>{row.label}</span>
              <strong>{row.count}</strong>
            </div>
            <meter
              min={0}
              max={Math.max(total, 1)}
              value={row.count}
              aria-label={`${row.label}: ${row.count}`}
            />
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function Ranking({ title, rows }: { title: string; rows: EntityRank[] }) {
  return (
    <Panel title={title}>
      {rows.length ? (
        <ol className="dashboard-ranking">
          {rows.map((row) => (
            <li key={row.id}>
              <span>
                <strong>{row.label}</strong>
                <small>Obserwowana tożsamość · {row.id.slice(0, 8)}</small>
              </span>
              <span>
                {row.count} <small>zdarzeń</small>
              </span>
            </li>
          ))}
        </ol>
      ) : (
        <Empty title="Brak obserwowanych encji">
          Brak rozpoznanej encji tego rodzaju w wybranym oknie.
        </Empty>
      )}
      <p className="muted">
        Do 10 pozycji. Jedno zdarzenie liczymy raz na tożsamość; takie same nazwy mogą oznaczać
        różne konta lub hosty.
      </p>
    </Panel>
  );
}

function Ingestion({ data }: { data: DashboardReport['ingestion'] }) {
  const max = Math.max(1, ...data.buckets.map((bucket) => bucket.count));
  return (
    <Panel title="Tempo przyjmowania logów">
      <div className="dashboard-rate-summary">
        <strong>{data.average_eps.toFixed(3)} zdarzeń/s</strong>
        <span>{data.accepted_events} nowych logów w ostatniej godzinie wybranego okna</span>
      </div>
      <svg
        viewBox="0 0 600 150"
        role="img"
        aria-label="Liczba przyjętych logów w 60 kolejnych minutach"
        className="dashboard-rate"
      >
        <line x1="0" y1="140" x2="600" y2="140" />
        {data.buckets.map((bucket, index) => (
          <rect
            key={bucket.from}
            x={index * 10 + 1}
            y={140 - (bucket.count / max) * 130}
            width={8}
            height={(bucket.count / max) * 130}
          >
            <title>
              {time(bucket.from)} — {time(bucket.to)}: {bucket.count} logów,{' '}
              {bucket.events_per_second.toFixed(3)} zdarzeń/s
            </title>
          </rect>
        ))}
      </svg>
      <div className="dashboard-axis">
        <span>{time(data.buckets[0]?.from)}</span>
        <span>Najwyższa minuta: {max === 1 && data.accepted_events === 0 ? 0 : max} logów</span>
        <span>{time(data.buckets.at(-1)?.to)}</span>
      </div>
      <p className="muted">
        Czas przyjęcia, po deduplikacji. Każdy słupek obejmuje pełne 60 sekund. Spóźniony log trafia
        do tempa przyjęcia w chwili odbioru.
      </p>
      <details>
        <summary>Tabela minutowa</summary>
        <div className="dashboard-rate-table">
          <table>
            <caption>Przyjęte logi na minutę</caption>
            <thead>
              <tr>
                <th>Początek</th>
                <th>Logi</th>
                <th>Zdarzenia/s</th>
              </tr>
            </thead>
            <tbody>
              {data.buckets.map((bucket) => (
                <tr key={bucket.from}>
                  <td>{time(bucket.from)}</td>
                  <td>{bucket.count}</td>
                  <td>{bucket.events_per_second.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </Panel>
  );
}

export function Dashboard({
  onEvents,
  onAlerts,
  onIncidents,
}: {
  onEvents: () => void;
  onAlerts: () => void;
  onIncidents: () => void;
}) {
  const [mode, setMode] = useState('live');
  const [dataset, setDataset] = useState('');
  const [run, setRun] = useState('');
  const [end, setEnd] = useState('');
  const [includeFp, setIncludeFp] = useState(false);
  const [path, setPath] = useState('/dashboard');
  const [automatic, setAutomatic] = useState(true);
  const [filterError, setFilterError] = useState<unknown>(null);
  const resource = useDashboard(path, automatic);
  const data = resource.data;
  function apply(event: FormEvent) {
    event.preventDefault();
    const params = new URLSearchParams({ mode });
    if (mode === 'replay') {
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const zero = '00000000-0000-0000-0000-000000000000';
      if (!uuid.test(dataset) || !uuid.test(run) || dataset === zero || run === zero) {
        setFilterError(new Error('Podaj identyfikator zestawu i niezerowego przebiegu replay.'));
        return;
      }
      params.set('dataset_id', dataset);
      params.set('run_id', run);
    }
    if (end) params.set('to', `${end}:00Z`);
    if (includeFp) params.set('include_false_positives', 'true');
    setFilterError(null);
    setPath(`/dashboard?${params}`);
    resource.reload();
  }
  return (
    <>
      <div className="intro">
        <div>
          <h2>Obraz sytuacji SOC</h2>
          <p>Jedno okno danych dla liczników, rankingów i rozkładów.</p>
        </div>
        <button onClick={resource.reload} disabled={resource.pending || resource.expired}>
          Odśwież Dashboard
        </button>
      </div>
      <Panel title="Zakres danych">
        <form onSubmit={apply} className="dashboard-filters">
          <label>
            Dane
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="live">Bieżące</option>
              <option value="replay">Replay</option>
            </select>
          </label>
          {mode === 'replay' && (
            <>
              <label>
                Zestaw replay
                <input
                  value={dataset}
                  onChange={(event) => setDataset(event.target.value)}
                  required
                />
              </label>
              <label>
                Przebieg replay
                <input value={run} onChange={(event) => setRun(event.target.value)} required />
              </label>
            </>
          )}
          <label>
            Koniec okna (UTC)
            <input
              type="datetime-local"
              value={end}
              onChange={(event) => setEnd(event.target.value)}
            />
          </label>
          <label className="dashboard-check">
            <input
              type="checkbox"
              checked={includeFp}
              onChange={(event) => setIncludeFp(event.target.checked)}
            />
            Uwzględnij fałszywe alarmy
          </label>
          <button type="submit" disabled={resource.expired}>
            Zastosuj zakres
          </button>
        </form>
        <p className="muted">
          Pusty koniec okna oznacza bieżący czas. Zdarzenia i alerty obejmują poprzednie 24 godziny
          według czasu zdarzenia.
        </p>
        <label className="dashboard-check">
          <input
            type="checkbox"
            checked={automatic}
            onChange={(event) => setAutomatic(event.target.checked)}
          />
          Automatyczne odświeżanie co 10 sekund
        </label>
        <p role="status">
          {resource.expired
            ? 'Sesja się zmieniła. Dane zostały ukryte.'
            : resource.polling
              ? 'Aktualizacja automatyczna aktywna. W ukrytej karcie jest wstrzymywana.'
              : 'Aktualizacja automatyczna wstrzymana.'}
        </p>
      </Panel>
      <ErrorNotice error={filterError ?? resource.error} />
      {resource.pending && !data && <Loading />}
      {!!resource.error && data && (
        <p className="notice">
          Wyświetlane dane są nieaktualne. Poniżej pozostaje ostatni poprawnie pobrany wynik.
        </p>
      )}
      {data && (
        <>
          <div className="dashboard-stamp">
            <Badge>{data.scope.mode}</Badge>
            <span>
              {time(data.scope.from)} — {time(data.scope.to)}
            </span>
            <span>
              Odczyt: {time(data.generated_at)}
              {resource.pending ? ' · Odświeżanie…' : ''}
            </span>
          </div>
          {data.scope.mode === 'replay' && (
            <p className="muted">
              Zestaw: {data.scope.dataset_id} · Przebieg: {data.scope.run_id}
            </p>
          )}
          <div className="metrics">
            <Metric
              label="Zdarzenia · 24 h"
              value={data.counts.events_24h}
              note="Znormalizowane, według czasu zdarzenia"
            />
            <Metric
              label="Alerty · 24 h"
              value={data.counts.alerts_24h}
              note={
                data.scope.include_false_positives
                  ? 'Zawiera fałszywe alarmy'
                  : `Pominięto fałszywe alarmy: ${data.counts.excluded_false_positives}`
              }
            />
            <Metric
              label="Otwarte incydenty"
              value={data.counts.open_incidents}
              note="Bieżący stan, cały okres w wybranym trybie"
            />
            <Metric
              label="Krytyczne incydenty"
              value={data.counts.critical_incidents}
              note="Otwarte sprawy o wadze krytycznej"
            />
          </div>
          <p className="muted">
            Przyjęto {data.counts.received_24h} nowych logów w tym oknie według czasu odbioru.
            Otwarte sprawy obejmują statusy: nowy, w analizie i opanowany.
          </p>
          <div className="dashboard-shortcuts">
            <button onClick={onEvents}>Otwórz moduł zdarzeń</button>
            <button onClick={onAlerts}>Otwórz moduł alertów</button>
            <button onClick={onIncidents}>Otwórz moduł incydentów</button>
          </div>
          {data.index_status.entities_partial && (
            <p className="notice" role="status">
              Rankingi encji są niepełne: {data.index_status.pending_events} zdarzeń oczekuje na
              indeks. Licznik wszystkich zdarzeń obejmuje również te rekordy.
            </p>
          )}
          <Ingestion data={data.ingestion} />
          <div className="dashboard-grid">
            <Distribution title="Waga alertów" rows={data.severity} />
            <Distribution title="Rozkład ryzyka alertów" rows={data.risk} />
            <Ranking title="Najaktywniejsi użytkownicy" rows={data.top.users} />
            <Ranking title="Najaktywniejsze hosty" rows={data.top.hosts} />
            <Ranking title="Źródłowe adresy IP" rows={data.top.source_ips} />
            <Ranking title="Docelowe adresy IP" rows={data.top.destination_ips} />
            <Panel title="Najczęstsze reguły detekcji">
              {data.rules.length ? (
                <ol className="dashboard-ranking">
                  {data.rules.map((rule) => (
                    <li key={`${rule.id}:${rule.version}`}>
                      <span>
                        <strong>{rule.label}</strong>
                        <small>
                          {rule.id} · wersja {rule.version}
                        </small>
                      </span>
                      <span>
                        {rule.count} <small>alertów</small>
                      </span>
                    </li>
                  ))}
                </ol>
              ) : (
                <Empty title="Brak dopasowań reguł" />
              )}
            </Panel>
            <Panel title="Taktyki MITRE ATT&CK">
              {data.tactics.length ? (
                <ul className="dashboard-ranking">
                  {data.tactics.map((tactic) => (
                    <li key={tactic.id}>
                      <span>
                        <strong>{tactic.label}</strong>
                        <small>{tactic.id}</small>
                      </span>
                      <span>
                        {tactic.count} <small>alertów</small>
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty title="Brak mapowań taktyk" />
              )}
              <p className="muted">
                Mapowania: {data.mitre_status.mapped_alerts} alertów. Bez mapowania:{' '}
                {data.mitre_status.unmapped_alerts}. Brak zapisu:{' '}
                {data.mitre_status.missing_snapshots}. Inny katalog:{' '}
                {data.mitre_status.other_catalogue_alerts}.
              </p>
              <p className="muted">
                Jeden alert może wskazywać kilka taktyk. Mapowanie jest wskazówką do analizy, a nie
                potwierdzeniem ataku.
              </p>
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
