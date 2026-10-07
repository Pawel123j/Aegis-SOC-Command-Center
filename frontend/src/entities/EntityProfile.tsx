import { useEffect, useRef, useState } from 'react';
import { AlertDialog } from '../Alerts';
import { Badge, Empty, ErrorNotice, JsonView, Loading, Metric, Panel } from '../components';
import { IncidentDetails } from '../incidents/IncidentDetails';
import { incidentStatuses } from '../incidents/labels';
import { RiskScore } from '../risk/RiskScore';
import type { Alert, Me, SecurityEvent } from '../types';
import { UebaProfile } from '../ueba/UebaProfile';
import { statusName, time } from '../utilities';
import { EntityTable, IndexNotice, ScopeNotice } from './presentation';
import { entityKinds } from './labels';
import type {
  EntityAlert,
  EntityDetail,
  EntityIncident,
  EntityPage,
  EntitySummary,
  EventActivity,
} from './types';
import { useEntityResource } from './useEntityResource';

export function EntityProfile({
  id,
  params,
  user,
  onBack,
  onSelect,
  onEvent,
  onCreateIncident,
}: {
  id: string;
  params: string;
  user: Me;
  onBack: () => void;
  onSelect: (id: string) => void;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
}) {
  const resource = useEntityResource<EntityDetail>(`/entities/${encodeURIComponent(id)}?${params}`);
  return (
    <div className="entity-profile">
      <div className="intro">
        <button className="quiet" onClick={onBack}>
          ← Lista profili
        </button>
        <button disabled={resource.pending} onClick={() => void resource.reload()}>
          Odśwież profil
        </button>
      </div>
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data && (
        <>
          <ProfileSummary detail={resource.data} />
          <UebaProfile
            id={id}
            kind={resource.data.kind}
            params={params}
            user={user}
            onEvent={onEvent}
          />
          <EntityCollections
            id={id}
            params={params}
            user={user}
            onSelect={onSelect}
            onEvent={onEvent}
            onCreateIncident={onCreateIncident}
            onChanged={() => void resource.reload()}
          />
        </>
      )}
    </div>
  );
}

function ProfileSummary({ detail }: { detail: EntityDetail }) {
  const { counts, risk, mitre } = detail;
  return (
    <>
      <div className="intro">
        <div>
          <span className="eyebrow">{entityKinds[detail.kind]} · DANE OBSERWOWANE</span>
          <h2 className="entity-label">{detail.label}</h2>
        </div>
        <RiskScore score={risk.score} level={risk.level} />
      </div>
      <ScopeNotice scope={detail.scope} />
      <IndexNotice status={detail.index_status} />
      <div className="metrics">
        <Metric
          label="Zdarzenia w zakresie"
          value={counts.events}
          note="Różne zdarzenia, niezależnie od liczby ról"
        />
        <Metric
          label="Zdarzenia z nieudanym logowaniem"
          value={counts.failed_logins}
          note="Powiązane zdarzenia niezależnie od roli encji; nie liczba jej własnych prób logowania."
        />
        <Metric
          label="Powiązane alerty"
          value={counts.alerts}
          note={`W tym ${counts.false_positive_alerts} fałszywych alarmów`}
        />
        <Metric
          label="Powiązane incydenty"
          value={counts.incidents}
          note="Z aktywnie dołączonym pasującym alertem"
        />
      </div>
      <div className="entity-grid">
        <Panel title="Tożsamość z logów">
          <dl className="facts">
            <dt>Pierwsza obserwacja w zakresie</dt>
            <dd>{time(detail.first_seen)}</dd>
            <dt>Ostatnia obserwacja w zakresie</dt>
            <dd>{time(detail.last_seen)}</dd>
            <dt>Podstawa łączenia obserwacji</dt>
            <dd className="mono">{detail.identity_basis}</dd>
            <dt>Wersja zasad tożsamości</dt>
            <dd className="mono">{detail.identity_policy}</dd>
            <dt>Source ID</dt>
            <dd className="mono">{detail.source_id ?? 'Adres sieciowy niezależny od źródła'}</dd>
            <dt>Obserwacje ról</dt>
            <dd>{counts.observations}</dd>
            <dt>Powiązane hosty</dt>
            <dd>{detail.related_host_count}</dd>
          </dl>
          <p className="muted">
            Obserwowane nazwy nie stanowią potwierdzonej ewidencji zasobów. Różne źródła lub słabe
            identyfikatory mogą tworzyć oddzielne profile. Sam PID nie pozwala połączyć procesów z
            różnych zdarzeń; profil takiego procesu dotyczy jednego zdarzenia.
          </p>
          <div className="entity-roles">
            {Object.entries(detail.roles).map(([role, count]) => (
              <Badge key={role}>
                {role}: {count}
              </Badge>
            ))}
          </div>
          <details>
            <summary>Kanoniczne pola tożsamości</summary>
            <JsonView value={detail.canonical_identity} />
          </details>
        </Panel>
        <Panel title="Ryzyko powiązanych alertów">
          <RiskScore score={risk.score} level={risk.level} />
          <p>
            Najwyższa bieżąca ocena powiązanego alertu w wybranym zakresie. To projekcja istniejącej
            oceny; profil nie ma odrębnego obliczenia ryzyka.
          </p>
          <dl className="facts">
            <dt>Alerty kwalifikujące się do oceny</dt>
            <dd>{risk.eligible_alerts}</dd>
            <dt>Alerty z bieżącą oceną</dt>
            <dd>{risk.assessed_alerts}</dd>
            <dt>Pominięte fałszywe alarmy</dt>
            <dd>{risk.excluded_false_positive_alerts}</dd>
            <dt>Alert z najwyższą oceną</dt>
            <dd className="mono">{risk.alert_id ?? '—'}</dd>
            <dt>Wersja polityki</dt>
            <dd>{risk.policy_version ?? '—'}</dd>
          </dl>
          {risk.score === null && (
            <p className="notice">
              Brak bieżącej oceny kwalifikujących się alertów. Brak oceny nie oznacza ryzyka równego
              zero.
            </p>
          )}
          <details>
            <summary>Uzasadnienie zachowanej oceny</summary>
            <dl className="facts">
              <dt>Calculation ID</dt>
              <dd className="mono">{risk.calculation_id ?? '—'}</dd>
              <dt>Powód projekcji</dt>
              <dd>{risk.reason}</dd>
            </dl>
            <JsonView value={risk.explanation} />
          </details>
        </Panel>
      </div>
      <Panel title="Możliwe powiązania MITRE ATT&CK">
        <p>
          Mapowania zachowane przy kwalifikujących się alertach wskazują możliwe zachowania. Nie
          potwierdzają udanego ataku ani zamiaru. Fałszywe alarmy są pomijane w ryzyku i mapowaniu,
          pozostają w historii aktywności.
        </p>
        {mitre.techniques.length ? (
          <ul className="entity-techniques">
            {mitre.techniques.map((technique) => (
              <li key={technique.id}>
                <strong>
                  {technique.name} · {technique.id}
                </strong>
                <span>
                  Powiązane alerty: {technique.alert_count} · katalog {technique.catalogue_version}
                </span>
                {trustedTechnique(technique.url) && (
                  <a
                    href={trustedTechnique(technique.url)!}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Opis techniki {technique.id}
                  </a>
                )}
                <details>
                  <summary>Pochodzenie mapowania {technique.id}</summary>
                  <span className="mono">SHA-256 katalogu: {technique.catalogue_hash}</span>
                </details>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">
            Brak mapowania do bieżącego katalogu. Nie potwierdza to braku zagrożeń.
          </p>
        )}
        <dl className="facts">
          <dt>Alerty mapowane</dt>
          <dd>{mitre.mapped_alerts}</dd>
          <dt>Alerty bez mapowania</dt>
          <dd>{mitre.unmapped_alerts}</dd>
          <dt>Starsze alerty bez zachowanego mapowania</dt>
          <dd>{mitre.legacy_alerts}</dd>
          <dt>Alerty z innym katalogiem</dt>
          <dd>{mitre.other_catalogue_alerts}</dd>
          <dt>Pominięte fałszywe alarmy</dt>
          <dd>{mitre.excluded_false_positive_alerts}</dd>
        </dl>
      </Panel>
    </>
  );
}
function trustedTechnique(value: string) {
  try {
    const url = new URL(value);
    if (
      url.protocol === 'https:' &&
      url.hostname === 'attack.mitre.org' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      /^\/techniques\/T\d{4}(\/\d{3})?\/?$/.test(url.pathname)
    )
      return url.href;
  } catch {
    /* Untrusted source metadata remains text. */
  }
  return null;
}

type Collection = 'events' | 'alerts' | 'incidents' | 'related';
const collectionNames: Record<Collection, string> = {
  events: 'Historia aktywności',
  alerts: 'Alerty profilu',
  incidents: 'Incydenty profilu',
  related: 'Hosty w tych samych zdarzeniach',
};
function EntityCollections({
  id,
  params,
  user,
  onSelect,
  onEvent,
  onCreateIncident,
  onChanged,
}: {
  id: string;
  params: string;
  user: Me;
  onSelect: (id: string) => void;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
  onChanged: () => void;
}) {
  const [tab, setTab] = useState<Collection>('events');
  return (
    <>
      <div className="entity-tabs" role="group" aria-label="Dane profilu">
        {(Object.keys(collectionNames) as Collection[]).map((kind) => (
          <button key={kind} aria-pressed={tab === kind} onClick={() => setTab(kind)}>
            {collectionNames[kind]}
          </button>
        ))}
      </div>
      <ProfileCollection
        key={`${tab}/${params}`}
        id={id}
        params={params}
        tab={tab}
        user={user}
        onSelect={onSelect}
        onEvent={onEvent}
        onCreateIncident={onCreateIncident}
        onChanged={onChanged}
      />
    </>
  );
}
function ProfileCollection({
  id,
  params,
  tab,
  user,
  onSelect,
  onEvent,
  onCreateIncident,
  onChanged,
}: {
  id: string;
  params: string;
  tab: Collection;
  user: Me;
  onSelect: (id: string) => void;
  onEvent: (event: SecurityEvent) => void;
  onCreateIncident: (alert: Alert) => void;
  onChanged: () => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [previous, setPrevious] = useState<(string | null)[]>([]);
  const [eventId, setEventId] = useState<string | null>(null);
  const [alertId, setAlertId] = useState<string | null>(null);
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const query = new URLSearchParams(params);
  if (cursor) query.set('cursor', cursor);
  if (tab === 'related') query.set('kind', 'host');
  const resource = useEntityResource<
    EntityPage<EventActivity | EntityAlert | EntityIncident | EntitySummary>
  >(`/entities/${encodeURIComponent(id)}/${tab}?${query}`);
  const event = useEntityResource<SecurityEvent>(
    eventId ? `/events/${encodeURIComponent(eventId)}` : null,
  );
  const deliveredEvent = useRef<SecurityEvent | null>(null);
  useEffect(() => {
    if (event.data && event.data !== deliveredEvent.current) {
      deliveredEvent.current = event.data;
      onEvent(event.data);
    }
  }, [event.data, onEvent]);
  function openEvent(nextId: string) {
    if (eventId !== nextId) setEventId(nextId);
    else if (event.data) onEvent(event.data);
    else if (!event.pending) void event.reload();
  }
  if (incidentId)
    return (
      <IncidentDetails
        key={incidentId}
        id={incidentId}
        user={user}
        onBack={() => setIncidentId(null)}
        onEvent={onEvent}
      />
    );
  return (
    <Panel
      title={collectionNames[tab]}
      aside={
        <button disabled={resource.pending} onClick={() => void resource.reload()}>
          Odśwież powiązania
        </button>
      }
    >
      <ErrorNotice error={resource.error} />
      <ErrorNotice error={event.error} />
      {Boolean(event.error) && (
        <p className="muted">
          Profil korzysta z zachowanych obserwacji. Otwarcie tego zdarzenia wymaga dostępnego
          archiwum; spróbuj ponownie przyciskiem „Otwórz zdarzenie”.
        </p>
      )}
      {(resource.pending || event.pending) && <Loading />}
      {resource.data && (
        <>
          <IndexNotice status={resource.data.index_status} />
          <p className="muted">
            Rekordy w zakresie: {resource.data.total}. Rozwiązane alerty i zamknięte incydenty
            pozostają w historii; odpięte powiązania incydentów są pomijane.
          </p>
          {resource.data.items.length ? (
            tab === 'events' ? (
              <ActivityTable items={resource.data.items as EventActivity[]} onEvent={openEvent} />
            ) : tab === 'alerts' ? (
              <AlertTable items={resource.data.items as EntityAlert[]} onSelect={setAlertId} />
            ) : tab === 'incidents' ? (
              <IncidentTable
                items={resource.data.items as EntityIncident[]}
                onSelect={setIncidentId}
              />
            ) : (
              <EntityTable items={resource.data.items as EntitySummary[]} onSelect={onSelect} />
            )
          ) : (
            <Empty
              title={
                resource.data.index_status.complete
                  ? 'Brak powiązań w zakresie'
                  : 'Powiązania oczekują na indeksowanie'
              }
            >
              {resource.data.index_status.complete
                ? 'Zmień zakres obserwacji lub sprawdź inny profil.'
                : 'Wynik jest niepełny; uzupełnij indeks i odśwież widok.'}
            </Empty>
          )}
          <div className="pagination">
            <span>Strona {previous.length + 1}</span>
            <div>
              <button
                disabled={!previous.length || resource.pending}
                onClick={() => {
                  setCursor(previous.at(-1) ?? null);
                  setPrevious((items) => items.slice(0, -1));
                }}
              >
                Poprzednie powiązania
              </button>
              <button
                disabled={!resource.data.next_cursor || resource.pending}
                onClick={() => {
                  setPrevious((items) => [...items, cursor]);
                  setCursor(resource.data!.next_cursor);
                }}
              >
                Następne powiązania
              </button>
            </div>
          </div>
        </>
      )}
      {alertId && (
        <AlertDialog
          key={alertId}
          id={alertId}
          user={user}
          onClose={() => setAlertId(null)}
          onEvent={onEvent}
          onCreateIncident={onCreateIncident}
          onChange={() => {
            void resource.reload();
            onChanged();
          }}
        />
      )}
    </Panel>
  );
}
function ActivityTable({
  items,
  onEvent,
}: {
  items: EventActivity[];
  onEvent: (id: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table aria-label="Aktywność profilu">
        <thead>
          <tr>
            <th>Czas zdarzenia</th>
            <th>Źródło / akcja</th>
            <th>Wynik</th>
            <th>Role encji</th>
            <th>Dowód</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.event_id}>
              <td>{time(item.timestamp)}</td>
              <td>
                <strong>{item.source_name}</strong>
                <small>
                  {item.source_type} · {item.event_category ?? '—'} · {item.event_action ?? '—'}
                </small>
              </td>
              <td>
                <Badge tone={item.event_outcome ?? undefined}>
                  {statusName[item.event_outcome ?? ''] ?? item.event_outcome ?? '—'}
                </Badge>
              </td>
              <td>{item.roles.join(', ')}</td>
              <td>
                <button onClick={() => onEvent(item.event_id)}>Otwórz zdarzenie</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function AlertTable({ items, onSelect }: { items: EntityAlert[]; onSelect: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table aria-label="Alerty powiązane z profilem">
        <thead>
          <tr>
            <th>Alert / reguła</th>
            <th>Status / waga</th>
            <th>Ryzyko alertu</th>
            <th>Dowody encji</th>
            <th>Czas zdarzenia / końca sekwencji</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <th scope="row">
                <button className="inline-link" onClick={() => onSelect(item.id)}>
                  {item.title}
                </button>
                <small>{item.rule_id}</small>
              </th>
              <td>
                <Badge>{statusName[item.status] ?? item.status}</Badge>
                <small>
                  <Badge tone={item.severity}>{item.severity}</Badge>
                </small>
                {item.status === 'false_positive' && (
                  <small>Poza oceną ryzyka i MITRE profilu</small>
                )}
              </td>
              <td>
                <RiskScore score={item.risk_score} level={item.risk_level} />
              </td>
              <td>
                {item.matched_entity_event_count} z {item.contributing_event_count} zdarzeń alertu
              </td>
              <td>{time(item.event_timestamp)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function IncidentTable({
  items,
  onSelect,
}: {
  items: EntityIncident[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table aria-label="Incydenty powiązane z profilem">
        <thead>
          <tr>
            <th>Incydent</th>
            <th>Status / waga</th>
            <th>Ryzyko incydentu</th>
            <th>Powiązane alerty encji</th>
            <th>Utworzono</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <th scope="row">
                <button className="inline-link" onClick={() => onSelect(item.id)}>
                  {item.title}
                </button>
              </th>
              <td>
                <Badge>
                  {incidentStatuses[item.status as keyof typeof incidentStatuses] ?? item.status}
                </Badge>
                <small>
                  <Badge tone={item.severity}>{item.severity}</Badge>
                </small>
              </td>
              <td>
                <RiskScore score={item.risk_score} level={item.risk_level} />
              </td>
              <td>{item.matched_alert_count}</td>
              <td>{time(item.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
