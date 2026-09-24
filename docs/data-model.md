# Model danych i normalizacja

Status: kontrakt projektowy PHASE 0. Modele Pydantic, tabele i parsery będą
implementowane w PHASE 1–3. Nazwy pól nie są deklaracją pełnej zgodności ECS/OTel.

## RawEvent

Envelope: `source_type`, `raw_event` (string lub JSON object), opcjonalne
`source_event_id`, `timestamp` i `timezone`. Konfiguracja źródła oraz credential
określają `source_id`, dozwolone typy parserów, strefę i `dataset_id`; klient nie
ustawia zaufanych pól `received_at`, risk, role ani parser_version.

`POST /events` przyjmuje jeden envelope albo obiekt `events` z listą. Maksymalnie
500 rekordów, 1 MiB body, 64 KiB raw_event i 16 poziomów JSON (wartości startowe
do testów). Walidacja envelope odrzuca cały batch; błędy zawartości pojedynczego
logu po `202` trafiają do kwarantanny i statusu batcha, nie znikają bez śladu.

## NormalizedSecurityEvent v1

| Pole | Typ / semantyka |
| --- | --- |
| `schema_version`, `parser_version` | Jawne wersje utrwalane przy normalizacji |
| `event_id`, `source_event_id` | UUID serwera; nullable oryginalny identyfikator źródła |
| `source_id`, `dataset_id`, `mode`, `run_id` | Zaufany scope źródła i izolacja live/demo/replay; stały namespace run dla live |
| `timestamp` | RFC3339 UTC z offsetem wymaganym przy dostawie JSON |
| `received_at`, `processed_at` | Czasy serwera, odrębne od czasu zdarzenia |
| `source` | Obiekt `name`, `type`, `ip`, `port` |
| `destination` | Obiekt nullable `ip`, `port` |
| `host` | `id`, `name`, `os`; hostname nie jest globalnym ID hosta |
| `user` | Actor: `id`, `name`, `realm`; `target.id/name/realm` dla konta zmienianego, osobny target SID |
| `session` | Nullable `id`, `provider`, `host_id`, `boot_id`; źródłowy logon ID z zakresem, nie globalny string |
| `process` | Nullable `entity_id`, `parent_entity_id`, `name`, `executable`, `command_line`, `pid`, `parent_pid`, `hash`; PID sam nie jest trwałą tożsamością |
| `event` | `category`, `type`, `action`, `outcome`, `severity`, `code` |
| `network`, `http`, `file` | Opcjonalne typowane dane protokołu, HTTP i pliku |
| `raw_event`, `raw_sha256` | Oryginalna treść ograniczona rozmiarem; checksum artefaktu |
| `extensions` | Ograniczone dodatkowe pola parsera; brak wykonywalnych wartości |
| `quality` | Ostrzeżenia i pochodzenie czasu/pól, np. inferred_year |

Klucz źródłowego eventu zawiera source/dataset/mode/run i source_event_id; conflict
payloadu jest błędem. Replay archiwum przechowuje membership oryginalnych event IDs
w manifeście. Nazwa user bez realm i hostname bez wiarygodnego mapowania nie tworzą
silnej krawędzi korelacji. Adapter musi podać provenance session/process entity IDs;
brak pola nie może zostać zastąpiony wymyśloną tożsamością.

`event.outcome`: `success`, `failure`, `unknown`. `event.severity`: znormalizowana
klasa `informational`, `low`, `medium`, `high`, `critical`, niezależna od risk.
Nieobecne IP/pole procesu = null, nie pusty string/0. IP walidowane jako IPv4/IPv6,
porty 0–65535, strefy jako nazwy IANA w konfiguracji. Nie wyprowadzamy privilege
użytkownika z przypadkowej nazwy konta; to wersjonowane wzbogacenie.

Alias query `result = "failed"` mapuje na `event.outcome = "failure"`.
Pozostałe aliasy: `username → user.name`, `hostname → host.name`,
`source_ip → source.ip`, `destination_ip → destination.ip`,
`source_port → source.port`, `destination_port → destination.port`,
`process_name → process.name`, `command_line → process.command_line`,
`action → event.action`, `source_type → source.type`, `severity → event.severity`.
`alert.severity` jest odrębnym filtrem adnotacji po detekcji.
Publiczny normalized JSON pozostaje zagnieżdżony; aliasy są tylko wejściem query.

MITRE i rule ID są **adnotacjami po detekcji**, a nie faktami rzekomo pochodzącymi
z surowego logu. Event Explorer filtruje je przez projekcję powiązań event-alert
z rule version i mapping version. Jeden event może wspierać wiele alertów.

## Parsery i niejednoznaczność

| Źródło | Kontrakt i testy |
| --- | --- |
| Linux auth.log / SSH | Syslog prefix, host, user, IP, accepted/failed; fixtures IPv6 i invalid user |
| sudo/su | Actor, target user, command, outcome; zwykłe sudo nie dowodzi exploit |
| Windows auth | Strukturalny JSON z eksportu Windows events; m.in. 4624/4625 i identyfikatory kont |
| Windows process | JSON 4688/Sysmon 1, executable/command line/parent, brak zgadywania nieobecnego pola |
| Windows account/group | 4720 i 4732 z target SID; sekwencja wiąże target, a nie wyłącznie actor |
| Firewall | Udokumentowany key=value adapter, action/protocol/IP/port; brak obietnicy wszystkich vendorów |
| nginx | Udokumentowany combined access log albo JSON; HTTP status nie jest automatycznie auth failure |
| Generic JSON | Walidowana mapa pola wejściowego do schema v1, nie dowolny schemat bez kontraktu |

XML/EVTX i bezpośredni Windows Event Collector nie są parserami MVP: collector
ma eksportować JSON. Linux syslog bez roku używa jawnej konfiguracji source timezone
i najbliższego poprawnego roku względem received_at; przekroczenie granic lub
niejednoznaczność DST wymaga quality flag/kwarantanny, nie cichego przesunięcia UTC.
Testy obejmą zmianę roku i czasu, Unicode, brakujące pola i zbyt długie inputy.

## Model operacyjny PostgreSQL

| Agregat | Planowane encje / constraints |
| --- | --- |
| Identity | users, roles/permissions, refresh_sessions, source_credentials; hashes zamiast sekretów |
| Ingest | sources, batches, inbox_events, outbox, processing_leases, checkpoints, dedupe_registry |
| Detection | rules, immutable rule_versions, detection_state, matches, alert_revisions, alert_events |
| Incidents | incidents z version, incident_alerts, notes, evidence_snapshots, incident_iocs, timeline |
| Context | assets, identities, iocs, enrichment_versions; wejście do risk i match IOC |
| Hunting | saved_queries, bookmarks, investigations, investigation_events, draft_rules |
| SOAR | playbooks, versions, runs, steps, attempts, notifications; unikalny execution key |
| Governance | audit_log append-only, replay_runs, risk_policy_versions, mitre_catalog_versions |

Relacje wewnątrz PostgreSQL mają FK; referencje do eventów w ClickHouse nie mogą mieć
międzybazowego FK, dlatego alert/case utrwala bounded evidence snapshot + checksum.
Unikalność source_event_id i fingerprintów jest wymuszana w bazie, nie tylko Pythonem.
Indeksy operational time/status/owner i entity key powstaną z rzeczywistymi zapytaniami.

## ClickHouse

Plan: partycja miesięczna po niezmiennym `timestamp`; sortowanie
`(dataset_id, source_id, toDate(timestamp), timestamp, event_id)`.
Retry zachowuje cały klucz. Parametryzowane wyszukiwanie zawsze wymaga zakresu czasu;
projekcja adnotacji ma własny checkpoint. Brak natywnych FK do PostgreSQL oznacza
okresowy test spójności i jawny status niedostępnej projekcji. Ostateczne DDL i
indeksy wymagają benchmarku przed akceptacją fazy implementacyjnej.
