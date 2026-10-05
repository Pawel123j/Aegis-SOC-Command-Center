# Model danych i normalizacja

Status 2026-10-05: PHASE 1–3, detekcje/alerty i incydenty,
korelacja, ryzyko, MITRE, Sigma oraz profile encji są zaimplementowane.
Etap 7 dodaje lokalne IOC i ledger dopasowań; końcowa regresja i migracje PASS.
Kontrakt działającej normalizacji opisuje
[normalization](normalization.md), a spraw [incidents](incidents.md).
Profile obserwowanych encji Etapu 6 opisuje [entities](entities.md);
dopasowania i rewizje IOC opisuje [intelligence](intelligence.md);
dalszy inwentarz i wcześniejsze szkice oznaczono jako projekt poniżej.
Nazwy pól nie są deklaracją pełnej zgodności ECS/OTel.

## RawEvent

Envelope: `source_type`, `raw_event` (string lub JSON object), opcjonalne
`source_event_id`, `timestamp` i `timezone`. Konfiguracja źródła oraz credential
określają `source_id`, dozwolone typy parserów, strefę i `dataset_id`; klient nie
ustawia zaufanych pól `received_at`, risk, role ani parser_version.

`POST /events` przyjmuje jeden envelope albo obiekt `events` z listą. Maksymalnie
500 rekordów, 1 MiB body, 64 KiB raw_event i 16 poziomów JSON (egzekwowane limity
startowe, bez deklaracji przepustowości). Walidacja envelope odrzuca cały batch; błędy zawartości pojedynczego
logu po `202` trafiają do kwarantanny i statusu batcha, nie znikają bez śladu.

W PHASE 2 `raw_events.envelope` to kanoniczny, zwalidowany envelope JSONB.
SHA-256 i `payload_bytes` odnoszą się do jego kanonicznego kodowania UTF-8:
posortowanych kluczy, zwartego JSON, liczb całkowitych znormalizowanych z
równoważnych floatów i timestampu envelope sprowadzonego do UTC. Nie jest to
hash bajtów całego oryginalnego HTTP body. Tekst `raw_event` zachowuje treść;
obiekt JSON nie zachowuje formatowania i kolejności kluczy nadawcy.
Nieznane pola envelope są odrzucane. Timestamp envelope wymaga RFC3339 z czasem
i offsetem, timezone jest nazwą IANA. `received_at` pochodzi z serwera.

## Tabele ingestion — PHASE 2

Migracja `0002_ingestion` tworzy poniższe tabele. Ich relacje mają FK w PostgreSQL.

| Tabela | Dane i ograniczenia |
| --- | --- |
| `ingestion_sources` | Unikalna nazwa, UUID source/dataset, mode/run, dozwolone source_types, timezone, enabled, version; publiczne tworzenie wyłącznie live |
| `source_credentials` | FK źródła, unikalny SHA-256 tokena, scopes, daty utworzenia/wygaśnięcia/odwołania; sekret nie jest przechowywany |
| `ingestion_batches` | Scope + unikalny idempotency_key, kanoniczny hash listy envelope, request_id, accepted/created/duplicate counts |
| `raw_events` | Niezmienny envelope, hash/rozmiar, scope, received_at; unikalny source_event_id w source/dataset/mode/run, nullable ID nie deduplikuje |
| `batch_events` | PK batch_id + position (0–499), FK event_id; zachowuje kolejność i wielokrotne odwołania do jednego raw eventu |
| `outbox_jobs` | Jeden wiersz na event; state, generation, próby dispatch/processing, terminy oraz oddzielne tokeny i terminy dzierżaw relay/workera |
| `ingest_capacity` | Singleton id=1; event_count, byte_count, receipt_count; blokada serializuje przyjęcie i ponowne dopuszczenie retry |

Admission zapisuje nowy batch, membership, nowe raw/jobs, liczniki i audyt w jednej
transakcji. Sama odpowiedź `202` nie wymaga publikacji do Celery. Deduplikacja
nie tworzy nowego joba dla istniejącego eventu. Status batcha odczytuje aktualne
zadania przez membership; nie jest oddzielnie aktualizowaną kopią licznika.

Runtime ma SELECT/INSERT do raw, batch i membership, bez UPDATE/DELETE.
Stan zadania może zmieniać, ale nie usuwać. Jedyny wiersz capacity tworzy migracja;
runtime ma SELECT/UPDATE, bez INSERT/DELETE. Nie ma automatycznej retencji ani TTL.
`staged` i `quarantined` pozostają w limitach przechowywania. `receipt_count`
liczy wszystkie pozycje nowych batchy, również duplikaty; `byte_count` jest
logicznym rozmiarem envelope, a nie zużyciem dysku PostgreSQL.
Opis operacyjny i wartości limitów: [PHASE 2 operations](phase2-operations.md).

Worker przechodzi `pending → processing → staged` lub do `quarantined`;
błąd przejściowy może wrócić do `pending`. Token dzierżawy oraz generation
warunkują zapis wyniku, więc spóźniona próba nie nadpisuje nowszej generacji.
Manualny retry zwiększa generation i resetuje stan/próby, zachowując to samo raw.
To koniec etapu worker raw. Osobny processor PHASE 3 tworzy
`NormalizedSecurityEvent` w PostgreSQL i projektuje go do ClickHouse;
osobny detector ocenia niezmienny snapshot.

## NormalizedSecurityEvent v1 — pierwotny szkic i dalsze rozszerzenia

Poniższa tabela zachowuje projekt koncepcyjny. Dokładne aktualne nazwy,
limity, parser/schema version i kontrakt API wynikają z
[wdrożonej normalizacji](normalization.md) i modeli Pydantic.

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

## Parsery i niejednoznaczność — PHASE 3

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

## Dalszy model operacyjny PostgreSQL — projekt

Aktualny przyrost incydentów (`0005_incidents`) dodaje `incidents`,
`incident_alerts`, `incident_notes`, `incident_timeline` i
`incident_create_receipts`. Dowód jest zachowanym snapshotem alertu
PostgreSQL. Powiązania alertów mają active/detached zamiast DELETE,
notes/timeline/receipts pozostają append-only. Scope live/replay oraz
limity opisuje [kontrakt incydentów](incidents.md).
Etap 2 rozszerza immutable alert o `event_snapshots`: listę wrapperów
`{event_id, event_sha256, event_snapshot}`. Dotychczasowy `event_snapshot`
pozostaje dowodem kotwicy. Trwałe zadania i watermark korelacji są stanem
PostgreSQL; replay zapisuje zamknięty manifest, identyfikatory i hashe wejścia.
Agregacja sprawy używa czasu i encji ze wszystkich dowodów aktywnych alertów.
Zakres i dokładne modele: [raport korelacji](validation-correlation.md).
Etap 3 dodaje `risk_calculations`: niezmienne wejście, wyjaśnienie, wersję/hash
polityki, wynik i poprzednie obliczenie dla alertu lub incydentu.
Nullable `risk_level` i `risk_calculation_id` uzupełniają istniejący score.
Projekcja bieżącego wyniku nie edytuje oryginalnego dowodu ani historii
i nie zmienia wersji decyzji analityka. Runtime odczytuje i dopisuje
obliczenia, a bieżący wynik aktualizuje ograniczona funkcja PostgreSQL.
Wagi i deduplikację opisuje [Risk Engine](risk-engine.md).
Etap 4 dodaje `alert_mitre_snapshots` (PK/FK alert_id, status, wersje/hash
katalogu i polityki, input/snapshot SHA-256, bounded JSON document) oraz
`alert_mitre_mappings` (PK alert_id/technique_id/tactic_id, FK do snapshotu).
Trigger INSERT sprawdza zgodność skojarzenia z dokumentem. Runtime ma
SELECT/INSERT; downgrade odmawia zniszczenia istniejącej historii.
Indeksy mode/event_timestamp i mode/dataset/run/event_timestamp służą coverage.
Oryginalne snapshoty reguł pozostają bez zmian, a legacy nie jest backfillowane.
Nazwy w szczegółach sprawy pochodzą z aktywnych alertów bez false positives,
z deduplikacją catalogue_hash/technique_id. Stare pole mitre_techniques
pozostaje kompatybilną adnotacją; nowy panel używa jawnej projekcji.
[Dokładne zasady](mitre.md).
Etap 5 dodaje `sigma_rules` (UUID, jednoznaczny detection_id, autor/data)
oraz `sigma_rule_versions` (UUID, FK rule_id, unikalna revision 1–20,
bounded YAML, source/compiled SHA-256, JSON AST, evaluator i autor/data).
Obie tabele są append-only dla runtime. Kontrolowana funkcja SQL tworzy
wyłączone wdrożenie albo wybiera kolejną utrwaloną rewizję; istniejące
granty nie pozwalają runtime dowolnie INSERT/UPDATE wersji RuleDeployment.
Downgrade odmawia usunięcia historii Sigma. Snapshot alertu wskazuje
oryginalną rewizję i deployment_version; wybór nowej wersji jej nie zmienia.
RiskInput v3 dodaje severity_baselines poza kontrolowanymi Signal.family;
historyczne obliczenia v2 pozostają niezmienne. [Sigma](sigma.md).

## Indeks obserwowanych encji — Etap 6

Migracja `0010_entities` wprowadza pięć append-only tabel. `entity_identities`
przechowuje deterministyczny UUID, hash i kanoniczny klucz z wersją polityki,
rodzajem, zakresem oraz podstawą identyfikacji. `entity_index_receipts`
wiąże normalized event/hash z liczbą obserwacji, także zerową.
`entity_observations` ma PK entity/event/role, czas zdarzenia, hash dowodu
i ograniczone observed attributes do wyboru najnowszej etykiety profilu.
`entity_alert_receipts` deklaruje liczbę contributed events;
`alert_event_references` ma PK alert/event i hash oryginalnego snapshotu.

FK i triggery sprawdzają scope, źródło, czas, hash i kompletność receipt przy
commit. Indeksy wspierają odczyt entity/time/event i event/alert.
Runtime ma SELECT/INSERT; UPDATE/DELETE/TRUNCATE są blokowane, a niepusty
downgrade odmawia utraty historii. Autor nowych INSERT nadal jest zaufany.
Nowa normalizacja i publikacja alertu indeksują swoje dowody atomowo.
Starszy zakres uzupełnia ograniczony, audytowany backfill, bez zmiany źródła.
[Zasady profilu](entities.md), [ADR 0012](adr/0012-observed-entity-profiles.md).

## Lokalny katalog IOC i ledger dopasowań — Etap 7

Migracja `0011_intelligence` jest head nowych źródeł. Dodaje cztery tabele:

| Tabela | Dane i ograniczenia |
| --- | --- |
| `ioc_identities` | UUID, niezmienne kind/canonical_value/normalization_version i autor/data; unikalny typ + wartość; pointer i wersja wybierane ograniczoną funkcją |
| `ioc_revisions` | UUID, FK IOC, unikalna rewizja 1–50; oryginalny JSON, jego kanoniczne UTF-8 i SHA-256, autor/data |
| `int_event_receipts` | PK/FK normalized event, oryginalny hash, normalization version, mode/dataset/run, evaluated_at i match_count 0–32, także zero |
| `int_event_matches` | FK event receipt/IOC/rewizji; unikalny event + revision + field; observed_value do 8192, canonical_value do 2048, pełny snapshot rewizji i hash |

Rewizja przechowuje reputację unknown/clean/suspicious/malicious, nullable
confidence 0–100, source, świadome first/last seen, tagi, opis i active.
Reputacja i confidence są deklaracją źródła. Typ i kanoniczna wartość nie
zmieniają się; edycja i archiwizacja tworzą nową rewizję. Limity katalogu
1000, rewizji 50 i atomowego importu 100 obejmują także wyłączone wpisy.
Runtime ma SELECT/INSERT; funkcja SECURITY DEFINER sprawdza aktora i wybiera
kolejną rewizję. FK, scope/hash guards i deferred cardinality sprawdzają
kompletność przy commit. UPDATE/DELETE/TRUNCATE historii i niepusty downgrade
są blokowane; INSERT pozostaje granicą zaufanego aplikacyjnego writera.

Receipt utrwala katalog użyty przy pierwszej analizie eventu, także pustą
listę. Replay jest związany z konkretnym event/dataset/run, bez założenia,
że reputacja była znana w historycznym czasie zdarzenia. Import/PATCH nie
zmieniają receipts, starych alertów ani ocen. Risk v4 wskazuje oryginalny
match/revision proof; v2/v3 zachowują oryginalne wejścia i hash. GET nie
tworzy dopasowań; jawny backfill obejmuje tylko zdarzenia bez receipt.
[Zasady i ograniczenia](intelligence.md),
[ADR 0013](adr/0013-local-intelligence.md),
[walidacja Etapu 7](validation-intelligence.md).

Poniższa tabela obejmuje dalsze, jeszcze niewdrożone agregaty.

| Agregat | Planowane encje / constraints |
| --- | --- |
| Detection | rules, immutable rule_versions, detection_state, matches, alert_revisions, alert_events |
| Incidents | incidents z version, incident_alerts, notes, evidence_snapshots, incident_iocs, timeline |
| Context | Zweryfikowane assets/identities i dalsze enrichment_versions; lokalne iocs i match IOC opisano wyżej |
| Hunting | saved_queries, bookmarks, investigations, investigation_events, draft_rules |
| SOAR | playbooks, versions, runs, steps, attempts, notifications; unikalny execution key |
| Governance | audit_log append-only, replay_runs, risk_policy_versions, mitre_catalog_versions |

Relacje wewnątrz PostgreSQL mają FK; referencje do eventów w ClickHouse nie mogą mieć
międzybazowego FK, dlatego alert/case utrwala bounded evidence snapshot + checksum.
Unikalność source_event_id i fingerprintów jest wymuszana w bazie, nie tylko Pythonem.
Indeksy operational time/status/owner i entity key powstaną z rzeczywistymi zapytaniami.

## ClickHouse — wdrożona projekcja i dalsze rozszerzenia

Działające DDL są w `infra/clickhouse/migrations`; archiwum używa
ReplacingMergeTree i deduplikacji na odczycie przed filtrowaniem/paginacją.
Procedury i granice: [PHASE 3 operations](phase3-operations.md).
Poniżej zachowano ogólne założenia dalszej projekcji adnotacji; benchmark
przepustowości pozostaje niewykonany.

Plan: partycja miesięczna po niezmiennym `timestamp`; sortowanie
`(dataset_id, source_id, toDate(timestamp), timestamp, event_id)`.
Retry zachowuje cały klucz. Parametryzowane wyszukiwanie zawsze wymaga zakresu czasu;
projekcja adnotacji ma własny checkpoint. Brak natywnych FK do PostgreSQL oznacza
okresowy test spójności i jawny status niedostępnej projekcji. Ostateczne DDL i
indeksy wymagają benchmarku przed akceptacją fazy implementacyjnej.
