# API v1 — zakres wdrożony i projekt dalszych faz

Status: kod PHASE 1–3 i przyrostów SOC, stan 2026-10-05;
Etap 7 implementuje lokalne IOC. Jego końcowe wyniki zapisuje
[raport Threat Intelligence](validation-intelligence.md): regresja i lokalne
uruchomienie potwierdzone, z jawnymi ograniczeniami testu przeglądarkowego.
Etap 8 dodaje odczyt chronologii dowodów sprawy; [jego raport](validation-attack-timeline.md)
zapisuje nową bramkę. Historyczne kontrole opisują raporty wcześniejszych etapów.
Kod obejmuje `/auth`, `/users`, `/audit`, `/system/health`, źródła, przyjęcie
eventów, status batcha, retry, normalized event search, alerts/detections,
incidents, correlations, risk, mitre, sigma, entities, intelligence oraz
techniczne sondy/metryki.
OpenAPI dla zaimplementowanych tras powstaje z modeli pod `/api/v1/openapi.json`.
Zasoby oznaczone jako przyszłe poniżej nie są dostępne w tej implementacji.
Weryfikację działania z rzeczywistymi usługami dokumentuje [raport walidacji](validation.md).
Wspólny prefiks zasobów: `/api/v1`. Role i scopes: [security](security.md).

## Konwencje

- UTC RFC3339; UUID identyfikatory; cursor pagination ze stabilnym tie-breaker ID.
- Docelowy limit listy: domyślnie 100, maksymalnie 500. Wyjątek PHASE 1:
  `/api/v1/users`, `/api/v1/audit` i `/api/v1/sources` używają domyślnie 50,
  maksymalnie 100 rekordów; ten limit obowiązuje również incidents i ich kolekcje.
  Wyszukiwanie eventów: domyślnie 24 h, max 7 dni na żądanie interaktywne,
  bez dowolnego SQL. Większy zakres jako kontrolowany job.
- Mutacja case/rule/IOC/playbook wymaga oczekiwanej wersji (ETag/If-Match): brak `428`,
  nieaktualna wersja `412`. Niedozwolone przejście stanu daje `409`.
- Idempotency-Key na ingest i tworzenie incydentu; w przyszłości start demo/replay
  i start playbook. Ponowienie zwraca
  ten sam wynik tylko dla zgodnego body i scope; konflikt treści `409`.
- `401` brak poprawnej sesji; `403` brak permission; `413` rozmiar; `422` walidacja;
  `429` rate limit z Retry-After; `503` brak zależności/pojemności. Nie pokazujemy stack trace.
- Error body: `code`, bezpieczny `message`, `request_id`, opcjonalne `field_errors`.
  Nie odbija raw logów, tokenów ani hasła w komunikacie błędu.
- `X-Request-ID` generuje serwer lub akceptuje ograniczony poprawny identyfikator;
  przenosi go do outbox/worker/audit. Każda mutacja ma spójny audyt.
- Żądania JSON wymagają `Content-Type: application/json`. W PHASE 1 `POST`
  `/api/v1/auth/refresh` i `/api/v1/auth/logout` dopuszczają puste body bez
  `Content-Type`; nadal wymagają cookie sesji, poprawnego `Origin` i `X-CSRF-Token`.
  Niepuste body także na tych dwóch trasach wymaga `application/json`.

W lokalnym Compose Uvicorn działa z `--no-proxy-headers`. Limiter IP widzi więc
wspólny adres reverse proxy, a klienci lokalnego demo współdzielą przepustowość
limitów IP. Nagłówek `X-Forwarded-For` podany przez klienta nie omija limitów.
Limity przypisane do rodziny sesji zachowują swój odrębny zakres. Integracja
PHASE 1 potwierdza działanie auth i limitera na rzeczywistych usługach;
przeglądarkowy przepływ UI należy do PHASE 13.

## Dostępne zasoby

| Obszar | Metody i ścieżki | Dostęp / zachowanie |
| --- | --- | --- |
| Auth | POST `/auth/login`, `/auth/refresh`, `/auth/logout`; GET `/auth/me`, `/auth/csrf` | JWT, rotacja refresh, unieważnienie sesji, CSRF |
| Users | GET/POST `/users`; PATCH `/users/{id}` | Admin; wersja przy PATCH |
| Audit | GET `/audit` | Admin/Manager; brak mutacji historii |
| Sources | GET/POST `/sources`; GET/PATCH `/sources/{id}` | Admin; PATCH zmienia tylko enabled, wymaga If-Match |
| Source credentials | POST `/sources/{id}/credentials`; DELETE `/sources/{id}/credentials/{credential_id}` | Admin; jednorazowy token przy wydaniu, odwołanie 204 |
| Admission | POST `/events` | Wyłącznie source credential `events:write`; single/batch, trwały zapis 202 |
| Batch status | GET `/events/batches/{batch_id}` | Własny source scope `events:status` lub ludzki `events:read` |
| Retry | POST `/events/{event_id}/retry` | Admin; quarantined + If-Match generacji; limit pending |
| System | GET `/system/health`, `/system/ingestion` | Admin/Manager; zależności oraz globalne liczniki/limity ingest |
| Event Search | POST `/events/search`; GET `/events`, `/events/{id}` | Human events:read; parametryzowane filtry, podpisany cursor, dowód |
| Pipeline | GET `/system/pipeline`, `/system/pipeline/{event_id}`; POST `/system/pipeline/{event_id}/retry` | Status; Admin może ponowić błąd z If-Match |
| Alerts | GET `/alerts`, `/alerts/{id}`; PATCH `/alerts/{id}` | Odczyt dowodu; Analyst/Manager/Admin zmienia status z If-Match |
| Detections | GET `/detections`, `/detections/{id}`; PATCH `/detections/{id}`; POST `/detections/test` | Trzy wbudowane reguły; publish włącza deployment, test nie zapisuje alertu |
| Detection status | GET `/system/detections` | Manager/Admin; checkpointy i backlog |
| Correlations | GET `/correlations`, `/correlations/{id}`; PATCH `/correlations/{id}`; POST `/correlations/test` | Pięć reguł, detections:read/publish/test; If-Match dla enabled; czysty test bez zapisu alertów |
| Correlation status | GET `/correlations/status` | Stan pracy, watermark i jawne luki pokrycia |
| Replay finalization | POST `/correlations/replay/finalize` | Uprawniona, audytowana finalizacja dataset/run z oczekiwaną liczbą wejścia |
| Incidents | GET/POST `/incidents`; GET/PATCH `/incidents/{id}` | Tworzenie z Idempotency-Key; edycja/status/owner z If-Match |
| Incident alerts | POST `/incidents/{id}/alerts`; DELETE `/incidents/{id}/alerts/{alert_id}` | Dopinanie/odpinanie z zachowaniem dowodów, If-Match |
| Incident history | POST/GET `/incidents/{id}/notes`; GET `/incidents/{id}/timeline`, `/incidents/{id}/evidence` | Append-only notes/timeline, paginacja i niezmienne dowody |
| Incident assignees | GET `/incidents/assignees` | Dostępni aktywni operatorzy zgodnie z rolą |
| Risk policy | GET `/risk/policy` | Detections:read; wersja/hash, wagi i poziomy 0–29/30–59/60–79/80–100 |
| Risk history | GET `/alerts/{id}/risk`, `/incidents/{id}/risk` | Właściwe alerts:read/incidents:read; current/history, limit 1–50, history_truncated; odczyt bez mutacji |
| Risk backfill | POST `/risk/backfill` | Admin system:manage; ograniczona porcja starszych rekordów, niezmienne obliczenia i audyt |
| Risk test | POST `/risk/test` | Detections:test; jawna symulacja wersjonowanego wejścia, bez zapisu efektów domenowych |
| Risk recalculation | POST `/alerts/{id}/risk/recalculate`, `/incidents/{id}/risk/recalculate` | Właściwe alerts:manage/incidents:edit, If-Match decyzji analityka, ponowna autoryzacja po blokadzie; wynik z zachowanych dowodów |
| Sigma | GET `/sigma/capabilities`, `/sigma/rules`, `/sigma/rules/{id}`; POST `/sigma/validate`, `/sigma/test`, `/sigma/rules`, `/sigma/rules/{id}/versions`; PATCH `/sigma/rules/{id}` | Odczyt/walidacja, bezstanowy test, import wyłączonej rewizji, publikacja z If-Match; szczegóły poniżej |
| Encje | GET `/entities`, `/entities/by-event/{event_id}`, `/entities/{id}` i kolekcje events/alerts/incidents/related; POST `/entities/backfill` | Obserwowane profile, siedem odczytów i jedna audytowana partia indeksowania; szczegóły poniżej |
| Intelligence | GET/POST `/intelligence/iocs`; GET/PATCH `/intelligence/iocs/{id}`; GET historia/providers/event proof; POST import/lookup/backfill | Lokalny katalog i zachowane pierwsze dopasowania, dziesięć metod; szczegóły poniżej |

Utworzenie źródła zwraca `{source, credential}` z tokenem widocznym tylko raz.
Source ma server-generated dataset UUID, `mode=live` i zerowy `run_id`.
Credential ma scopes `events:write`/`events:status`, ważność 1–90 dni (domyślnie 30).
GET źródła zwraca konfigurację i metadane do 100 najnowszych credentiali, bez sekretów.
Wyłączenie źródła odwołuje wszystkie jego credentiale; ponowne włączenie wymaga
wydania nowych. Odpowiedzi źródeł, ingest i statusu mają `Cache-Control: no-store`.

Przebieg nadawcy, operacje Admina i znaczenie pojemności:
[PHASE 2 operations](phase2-operations.md).

Szczegółowy kontrakt incydentów i limity: [etap 1](incidents.md).
Kontrakty wcześniejszego panelu i trzech detekcji: [initial SOC](initial-soc.md).
Finalizacja czasowa i wielozdarzeniowe dowody: [ADR 0008](adr/0008-temporal-correlation.md),
[raport Etapu 2](validation-correlation.md).
Szczegóły punktacji, deduplikacji i jawnych braków: [Risk Engine](risk-engine.md).
Listy alertów/spraw zawierają nullable score, level i calculation ID;
szczegóły także `risk_explanation`. Wynik zachowuje składniki, uzasadnienie
punktów, policy/input hashes i odniesienie do poprzedniego obliczenia.

## Projekt zasobów przyszłych faz

| Obszar | Planowane metody i ścieżki | Zachowanie |
| --- | --- | --- |
| Alert extensions | GET `/alerts/{id}/events` | Wiele contributing events i wyjaśnione risk |
| Case extensions | POST `/incidents/{id}/evidence`, `/incidents/{id}/iocs` | Dodatkowe artefakty/IOC i verdict; obecny status zmienia PATCH |
| Rule authoring | POST `/detections`; wersjonowane definicje | Draft/version/import oprócz obecnego stałego katalogu |
| Hunts | GET/POST `/hunts`; PATCH `/hunts/{id}`; POST `/hunts/{id}/runs`, `/hunts/{id}/bookmarks`, `/hunts/{id}/investigations`, `/hunts/{id}/draft-detections` | Saved query, evidence, investigation, draft rule |
| Investigations | POST `/investigations/{id}/promote` | Jednorazowa, audytowana promocja do sprawy |
| Playbooks | GET/POST `/playbooks`; POST `/playbooks/{id}/versions`, `/playbooks/{id}/publish`, `/playbooks/{id}/runs` | Publikowane wersje i wykonanie simulation |
| SOAR runs | GET `/playbook-runs/{id}`; POST `/playbook-runs/{id}/cancel` | Historia kroków, prób i wyników |
| SOC metrics | GET `/metrics`, `/dashboard` | JSON metryk domenowych, auth |
| Demo | POST `/demo/runs`; GET `/demo/runs/{id}` | Admin/Manager, izolowany dataset i scenariusz |
| Replay | POST `/replays`; GET `/replays/{id}` | Uprawniony, bounded, zamknięte wejście i snapshot wersji |
| Reports | POST `/incidents/{id}/reports`; GET `/reports/{id}` | Audytowany snapshot JSON/HTML z redakcją danych |

Trasy stałe jak `/events/batches` i `/detections/import` są deklarowane przed
dynamicznymi ID lub typowane UUID; test routingu chroni przed przechwyceniem słowa
`import` jako identyfikatora. Paths skrócone w komórce dziedziczą jawny prefix zasobu.

## Ingest PHASE 2

```http
POST /api/v1/events
Authorization: Bearer <source-credential>
Idempotency-Key: <unique-batch-key>
Content-Type: application/json

{"events":[{"source_type":"generic_json","source_event_id":"log-001","raw_event":{"timestamp":"2026-09-24T12:00:00Z","username":"analyst-demo","action":"login","result":"failed","source_ip":"192.0.2.10"}}]}
```

Przyjęcie zwraca `202` z `batch_id`, `accepted_count`, `created_count`,
`duplicate_count`, `status_url` i oryginalnym `request_id`. Ten sam klucz
`Idempotency-Key` (1–128 znaków `[A-Za-z0-9._:-]`) i kanoniczna treść w tym samym
source/dataset/mode/run zwracają ten sam wynik. Zmieniona treść daje `409`.
`source_event_id` deduplikuje identyczne rekordy w tym scope także pomiędzy batchami;
inny payload dla tego ID odrzuca cały batch. Brak ID wyłącza deduplikację eventu.
Pojedynczy envelope i jednoelementowy `events` mają ten sam kanoniczny hash.

Batch ma 1–500 pozycji, request do 1 MiB, raw do 64 KiB, głębokość JSON do 16.
Nieznane pola, typ spoza listy źródła, wadliwy envelope lub timestamp bez jawnego
offsetu odrzucają całe wejście `422`. Timestamp envelope musi być tekstem RFC3339,
nie liczbą Unix epoch. Przyjęcie wymaga dostępnego limitera Redis: 10 żądań/s
na źródło wspólnie dla credentiali, `429` z Retry-After lub `503` przy awarii.
Ograniczenia pojemności również dają `503` z `Retry-After: 5`.

Źródło ma `events:status` tylko dla własnych batchy w swoim source/dataset; ten scope
nie daje prawa wyszukiwania logów innych źródeł ani odczytu spraw.
Status zwraca `records` z pozycją, event UUID, stanem, generacją, liczbą prób i
bezpiecznym error_code; nie zwraca raw treści. Jego counts liczą pozycje batcha,
więc powtórzony event może wystąpić więcej niż raz. Operator `/system/ingestion`
liczy unikalne zadania. `staged` oznacza gotowość do normalizacji; counts
`normalized`, `processed`, `projected` wynoszą zero w PHASE 2. Mapowania pól,
normalizacja, detekcja i ClickHouse pozostają następnymi fazami.
Pole source credential w przykładzie jest miejscem na sekret, nie wartością do Git.

## Explorer i query — przyszłe fazy

Filtry: czas, user, host, IP, process, event category/type/severity, source,
MITRE technique i rule ID. Parametr `q` jest parsowany do typowanego AST.
Przykład użytkownika pozostaje obsługiwany przez jawne aliasy:

```text
source.ip = "192.168.1.10" AND event.category = "authentication" AND result = "failed"
```

Parser query nie używa eval, konkatenacji SQL ani dowolnych identyfikatorów kolumn.
Walidacja operatorów, paginacja, budżet czasu i kontrole zakresu obowiązują także
saved queries i API (nie tylko UI). Pełne zasady: [Threat Hunting](threat-hunting.md).

## Health i metryki techniczne

Poza wersjonowanym API: `/health` (liveness), `/ready` (readiness), `/metrics`
(Prometheus). Nie mylić z `/api/v1/metrics` dla JSON SOC. `/ready` zwraca `503`,
gdy bazowe zależności są niedostępne; szczegóły tylko w chronionym widoku System Health.
`/metrics` dostępne wyłącznie w wewnętrznej sieci lub z uprawnionym scraperem.

## MITRE ATT&CK — Etap 4

GET `/api/v1/mitre/catalog` wymaga `detections:read` i zwraca aktywne metadane
lokalnego Enterprise ATT&CK: 15 tactics, 697 techniques/subtechniques.
`catalogue` zawiera version/sha256, source URL/hash/commit, attribution i license URL.

GET `/api/v1/mitre/coverage` wymaga jednocześnie `detections:read`, `alerts:read`
i `incidents:read`. Parametry: mode=live|replay, from/to (UTC z timezone),
dataset_id/run_id i include_false_positives=false. Live obejmuje wszystkie źródła
i odrzuca dataset/nonzero run; replay wymaga exact dataset/nonzero run.
Zakres domyślnie 30 dni, maksymalnie 366, dodatni i bez przyszłego to.
`scope` dokumentuje alert.event_timestamp i przedział [from,to).

`tactics`/`techniques` mają configured_rule_count/enabled_rule_count oraz
distinct alert_count/incident_count. `summary` osobno opisuje eligible/mapped/
unmapped/legacy/other_catalogue/excluded_false_positive alerts, distinct incidents
i observed/configured/enabled technique/tactic counts. Sprawa musi mieć aktywny
link do kwalifikującego się alertu w zakresie; closed/resolved nadal są dowodem.
Wielu technik/taktyk nie sumuje się do liczby wszystkich alertów/spraw.
Limit: 60 żądań/min/osoba, SQL statement_timeout=3 s; odczyt jednym aggregate SQL.
Oba endpointy mają Cache-Control: no-store i nie wykonują backfillu.

Istniejące katalogi reguł i szczegóły alertu zwracają osobne `mitre_mapping`:
status mapped/unmapped/legacy_unmapped, catalogue_version/hash,
mapping_version/hash, techniques z nazwami/URL i tactics oraz reason.
`claim=candidate_association`, `confirmed_attack=false` określają znaczenie
wszystkich skojarzeń. Szczegół incydentu ma deduplikowane historyczne techniki
i mapped/unmapped/legacy/excluded-FP counters z aktualnych aktywnych links.
Stare rule_snapshot i legacy mitre_techniques zachowują zgodność kontraktu.
Mapping nie nadaje punktów T w Risk Engine. [Zasady i ograniczenia](mitre.md).

## Sigma — Etap 5

Wspólny prefiks `/api/v1/sigma`. GET capabilities/rules/rules/{id} i POST
validate wymagają `detections:read`; POST test wymaga `detections:test`.
POST rules/rules/{id}/versions wymaga `detections:import`, PATCH rules/{id}
`detections:publish`. Mutacje ponownie sprawdzają authority po blokadzie.
Każda odpowiedź ma Cache-Control: no-store. Szczegół/mutacja zwraca ETag
wdrożenia. Rewizja i enabled PATCH wymagają `If-Match`, 428 brak, 412 konflikt.

Import/validate używa `{yaml:string}`; test dodaje `events` ze schematu
NormalizedSecurityEvent, 1–25. YAML ma 1–65536 bajtów UTF-8, import JSON
do 262144 bajtów, test JSON do 1048576. Capabilities zwraca pełne limity,
pola/aliasy, logsource, operatory, wersję wykonawcy i ograniczenia.
Walidacja/test nie zapisują reguły, alertu, ryzyka ani incydentu.
Limity per osoba: validate/test 30/min, import/revisions 20/min.

GET rules zwraca `{items:[RuleView]}` do 100. RuleView ma `id`/`sigma_id`,
rewizję i jej UUID, title/description/severity/mitre/guidance/references,
evaluator/source_types/source_sha256/compiled_sha256/mitre_mapping oraz
enabled/version/updated_at/updated_by. Szczegół dodaje definition_yaml,
compiled AST i do 20 historycznych VersionView. Historia zawiera numery,
UUID, hashe, created_at/created_by, a źródłem bieżącego szczegółu jest
wybrana niezmienna rewizja.

Pierwszy import daje 201, rewizję 1 i enabled=false. Identyczny bieżący
source hash daje 200 istniejącego wpisu bez dodatkowych zapisów. Inne źródło
tego UUID daje 409 `sigma_rule_exists`. POST versions zachowuje UUID, tworzy
201 kolejną rewizję i wyłącza publikację; unchanged/id mismatch/limit daje409.
PATCH `{enabled:boolean}` daje200; ten sam stan daje409. Niedostępna albo
niespójna utrwalona rewizja daje503 bez ujawniania treści źródła.

Alert ma `detection_type=sigma`, wykonawcę `sigma-subset-v1` oraz historyczne
source/revision/AST. Risk policy v3 rozdziela deklarowaną severity od
kontrolowanych rodzin C/E. [Semantyka](sigma.md), [decyzja](adr/0011-versioned-sigma-rules.md).

## Profile encji — Etap 6

Kontrakt implementowany w Etapie 6; wykonane wyniki zapisuje
[raport](validation-entities.md). Prefiks `/api/v1/entities`.
Wszystkie GET wymagają łącznie events:read, alerts:read i incidents:read.
POST backfill wymaga system:manage i ponownej autoryzacji po blokadzie.

| Metoda i ścieżka | Wynik |
| --- | --- |
| GET `/entities` | EntityPage z EntitySummary |
| GET `/entities/by-event/{event_id}` | Profile encji zweryfikowanego eventu; bez indeksowania przy GET |
| GET `/entities/{id}` | EntityDetail z kanoniczną podstawą, rolami, risk i MITRE |
| GET `/entities/{id}/events` | Paginowana aktywność i role w oryginalnych zdarzeniach |
| GET `/entities/{id}/alerts` | Paginowane alerty wszystkich contributed events |
| GET `/entities/{id}/incidents` | Paginowane sprawy z aktywnymi powiązaniami |
| GET `/entities/{id}/related?kind=host` | Profile hostów współobserwowanych w zdarzeniach |
| POST `/entities/backfill` | Audytowany, ograniczony indeks starszych dowodów |

Filtry query: mode live/replay, dataset_id/run_id dla dokładnego replay,
UTC `from`/`to`, kind host/user/ip/process, literalne q do128 znaków,
limit1–100 (domyślnie25), podpisany cursor. Domyślnie30 dni, maksimum366;
past positive `[from,to)`, czas contributed event. Cursor wiąże zasób,
filtry, okno i porządek. Zmiana filtrów wymaga rozpoczęcia od pierwszej strony.

EntityPage zawiera scope, items, dokładny total, next_cursor i index_status.
Summary zawiera UUID/kind/label, identity_policy/basis, inventory_verified=false,
source_id, first_seen/last_seen w oknie, counts oraz nullable risk score/level.
Counts rozdzielają distinct events, role observations, alerty kwalifikujące się,
false positives i aktywnie powiązane incydenty; failed_logins są distinct event
powiązane z encją niezależnie od roli, bez przypisywania jej własnych prób.
Detail dodaje canonical_identity, role counts, related_host_count i pełną
projekcję istniejącej oceny: strategy maximum_current_eligible_alert,
entity_calculation=false, alert/calculation/policy i oryginalne explanation.
MITRE claim candidate_association i confirmed_attack=false pozostają jawne.
Alert false positive pozostaje w historii, bez udziału w ryzyku/MITRE.

IndexStatus pending_events/pending_alerts/complete wskazuje niepełną historię.
POST `{limit:25}` (strict integer1–100) obejmuje maksymalnie limit normalized
events oraz limit alertów. Receipt zapewnia idempotencję. Backfill nie zmienia
snapshotów, alertów ani wyników risk. Błąd integralności daje409 bez partial
commit. Trzysekundowy limit SQL oraz ograniczona odpowiedź chronią koszt
odczytu. Konserwatywną tożsamość i ograniczenia opisuje [entities](entities.md).

## Threat Intelligence — Etap 7

Prefiks `/api/v1/intelligence`, osiem ścieżek i dziesięć metod:

| Metoda i ścieżka pod prefiksem | Dostęp i wynik |
| --- | --- |
| GET `/iocs` | intelligence:read; IOCPage, dokładny total, next_cursor, normalization_version i limity |
| POST `/iocs` | intelligence:manage; IOCView, 201 nowy albo 200 identyczny bieżący wpis |
| GET `/iocs/{id}` | intelligence:read; IOCView i ETag bieżącej rewizji |
| PATCH `/iocs/{id}` | intelligence:manage; nowa rewizja metadanych/active z If-Match; no-op zachowuje wersję |
| GET `/iocs/{id}/history` | intelligence:read; oryginalne rewizje, hashe, autor/data, total i signed next_cursor |
| POST `/import` | intelligence:manage; atomowe `{items:[IOCInput]}`, wynik items/created/unchanged |
| POST `/lookup` | intelligence:read; dokładne `{type,value}`, wynik canonical_value/found/item, także wpis nieaktywny |
| GET `/providers` | intelligence:read; rzeczywiście dostępny lokalny provider i brak network_access |
| GET `/events/{event_id}` | intelligence:read i events:read; pending albo evaluated, oryginalne field matches i receipt |
| POST `/backfill` | system:manage; jawna partia do 100 starszych events bez receipt, bez nowych alertów/recalculation |

IOCInput: type ip/domain/url/hash, value 1–2048, reputation
unknown/clean/suspicious/malicious, nullable strict confidence 0–100,
source 1–128, opcjonalne świadome czasy first_seen/last_seen, do 16 różnych
tagów po 1–64, description do 2048 oraz strict active (domyślnie true).
Nieznane pola, kontrolne znaki metadanych i niepoprawne wskaźniki są odrzucane.
Source i tagi mają znormalizowane zewnętrzne spacje; daty są UTC i first≤last.
Reputacja oraz confidence są deklaracją źródła, bez gwarancji prawdopodobieństwa.

IOCView dodaje id, canonical_value, normalization_version, revision,
revision_id, document_sha256, version, created_at/by i updated_at/by.
Value jest kanoniczna; typ/wartość/ID nie podlegają PATCH. Zmiana active=false
archiwizuje przez rewizję, bez DELETE. Version odpowiada numerowi rewizji.
Brak If-Match daje 428 version_required, nieaktualna wersja 412 version_conflict.
Inne metadane istniejącej tożsamości przy POST dają 409 ioc_exists.

Katalog ma limit 1000 także dla wpisów wyłączonych, historia 50 rewizji na IOC,
a import 1–100 rekordów i body do 1 MiB. Pozostałe mutacje mają limit 64 KiB.
Duplikaty kanoniczne w imporcie dają 422 ioc_import_duplicates; dowolny błąd
albo brak audytu wycofuje całą partię. Limity katalogu/rewizji dają 409.
Publikacja/import/PATCH ponownie sprawdzają rolę i aktywną sesję po blokadzie.
Analyst ma obecnie odczyt; endpointu intelligence:propose nie dostarczono.

Lista filtruje kind, reputation, active i literalne q do 128 znaków.
Limit 1–100 (domyślnie 25); historia domyślnie 50, maksimum 100 na stronę.
Cursor do 4096 znaków wiąże principal, path, filtry i limit; niepoprawny daje
422 invalid_cursor. Count/page katalogu mają jedną migawkę SQL. Timestamp
anchor nie jest commit timestamp ani wspólną migawką wszystkich stron;
zmiana bieżącej rewizji może zmienić filtr następnej strony.

Dowód eventu zawiera event_id, status, document_sha256, normalization_version,
evaluator_version, evaluated_at, match_count i matches. Match zachowuje IOC
i revision IDs, field, observed/canonical value, pełny revision_snapshot/hash.
Reputation_origin=source_assertion i confirmed_attack=false są jawne. Receipt
zero matches oznacza wykonaną analizę; pending nie oznacza braku wskaźników.
GET nigdy nie tworzy dopasowań. Import/PATCH nie zmieniają pierwszego wyniku.
Backfill `{limit:25}` (strict 1–100) nie resetuje DetectionJob i nie przelicza
historycznych ocen; jawne risk/recalculate może utworzyć kolejną ocenę.

Dokładne reguły kanonikalizacji, typowane pola i semantykę medium TI oraz
opt-in risk v4 z fallback v3 opisuje [intelligence](intelligence.md).
[ADR 0013](adr/0013-local-intelligence.md),
[walidacja Etapu 7](validation-intelligence.md).

## Attack Timeline — Etap 8

`GET /incidents/{incident_id}/attack-timeline?limit=25&cursor=...` wymaga razem
incidents:read, alerts:read i events:read. Strony 1–25, no-store, obserwowany
czas ASC/UUID, zachowany event_snapshot/event_sha256 i wszystkie odnośniki
aktywnych alertów. Signed cursor wiąże użytkownika, ścieżkę, limit i fingerprint.
DTO, index_status oraz kody 409 opisuje [kontrakt chronologii](attack-timeline.md).
Zmiana fingerprintu wymaga odświeżenia; pending nie uruchamia backfill w GET.
