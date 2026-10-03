# API v1 — zakres wdrożony i projekt dalszych faz

Status: kod PHASE 1–3 i przyrostów SOC, stan 2026-10-03;
wyniki wykonanych kontroli w [raporcie MITRE](validation-mitre.md)
i wcześniejszych raportach walidacji.
Kod obejmuje `/auth`, `/users`, `/audit`, `/system/health`, źródła, przyjęcie
eventów, status batcha, retry, normalized event search, alerts/detections,
incidents, correlations, risk, mitre oraz techniczne sondy/metryki.
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
- Mutacja case/rule/playbook wymaga oczekiwanej wersji (ETag/If-Match): brak `428`,
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
| Sigma | POST `/detections/import` | Walidacja i kompilacja obsługiwanego subsetu |
| Hunts | GET/POST `/hunts`; PATCH `/hunts/{id}`; POST `/hunts/{id}/runs`, `/hunts/{id}/bookmarks`, `/hunts/{id}/investigations`, `/hunts/{id}/draft-detections` | Saved query, evidence, investigation, draft rule |
| Investigations | POST `/investigations/{id}/promote` | Jednorazowa, audytowana promocja do sprawy |
| TI | GET/POST `/iocs`; PATCH `/iocs/{id}` | Typowana lokalna reputacja, wersje i audit |
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
