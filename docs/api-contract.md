# API v1 — projekt kontraktu

Status: kontrakt docelowy z ukończonym zakresem PHASE 1 (2026-09-28).
Kod obejmuje `/auth`, `/users`, `/audit`, `/system/health` i techniczne sondy/metryki.
OpenAPI dla zaimplementowanych tras powstaje z modeli pod `/api/v1/openapi.json`.
Pozostałe zasoby poniżej należą do kolejnych faz; tabela nie oznacza ich dostępności.
Weryfikację działania z rzeczywistymi usługami dokumentuje [raport walidacji](validation.md).
Wspólny prefiks zasobów: `/api/v1`. Role i scopes: [security](security.md).

## Konwencje

- UTC RFC3339; UUID identyfikatory; cursor pagination ze stabilnym tie-breaker ID.
- Docelowy limit listy: domyślnie 100, maksymalnie 500. Wyjątek PHASE 1:
  `/api/v1/users` i `/api/v1/audit` używają domyślnie 50, maksymalnie 100 rekordów.
  Wyszukiwanie eventów: domyślnie 24 h, max 7 dni na żądanie interaktywne,
  bez dowolnego SQL. Większy zakres jako kontrolowany job.
- Mutacja case/rule/playbook wymaga oczekiwanej wersji (ETag/If-Match): brak `428`,
  nieaktualna wersja `412`. Niedozwolone przejście stanu daje `409`.
- Idempotency-Key na ingest, start demo/replay i start playbook; ponowienie zwraca
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

## Powierzchnia zasobów

| Obszar | Planowane metody i ścieżki | Zachowanie |
| --- | --- | --- |
| Auth | POST `/auth/login`, `/auth/refresh`, `/auth/logout`; GET `/auth/me`, `/auth/csrf` | Access JWT, refresh rotation, unieważnienie sesji, CSRF token |
| Events | POST `/events`, `/events/search`; GET `/events`, `/events/{id}`, `/events/batches/{batch_id}` | Single/batch ingest, bounded query i status async |
| Alerts | GET `/alerts`, `/alerts/{id}`, `/alerts/{id}/events` | Explanation, wkłady risk, immutable wersja reguły, pivots |
| Incidents | GET/POST `/incidents`; GET/PATCH `/incidents/{id}`; POST `/incidents/{id}/transitions` | Przypisanie, opis, verdict i kontrolowane przejście statusu |
| Case artifacts | POST `/incidents/{id}/notes`, `/evidence`, `/iocs`; GET `/incidents/{id}/timeline` | Audytowana praca analityka i storyline |
| Detections | GET/POST `/detections`; GET/PATCH `/detections/{id}` | Draft/version/enable/disable zgodnie z permission |
| Sigma / rule test | POST `/detections/import`, `/detections/{id}/test` | Walidacja obsługiwanego subsetu, sandbox test bez live efektów |
| Hunts | GET/POST `/hunts`; PATCH `/hunts/{id}`; POST `/hunts/{id}/runs`, `/hunts/{id}/bookmarks`, `/hunts/{id}/investigations`, `/hunts/{id}/draft-detections` | Saved query, evidence, investigation, draft rule |
| Investigations | POST `/investigations/{id}/promote` | Jednorazowa, audytowana promocja do sprawy |
| TI | GET/POST `/iocs`; PATCH `/iocs/{id}` | Typowana lokalna reputacja, wersje i audit |
| Playbooks | GET/POST `/playbooks`; POST `/playbooks/{id}/versions`, `/playbooks/{id}/publish`, `/playbooks/{id}/runs` | Publikowane wersje i wykonanie simulation |
| SOAR runs | GET `/playbook-runs/{id}`; POST `/playbook-runs/{id}/cancel` | Historia kroków, prób i wyników |
| Users | GET/POST `/users`; PATCH `/users/{id}` | Role/deactivation; Admin, bez ujawniania hashy |
| Audit | GET `/audit` | Brak endpointów UPDATE/DELETE; Manager/Admin |
| SOC metrics | GET `/metrics`, `/dashboard`, `/system/health` | JSON metryk domenowych i stanu zależności, auth |
| Demo | POST `/demo/runs`; GET `/demo/runs/{id}` | Admin/Manager, izolowany dataset i scenariusz |
| Replay | POST `/replays`; GET `/replays/{id}` | Uprawniony, bounded, zamknięte wejście i snapshot wersji |
| Reports | POST `/incidents/{id}/reports`; GET `/reports/{id}` | Audytowany snapshot JSON/HTML z redakcją danych |

Trasy stałe jak `/events/batches` i `/detections/import` są deklarowane przed
dynamicznymi ID lub typowane UUID; test routingu chroni przed przechwyceniem słowa
`import` jako identyfikatora. Paths skrócone w komórce dziedziczą jawny prefix zasobu.

## Przykład ingestu (kontrakt, nie działające demo)

```http
POST /api/v1/events
Authorization: Bearer <source-credential>
Idempotency-Key: <unique-batch-key>
Content-Type: application/json

{"events":[{"source_type":"generic_json","source_event_id":"log-001","raw_event":{"timestamp":"2026-09-24T12:00:00Z","username":"analyst-demo","action":"login","result":"failed","source_ip":"192.0.2.10"}}]}
```

Przyjęcie zwraca `202` z `batch_id`, `accepted_count`, `status_url` i `request_id`.
Źródło ma `events:status` tylko dla własnych batchy w swoim source/dataset; ten scope
nie daje prawa wyszukiwania logów innych źródeł ani odczytu spraw.
Ten przykład wymaga skonfigurowanego mapowania generic_json. Pole source credential
jest miejscem na sekret, a nie wartością do zapisania w repozytorium.

## Explorer i query

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
