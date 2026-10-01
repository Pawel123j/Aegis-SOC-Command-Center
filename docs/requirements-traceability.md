# Macierz wymagań i dowodów

Macierz zachowuje numerację 1–37 z wymagań użytkownika. Łączy każdy punkt z fazą, planowanym artefaktem i obserwowalnym kryterium odbioru. Rozwinięcie zadań, zależności i testów znajduje się w [planie implementacji](implementation-plan.md). Źródłem informacji o stanie zastanym jest [raport aktualnego stanu](current-state-report.md).

## Znaczenie statusów

- **Projektowane w fazie 0** — powstała decyzja, kontrakt lub dokument. Nie jest to działająca funkcja.
- **Szkielet fazy 0** — istnieją lub są przygotowywane katalogi/pliki startowe; lokalną poprawność należy potwierdzić walidatorem.
- **Planowane** — implementacja i dowód działania są pracą przyszłych faz.
- **PHASE 1: ukończona** — fundament przeszedł testy jednostkowe, integrację rzeczywistych usług i start Compose; status dotyczy tylko zakresu fazy 1.
- **PHASE 2: ukończona** — trwałe ingestion i odzyskiwanie przeszły regresję na rzeczywistych usługach; normalizacja i detekcje pozostają kolejnymi fazami.
- **PHASE 3: ukończona** — sześć parserów, trwałe snapshoty i wyszukiwanie w ClickHouse potwierdzone testami; UI i dalsze adnotacje pozostają osobnym zakresem.
- **Wymóg procesu** — zasada obowiązuje od początku, ale jej zastosowanie musi być potwierdzane w każdym przyroście.

Na tym etapie **żaden status w macierzy nie oznacza ukończenia działającej platformy**. Dotyczy to również obecności workflow: konfiguracja CI i rzeczywisty zielony przebieg na zdalnym repozytorium są odrębnymi dowodami. Po realizacji należy uzupełnić wiersze o konkretne pliki, testy, komendy i identyfikator zweryfikowanej wersji.

## Pokrycie wymagań 1–37

| Nr | Wymaganie | Fazy odpowiedzialne | Artefakty i kryterium odbioru | Aktualny status |
| --- | --- | --- | --- | --- |
| 1 | Architektura production-like | 0, 1; integracja 13, 15 | `docs/architecture.md`, ADR, modularny backend FastAPI/Pydantic/SQLAlchemy, frontend React/TS/Vite, PostgreSQL, ClickHouse, Redis/Celery i Compose. Każdy komponent ma odpowiedzialność i uzasadnienie; uruchomienie, migracje i przepływ między procesami mają test integracyjny. | PHASE 0–3 zweryfikowane; początkowy panel React/TS/Vite i alerty istnieją, pełna platforma pozostaje otwarta |
| 2 | Log ingestion | 2, 3, 14 | `/api/v1/events` single/batch, RawEvent, durable inbox/outbox, status i retry. Obsługiwane Linux auth.log, SSH, sudo, Windows authentication/process, firewall, nginx i generic JSON. Kontrakt obejmuje timestamp, event_id, source/source_type, hostname, username, source/destination IP/port, process_name, command_line, action/result, raw_event i normalized fields. Test akceptacji potwierdza trwałość, limity i idempotencję. | PHASE 2 ingestion i PHASE 3 parsery/projekcja zweryfikowane; generator pozostaje fazą 14 |
| 3 | Normalization Engine | 0, 3 | Wersjonowany uproszczony schemat inspirowany ECS/OpenTelemetry; `RawEvent → Parser → NormalizedSecurityEvent`, rejestr parserów, golden fixtures, pochodzenie i wersja parsera. Każde źródło przechodzi pozytywne i negatywne przypadki; brakujące pola nie są wymyślane. | PHASE 3 ukończona 2026-10-01: sześć parserów, 75 unit i 13 golden fixtures; raw → snapshot → search potwierdzony w rzeczywistych bazach |
| 4 | Event Search | 3; rozszerzenia 4, 8, 11, 13 | Ograniczony query builder/AST i parametryzowane query API; filtry time, user, IP, hostname, process, severity, event type, source, MITRE technique i detection rule. Testy sprawdzają wynik w rzeczywistym ClickHouse, limity, paginację, deduplikację i odrzucenie injection. UI udostępnia działający Event Explorer. | PHASE 3 API/search zweryfikowane; wczesny Event Explorer i dowody istnieją; MITRE/rule annotations pozostają dalszym zakresem |
| 5 | Detection Engine | 4, 14, 17 | Single-event, threshold, time-window, sequence i correlation detections; reguły brute force ≥10/5 min, sukces po porażkach, escalation, suspicious PowerShell, new admin. Wersjonowane wyniki i trwały stan; fixtures sprawdzają granice czasu/liczników, benign input, restart i replay. | Częściowy przyrost: trzy stałe reguły single-event, trwały checkpoint i dowód; threshold/window/sequence/correlation/Sigma pozostają planowane |
| 6 | Sigma | 4, 13, 18 | Import YAML, walidacja, magazyn reguł i kompilator do wewnętrznego modelu; jawna specyfikacja wspieranego subsetu. Nieobsługiwana konstrukcja daje błąd; alert wskazuje regułę i wersję. Testy pozytywne/negatywne i bezpieczny parser YAML. | Planowane |
| 7 | MITRE ATT&CK | Metadane 4; katalog/chain 8; UI 13 | Lokalny wersjonowany katalog tactic/technique/ID, walidacja mapowań, snapshoty i attack chain incydentu. Testy obejmują sub-techniques, nieznane ID i zgodność chain z dowodami. Runtime demo nie wymaga pobierania katalogu. | Planowane |
| 8 | Event Correlation | 6, 7, 14 | Deterministyczne grupowanie według user/host/IP/time/MITRE/rules, trwałe członkostwo i powód łączenia. Attack chain daje jeden incydent; niezależne konta za NAT i aktywność poza oknem nie są automatycznie sklejane. Testy concurrency/replay. | Planowane |
| 9 | Attack Storyline Engine | 7, 8, 9, 13 | Chronologiczna projekcja eventów i działań analityka, MITRE chain i wersjonowany risk breakdown w investigation. Każdy wpis prowadzi do źródłowego dowodu; test sprawdza kolejność, spóźnione eventy i brak nieudokumentowanych faktów. | Planowane |
| 10 | Risk Engine | 9; IOC 10; UI 13 | Deterministyczny wynik 0–100 z severity, confidence, asset criticality, IOC, liczby alertów, MITRE, previous activity i privileges; snapshot wejść, wkłady i wersja algorytmu. Testy granic, deduplikacji i odtwarzalności; `docs/risk-engine.md`. | Planowane |
| 11 | Incident Management | 7, 9, 13 | ID/title/description/severity/risk/status/owner/timestamps, linked alerts/events, MITRE/IOC, notes/timeline/evidence. Stany New, Triaged, Investigating, Contained, Resolved, False Positive z kontrolą przejść. API i UI przechodzą pełny cykl obsługi. | Planowane |
| 12 | Case Management | 7, 13 | Przypisanie, notatki, status, false positive, evidence, IOC i komentarze; każda mutacja zapisuje audit event. Testy RBAC, współbieżnej edycji, kompletności audytu i bezpiecznego pobierania dowodów. | Planowane |
| 13 | Threat Intelligence | 10, 13, 14 | Lokalny IOC CRUD/import dla IP/domain/URL/hash z value/type/source/confidence/severity/tags/first_seen/last_seen/description. Dopasowania eventów mają dowód i wpływ na detekcję/ryzyko. Adaptery przyszłych dostawców nie wymagają kluczy ani wywołań zewnętrznych w MVP. | Planowane |
| 14 | Threat Hunting | 11, 13 | `/hunts`, zapis zapytań/hipotez, bookmarki, investigation z dowodów, szkic reguły i rule-test przed aktywacją. Przykładowe zapytania i `docs/threat-hunting.md`; E2E hunt → investigation → testowana reguła. | Planowane |
| 15 | SOAR | 12, 13, 14 | Wersjonowane playbooki i kroki waiting/running/completed/failed, trwałe run history, retry/timeout. Brute Force Response wykonuje enrich_ip, IOC check, calculate_risk, create_incident i wewnętrzne notify_analyst. Akcje infrastrukturalne zawsze symulowane; restart nie powtarza skutku biznesowego. | Polityka symulacji projektowana w fazie 0; silnik planowany |
| 16 | SOC Dashboard | 13, 15 | Widoki Overview, Alerts, Incidents, Investigation, Hunting, Rules, TI, SOAR, Event Explorer, Health, Audit. Overview: alerts/24h, incidents/critical, EPS, top rules/IP/accounts, severity/MITRE distribution. Przeglądarkowe testy odczytu rzeczywistego API i stanów błędu. | Wczesny panel realnego API: przegląd, zdarzenia, alerty, reguły, źródła i status; pełny zakres PHASE 13 pozostaje otwarty |
| 17 | SOC Metrics | Timestampy 5, 7; implementacja 15 | MTTD, MTTA, MTTR, false positive rate, alerts/day, incidents/day, top/noisy rules, jawne kohorty i mianowniki. Testy znanych timestampów, brakujących danych i reopen. UI pokazuje brak danych bez fikcyjnego zera. | Planowane |
| 18 | Detection Quality | 4, 13 | Metadane name/description/severity/confidence/MITRE/false positive guidance/references/author/version/enabled/created_at/updated_at; kontrolowana zmiana enabled i audyt. Test wersjonowania i zachowania snapshotu po edycji. | Częściowy katalog trzech reguł: snapshot wersji, metadata, guidance, references i audited enabled; pełny CRUD/Sigma pozostają planowane |
| 19 | Rule Testing | 4, 13, 17 | Izolowany endpoint testu given events/expected alerts, fixtures istotnych reguł i regression suite w CI. Test nie modyfikuje aktywnych okien detekcji, rzeczywistych alertów ani SOAR. UI przedstawia wynik i różnicę oczekiwań. | Czyste API i UI testu trzech wbudowanych reguł, 69 regression unit; pełny authoring i expected-alert diff pozostają dalszym zakresem |
| 20 | Alert Explainability | 5; uzupełnienia 8–10, 13 | Szczegół alertu odpowiada WHAT/WHY/WHEN/WHERE/WHO, rule/version, contributed events, MITRE i wkłady risk score. Niezmienne dowody pozostają dostępne zgodnie z retencją dowodów po usunięciu eventów z archiwum. Test odtworzenia wyjaśnienia historycznego. | Działające alerty z powodem, wersją reguły i niezmiennym normalized/raw snapshot; brak risk, incident chain i retencji |
| 21 | RBAC | 1, każda faza API; audyt 16–17 | Admin, SOC Manager, SOC Analyst, Read Only, serwerowa macierz permissions i kontrola obiektów/akcji. Każdy endpoint i operacja w tle mają właściwy kontekst autoryzacji; testy dozwolonej i zabronionej akcji dla ról. Ukrycie przycisku nie zastępuje kontroli backendu. | RBAC backendu alertów/reguł potwierdzone integracją; panel filtruje kontrolki według aktualnych permissions |
| 22 | Audit Log | 1; rozszerzenia 4, 7, 12; UI 13; przegląd 16 | Append-only z perspektywy zwykłego użytkownika, aktor/czas/request ID i zmiana: login, incident, rule, playbook creation/run, user. Transakcje domenowe i audyt nie rozchodzą się; odmowa usuwania/edycji przez role aplikacyjne ma test. | PHASE 1 ukończona: zapis, API odczytu, rollback i granty audytu potwierdzone integracją; dalsze moduły/UI planowane |
| 23 | Demo Data | 14; fixtures od 3 | Generator benign activity i siedmiu wymaganych scenariuszy, seed/run ID i oczekiwane wyniki. Emisja wyłącznie przez ingestion; alertów/incydentów nie seeduje się. Pełny E2E potwierdza wyniki, powtarzalność i działanie bez zewnętrznej infrastruktury. | Planowane |
| 24 | Security | 1 i każda faza; przegląd 16 | Hashing, bezpieczne JWT/refresh, input validation, rate limits, headers, env secrets, brak stałych haseł, injection protection, RBAC i secure errors. Negatywne API tests, secret/dependency scanning i udokumentowany threat model. | PHASE 1 ukończona: auth/config/limits/errors zweryfikowane; zabezpieczenia przyszłych modułów i przegląd końcowy otwarte |
| 25 | Testy | Od 1; konsolidacja 17 | Unit, integration, API, detection rule, correlation, risk, RBAC oraz E2E od UI; uzasadnione progi coverage po pomiarze. Realne PostgreSQL/ClickHouse w testach integracyjnych, scenariusze awarii i replay. Faza 0 waliduje wyłącznie dokumentację/szkielet. | 747 passed pełnej regresji backendu i 22 passed końcowej regresji alertów (748 różnych backend tests); coverage 91%; 12 frontend unit/component passed; browser proof raportowany osobno |
| 26 | CI/CD | Bootstrap 0; testy od 1; komplet 19 | GitHub Actions: lint/format/typy/tests/security/Docker build, scanning i wymagane status checks. Dowodem ukończenia jest zielony przebieg hostowanego CI i sprawdzona blokada PR przy czerwonych podstawowych testach. Plik workflow to tylko konfiguracja. | Workflow backendu quality/integration istnieje; hostowane CI niezweryfikowane |
| 27 | Observability | Fundament 1; rozszerzenia 2–12; pełny zakres 15 | `/health`, `/ready`, chronione `/metrics`, logi JSON i request/correlation IDs; events processed, alerts generated, latency, failed events, playbook executions. Test awarii zależności i zgodności metryk z wykonaniem; brak tokenów w logach. | PHASE 1 ukończona: sondy, metrics i logi JSON zweryfikowane; metryki domenowe planowane |
| 28 | Dokumentacja | 0 i każda faza; komplet 18 | README: opis, stack, diagram, instalacja/Docker/demo/scenariusze/detekcje/API/security/roadmap i prawdziwe screenshots; osiem wymaganych dokumentów domenowych. Czysty start według instrukcji i kontrola zgodności z kodem. | Dokumentacja i odtworzony start PHASE 1 potwierdzone; dokumentacja pełnej platformy i screenshots planowane |
| 29 | Architecture Diagram | 0; aktualizacje 1–18 | Mermaid pokazuje Sources → Ingestion → Parser/Normalization → Event Storage → Detection → Correlation → Risk → Alert/Incident → SOAR; diagram i opis rozróżniają logiczną analizę oraz fizyczną trwałość, retry i aktualizacje ocen. Zgodność z rzeczywistą implementacją w audycie. | Projektowane w fazie 0 |
| 30 | API | 1–12, 15; UI 13 | `/api/v1/` z `/auth`, `/events`, `/alerts`, `/incidents`, `/detections`, `/hunts`, `/iocs`, `/playbooks`, `/users`, `/audit`, `/metrics`; OpenAPI, RBAC, walidacja, paginacja/limity i spójne błędy. Osobne techniczne `/metrics` eksportuje telemetrię. Każdy zasób ma test API i integrację UI, gdy jest widokiem użytkownika. | PHASE 1 ukończona: auth/users/audit/system health i OpenAPI zweryfikowane; pozostałe zasoby/UI planowane |
| 31 | Database | 1 i każda zmiana modelu; kontrola 19 | Alembic dla PostgreSQL, wersjonowane migracje ClickHouse; migracje pustej i istniejącej bazy oraz strategia rollback/backup dla zmian danych. Brak `create_all` jako głównej migracji wdrożeniowej. | Migracje PostgreSQL 0001–0004 i dwie ClickHouse; granty immutable evidence i zgodność schematu potwierdzone |
| 32 | Code Quality | 0–20 | Granice modułów, typy, dependency injection tam, gdzie potrzebne, małe funkcje i lint/type checks; review pod kątem God Classes, secrets, martwego kodu i pozornych implementacji TODO. Szkielet jawnie odróżniony od działającego kodu. | Wymóg procesu; kod i testy PHASE 1 zweryfikowane; dokładne kontrole w raporcie walidacji |
| 33 | UX | 13, 18, 20 | Dark mode, priorytet czytelności, jasny kontekst ryzyka i nawigacja Alert → Events → User → Host → IOC → Incident; dostępność klawiatury/kontrast, filtry, loading/empty/error. Test przeglądarkowy zadania analityka na rzeczywistych danych. | Wczesny panel: dark mode, klawiatura, filtry, error/loading/empty, dowody alertu; pełny przebieg incident/IOC/risk czeka na dalsze moduły |
| 34 | Senior-level elements | 0–20 | ADR z trade-offami, failure model, trwały pipeline, detekcje/regresja, korelacja, IR, hunting, TI, SOAR, observability i secure SDLC. Prezentacja 30–60 min opiera się na działających scenariuszach i decyzjach, nie na liczbie technologii. | ADR, model awarii i fundament PHASE 1 zweryfikowane; pełny pipeline i demo planowane |
| 35 | Implementation Strategy | 0–20 | Dokładnie fazy 0–20, mniejsze zadania, jawne zależności i kryteria w `implementation-plan.md`; każdą zamyka test/lint/integracja/poprawki/dokumentacja/Conventional Commit. Nie przechodzimy dalej z uszkodzoną poprzednią fazą. | PHASE 0–3 ukończone; jawny częściowy przyrost 4/5/13 zgodnie z ADR; pozostałe pełne fazy i ich bramki otwarte |
| 36 | Git | 0–20 | Conventional Commits, logiczny zakres zmian, kontrola diff i brak force push. Stan Git i tożsamość autora ustalone z rzeczywistego środowiska; brakujące ustawienia nie są zgadywane. Historia commitów jest dowodem realizacji, nie obietnicą. | Wymóg procesu; commit PHASE 0 istnieje; stan przyrostu PHASE 1 w raporcie walidacji |
| 37 | Definition of Done | 20; dowody z 1–19 | Pełny checklist poniżej, wynik każdego punktu poparty testem, komendą, widokiem lub identyfikatorem CI dla audytowanej wersji. Żaden otwarty punkt nie może być zastąpiony samą dokumentacją lub mockupem. | Otwarte: fundament backendu istnieje, pełna platforma pozostaje nieukończona |

## Pełne Definition of Done — jeszcze niepotwierdzone

Każdy poniższy punkt pozostaje otwarty do czasu implementacji i zapisania dowodu. Zaznaczenie pola wymaga sprawdzenia działającego systemu, a nie tylko istnienia pliku o właściwej nazwie.

| Kryterium z wymagania 37 | Faza dostarczająca | Wymagany dowód końcowy | Stan |
| --- | --- | --- | --- |
| Uruchomienie przez Docker Compose | 1, 13–14, 19 | Czysty start całego zestawu, migracje i readiness zgodnie z README | Otwarte dla pełnej platformy; świeży stos PHASE 1 przeszedł |
| Użytkownik może się zalogować | 1, 13 | API i przeglądarkowy test login/refresh/logout | API PHASE 1 potwierdzone; UI/E2E przeglądarkowe otwarte |
| Generator tworzy eventy | 14 | Zapis odpowiedzi ingestion oraz run ID wszystkich scenariuszy | Otwarte |
| Eventy przechodzą normalizację | 3, 14 | Eventy źródłowe mają wyszukiwalne odpowiedniki w wspólnym schemacie | Otwarte |
| Detection Engine generuje prawdziwe alerty | 4–5, 14 | Given events/expected alerts i E2E z identyfikatorami dowodów | Otwarte |
| Alerty są korelowane | 6, 14 | Dodatni attack chain oraz negatywny test niezależnych encji | Otwarte |
| Powstają incydenty | 7, 14 | Idempotentne powiązanie grupy z incydentem i historia case | Otwarte |
| Widoczny jest MITRE ATT&CK mapping | 8, 13 | Walidowane techniki reguły/alertu/chain widoczne w UI | Otwarte |
| Działa risk scoring | 9–10, 13 | Powtarzalny wynik, snapshot czynników i widoczne wyjaśnienie | Otwarte |
| Działa Threat Intelligence | 10, 13–14 | Lokalny IOC jest dopasowany przez pipeline i widoczny w wyniku | Otwarte |
| Działa Threat Hunting | 11, 13 | Zapisany hunt → eventy → investigation → przetestowany szkic reguły | Otwarte |
| Działa Playbook Engine | 12–14 | Trwała historia rzeczywistego wykonania, recovery i jawna symulacja infrastruktury | Otwarte |
| Frontend pobiera prawdziwe dane z API | 13 | E2E widoków i mutacji bez produkcyjnych tablic mock | Otwarte |
| RBAC działa | 1, każda faza, 16–17 | Dozwolone i zabronione operacje wszystkich ról sprawdzone na serwerze | Zakres PHASE 1 potwierdzony; przyszłe moduły i audyt końcowy otwarte |
| Audit log działa | 1, 4, 7, 12, 16 | Wymagane operacje pozostawiają wpis; zwykły użytkownik nie edytuje historii | Zakres PHASE 1 potwierdzony; audyt przyszłych operacji otwarty |
| Testy są zielone | Każda faza; komplet 17, 20 | Komendy i wyniki pełnego zestawu dla końcowej wersji | 230 unit i 33 integration PHASE 1 przeszły; pełna platforma otwarta |
| CI jest zielone | 19 | Faktyczny hostowany przebieg i wymagane kontrole PR dla tej samej wersji | Otwarte |
| Dokumentacja jest kompletna | 18 | Weryfikacja wymaganych dokumentów i odtworzenie instrukcji | Zakres PHASE 1 potwierdzony; pełna dokumentacja otwarta |
| Demo działa bez zewnętrznych usług | 14, 20 | Pełny runtime bez zewnętrznych API i prawdziwej infrastruktury po przygotowaniu obrazów/zależności | Otwarte |

## Dowody i zakres fazy 0

W fazie 0 można potwierdzić raport stanu, architekturę, ADR, diagram, strukturę, plan i pokrycie wszystkich wymagań. Polecenie `py scripts/validate_repository.py` lokalnie lub `python scripts/validate_repository.py` w CI kontroluje ten przyrost. Nie dostarcza dowodu działania auth, baz, pipeline, Docker runtime ani zdalnego GitHub Actions.

Wyniki uruchomionych kontroli oraz stan commita należy czytać w raporcie fazy 0. Po ukończeniu każdej dalszej fazy odpowiednie wiersze tej macierzy trzeba uaktualnić z „Planowane” na konkretny status wdrożenia i weryfikacji; nie wolno automatycznie oznaczać całego wielofazowego wymagania jako ukończonego po dostarczeniu jednego z jego elementów.

## Dowody zamknięcia PHASE 1 — 2026-09-28

- Python 3.12.14: zgodna wersja lokalnego interpretera, obrazów API/testów i konfiguracji
  CI; uzasadnienie oraz historyczny wynik z 2026-09-26 w
  [ADR 0001](adr/0001-modular-monolith.md).
- Kod fundamentu: `backend/app/main.py`, `backend/app/api/auth.py`,
  `backend/app/api/users.py`, `backend/app/api/audit.py`, `backend/app/core/permissions.py`,
  `backend/app/api/health.py`, `backend/app/core/observability.py` i `backend/app/worker.py`.
  Zakres fazy 1 nie zamyka wielofazowych wymagań powyżej.
- Build obrazów API i testów na Linux/Python 3.12.14 przeszedł.
  `docker compose up -d --wait` uruchomiło świeży stos: PostgreSQL, Redis i ClickHouse
  osiągnęły healthy, a migrator zakończył się exit 0. Migrację `0001_foundation`,
  zgodność modeli, granty runtime oraz rollback przy błędzie audytu pokrywa
  `backend/tests/integration/test_storage.py`.
- Zależności: instalacja `backend/requirements-dev.lock` z `--require-hashes`
  przeszła; `python -m pip check` nie wykazał konfliktów. Audyt runtime lock
  z `--strict --require-hashes` nie wykazał znanych podatności (2026-09-28).
  Piny współdzielone przez runtime i dev lockfile są zgodne.
- Testy z katalogu `backend`: `python -m pytest -m "not integration" -p no:cacheprovider --cov=app`
  dały **230 passed in 16.40s**, coverage **65%**. Dotyczy to `test_config.py`,
  `test_health.py`, `test_http.py`, `test_permissions.py`, `test_rate_limit.py`
  i `test_security.py` w `tests/unit`.
- Osobny przebieg integracyjny w obrazie testów dał **33 passed, 230 deselected
  in 32.30s**, coverage **82%**, z rzeczywistymi PostgreSQL, Redis, ClickHouse
  i Celery. Pliki `backend/tests/integration/test_auth.py`, `test_users.py`,
  `test_storage.py`, `test_infrastructure.py` i `test_concurrency.py` obejmują
  sesje/CSRF, role, trwałość, sondy, brokera i równoczesne zmiany konta/refresh.
  Wartości coverage 65% i 82% pochodzą z odrębnych przebiegów; nie są łącznym wynikiem.
- Kontrolowane przywrócenie starej blokady `FOR UPDATE` odtworzyło odpowiedź 503;
  test współbieżności wykrył regresję. Poprawiona blokada przeszła integrację.
- Próby przez rzeczywisty proxy: `/health` 200, `/ready` 200, `/metrics` 404,
  `/api/v1/openapi.json` 200 i nieuwierzytelnione `/api/v1/users` 401.
  Zadanie `aegis.ping` przeszło przez rzeczywisty broker, worker i backend wyników.
- `.github/workflows/backend.yml` istnieje, ale brak zdalnego repozytorium
  i przebiegu GitHub Actions oznacza nadal niezweryfikowane hostowane CI.

**Historyczny dowód PHASE 1 zachowuje [raport PHASE 1](validation-phase1.md).** Bieżąca PHASE 2 jest ukończona. Nie ma jeszcze frontendu,
normalizacji, detekcji ani pełnego demo. Polecenia odtworzenia środowiska i testów
zawiera [instrukcja operacyjna PHASE 1](phase1-operations.md), a dokładne wyniki
oraz identyfikator wersji zapisuje [raport walidacji](validation.md).

## Przyrost PHASE 2

Kontrakt i procedury operatora: [phase2-operations.md](phase2-operations.md).
Kod: `backend/app/modules/ingestion`, `backend/app/api/events.py`,
`backend/app/api/sources.py`, `backend/app/relay.py` i migracja `0002_ingestion`.
Testy `test_ingestion_api.py`, `test_ingestion_processing.py` oraz
`test_ingestion_celery.py` sprawdzają atomowość, role, deduplikację, ograniczenia,
wyścigi, utratę publikacji, ponowienie i kwarantannę. Aktualne wyniki wykonania
podaje [raport walidacji](validation.md): **454 passed** we wspólnym przebiegu
341 unit i 113 integracji, coverage 91% procesu testowego. Dodatkowy
`test_ingestion_deployed.py` sprawdza rzeczywiste HTTP, relay, prefork worker
i wznowienie po jego zatrzymaniu. `test_app.py` wykrywa wyścig inicjalizacji
schematów; 30 powtórzeń współbieżnego admission potwierdziło poprawkę.
