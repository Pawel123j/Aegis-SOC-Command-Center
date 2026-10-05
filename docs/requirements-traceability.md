# Macierz wymagań i dowodów

Macierz zachowuje numerację 1–37 z wymagań użytkownika. Łączy każdy punkt z fazą, planowanym artefaktem i obserwowalnym kryterium odbioru. Rozwinięcie zadań, zależności i testów znajduje się w [planie implementacji](implementation-plan.md). Źródłem informacji o stanie zastanym jest [raport aktualnego stanu](current-state-report.md).

## Znaczenie statusów

- **Projektowane w fazie 0** — powstała decyzja, kontrakt lub dokument. Nie jest to działająca funkcja.
- **Szkielet fazy 0** — istnieją lub są przygotowywane katalogi/pliki startowe; lokalną poprawność należy potwierdzić walidatorem.
- **Planowane** — implementacja i dowód działania są pracą przyszłych faz.
- **PHASE 1: ukończona** — fundament przeszedł testy jednostkowe, integrację rzeczywistych usług i start Compose; status dotyczy tylko zakresu fazy 1.
- **PHASE 2: ukończona** — trwałe ingestion i odzyskiwanie przeszły regresję na rzeczywistych usługach; normalizacja i detekcje pozostają kolejnymi fazami.
- **PHASE 3: ukończona** — sześć parserów, trwałe snapshoty i wyszukiwanie w ClickHouse potwierdzone testami; UI i dalsze adnotacje pozostają osobnym zakresem.
- **Etap 7: ukończony lokalnie** — lokalne IOC i dopasowania mają kod/API/UI; 1966 testów backendu i 206 panelu PASS, migracje/start/restart sprawdzone. Zalogowany browser E2E, online audit i hostowane CI pozostają otwarte.
- **Wymóg procesu** — zasada obowiązuje od początku, ale jej zastosowanie musi być potwierdzane w każdym przyroście.

Na tym etapie **żaden status w macierzy nie oznacza ukończenia działającej platformy**. Dotyczy to również obecności workflow: konfiguracja CI i rzeczywisty zielony przebieg na zdalnym repozytorium są odrębnymi dowodami. Po realizacji należy uzupełnić wiersze o konkretne pliki, testy, komendy i identyfikator zweryfikowanej wersji.

## Pokrycie wymagań 1–37

| Nr | Wymaganie | Fazy odpowiedzialne | Artefakty i kryterium odbioru | Aktualny status |
| --- | --- | --- | --- | --- |
| 1 | Architektura production-like | 0, 1; integracja 13, 15 | `docs/architecture.md`, ADR, modularny backend FastAPI/Pydantic/SQLAlchemy, frontend React/TS/Vite, PostgreSQL, ClickHouse, Redis/Celery i Compose. Każdy komponent ma odpowiedzialność i uzasadnienie; uruchomienie, migracje i przepływ między procesami mają test integracyjny. | PHASE 0–3 zweryfikowane; początkowy panel React/TS/Vite i alerty istnieją, pełna platforma pozostaje otwarta |
| 2 | Log ingestion | 2, 3, 14 | `/api/v1/events` single/batch, RawEvent, durable inbox/outbox, status i retry. Obsługiwane Linux auth.log, SSH, sudo, Windows authentication/process, firewall, nginx i generic JSON. Kontrakt obejmuje timestamp, event_id, source/source_type, hostname, username, source/destination IP/port, process_name, command_line, action/result, raw_event i normalized fields. Test akceptacji potwierdza trwałość, limity i idempotencję. | PHASE 2 ingestion i PHASE 3 parsery/projekcja zweryfikowane; generator pozostaje fazą 14 |
| 3 | Normalization Engine | 0, 3 | Wersjonowany uproszczony schemat inspirowany ECS/OpenTelemetry; `RawEvent → Parser → NormalizedSecurityEvent`, rejestr parserów, golden fixtures, pochodzenie i wersja parsera. Każde źródło przechodzi pozytywne i negatywne przypadki; brakujące pola nie są wymyślane. | PHASE 3 ukończona 2026-10-01: sześć parserów, 75 unit i 13 golden fixtures; raw → snapshot → search potwierdzony w rzeczywistych bazach |
| 4 | Event Search | 3; rozszerzenia 4, 8, 11, 13 | Ograniczony query builder/AST i parametryzowane query API; filtry time, user, IP, hostname, process, severity, event type, source, MITRE technique i detection rule. Testy sprawdzają wynik w rzeczywistym ClickHouse, limity, paginację, deduplikację i odrzucenie injection. UI udostępnia działający Event Explorer. | PHASE 3 API/search zweryfikowane; wczesny Event Explorer i dowody istnieją; MITRE/rule annotations pozostają dalszym zakresem |
| 5 | Detection Engine | 4, 14, 17 | Single-event, threshold, time-window, sequence i correlation detections; reguły brute force ≥10/5 min, sukces po porażkach, escalation, suspicious PowerShell, new admin. Wersjonowane wyniki i trwały stan; fixtures sprawdzają granice czasu/liczników, benign input, restart i replay. | Trzy single-event i pięć reguł korelacji Etapu 2, trwały checkpoint/watermark; Sigma Etapu 5: import i wykonanie. Etap 7 dodaje medium ti:malicious-indicator z oryginalnym match proof; końcowa regresja i lokalne uruchomienie PASS w raporcie TI |
| 6 | Sigma | 4, 13, 18 | Import YAML, walidacja, magazyn reguł i kompilator do wewnętrznego modelu; jawna specyfikacja wspieranego subsetu. Nieobsługiwana konstrukcja daje błąd; alert wskazuje regułę i wersję. Testy pozytywne/negatywne i bezpieczny parser YAML. | Etap 5: ograniczony parser/AST, append-only rewizje, publikacja i test, API/UI, dowody alertu i pochodzenie ryzyka; validation-sigma.md |
| 7 | MITRE ATT&CK | Metadane 4; katalog/chain 8; UI 13 | Lokalny wersjonowany katalog tactic/technique/ID, walidacja mapowań, snapshoty i attack chain incydentu. Testy obejmują sub-techniques, nieznane ID i zgodność chain z dowodami. Runtime demo nie wymaga pobierania katalogu. | Etap 4: lokalny katalog 19.2, walidacja ID/relacji/hash, niezmienne nowe mapowania, nazwy i coverage API/UI; pełny graf/chain oraz event-search annotations pozostają przyszłe |
| 8 | Event Correlation | 6, 7, 14 | Deterministyczne grupowanie według user/host/IP/time/MITRE/rules, trwałe członkostwo i powód łączenia. Attack chain daje jeden incydent; niezależne konta za NAT i aktywność poza oknem nie są automatycznie sklejane. Testy concurrency/replay. | Etap 2: jawne threshold/sequence, AND/OR, silne encje, wiele dowodów i automatyczna sprawa High/Critical; pełny graf/merge/reconstruct pozostają przyszłe |
| 9 | Attack Storyline Engine | 7, 8, 9, 13 | Chronologiczna projekcja eventów i działań analityka, MITRE chain i wersjonowany risk breakdown w investigation. Każdy wpis prowadzi do źródłowego dowodu; test sprawdza kolejność, spóźnione eventy i brak nieudokumentowanych faktów. | Oś pracy incydentu, chronologiczne dowody alertu i risk breakdown Etapu 3; pełna storyline/graf pozostają planowane |
| 10 | Risk Engine | 9; IOC 10; UI 13 | Deterministyczny wynik 0–100 z severity, confidence, asset criticality, IOC, liczby alertów, MITRE, previous activity i privileges; snapshot wejść, wkłady i wersja algorytmu. Testy granic, deduplikacji i odtwarzalności; `docs/risk-engine.md`. | Etapy 3/5: wersjonowane 0–100, niezmienne obliczenia i v3. Etap 7 dodaje v4 z maksymalnym I=15 (malicious słabe/nieznane confidence: 5), TI D30/C/E0; brak TI zachowuje v3, pozostały kontekst unknown; validation-intelligence.md: regresja i lokalne wdrożenie PASS |
| 11 | Incident Management | Etap 1; oceny 3, IOC 7 nowego planu | ID/title/description/severity/risk/status/owner/timestamps, linked alerts/events, MITRE/IOC, notes/timeline/evidence. Aktualne stany użytkownika: New, Investigating, Contained, Resolved, Closed z kontrolą przejść. | Etap 1: modele/API/panel spraw; Etap 3: odrębny score i historia. Etap 7 wzbogaca ocenę aktywnych dowodów o zachowane IOC; medium TI nie tworzy automatycznie sprawy, confidence detekcji nieznane; osobne incident_iocs przyszłe |
| 12 | Case Management | Etap 1, dalsze IOC/reporting | Przypisanie, notatki, status, evidence, IOC i komentarze; każda mutacja zapisuje audit event. Testy RBAC, współbieżnej edycji, audytu i dowodów. | API i panel incydentów, If-Match, właściciel, tagi i append-only notes/timeline. Zachowane IOC są dowodem powiązanego alertu Etapu 7; ręczne incident_iocs/verdict/retencja pozostają przyszłe |
| 13 | Threat Intelligence | 10, 13, 14 | Lokalny IOC IP/domain/URL/hash z value/type/source/confidence/reputation/tags/first_seen/last_seen/description; niezmienne rewizje i dopasowania wpływają na detekcję/ryzyko. Adapter przyszłych dostawców bez wywołań zewnętrznych. | Etap 7: kanoniczny lokalny katalog/API/UI, rewizje i atomowy import, receipts także zero matches, exact typed field proof, medium TI i opt-in risk v4. Reputacja/confidence to deklaracja źródła, provider wyłącznie lokalny; lokalna bramka w validation-intelligence.md PASS; browser E2E/online audit/hostowane CI otwarte |
| 14 | Threat Hunting | 11, 13 | `/hunts`, zapis zapytań/hipotez, bookmarki, investigation z dowodów, szkic reguły i rule-test przed aktywacją. Przykładowe zapytania i `docs/threat-hunting.md`; E2E hunt → investigation → testowana reguła. | Planowane |
| 15 | SOAR | 12, 13, 14 | Wersjonowane playbooki i kroki waiting/running/completed/failed, trwałe run history, retry/timeout. Brute Force Response wykonuje enrich_ip, IOC check, calculate_risk, create_incident i wewnętrzne notify_analyst. Akcje infrastrukturalne zawsze symulowane; restart nie powtarza skutku biznesowego. | Polityka symulacji projektowana w fazie 0; silnik planowany |
| 16 | SOC Dashboard | 13, 15 | Widoki Overview, Alerts, Incidents, Investigation, Hunting, Rules, TI, SOAR, Event Explorer, Health, Audit. Overview: alerts/24h, incidents/critical, EPS, top rules/IP/accounts, severity/MITRE distribution. Przeglądarkowe testy odczytu rzeczywistego API i stanów błędu. | Panel rzeczywistego API obejmuje MITRE Coverage, profile encji oraz katalog/lookup/historię IOC i event/alert match proof Etapu 7; pełne dashboard aggregates i zalogowany browser proof przyszłe |
| 17 | SOC Metrics | Timestampy 5, 7; implementacja 15 | MTTD, MTTA, MTTR, false positive rate, alerts/day, incidents/day, top/noisy rules, jawne kohorty i mianowniki. Testy znanych timestampów, brakujących danych i reopen. UI pokazuje brak danych bez fikcyjnego zera. | Planowane |
| 18 | Detection Quality | 4, 13 | Metadane name/description/severity/confidence/MITRE/false positive guidance/references/author/version/enabled/created_at/updated_at; kontrolowana zmiana enabled i audyt. Test wersjonowania i zachowania snapshotu po edycji. | Trzy single-event i pięć correlation rules: immutable metadata/version, walidowane candidate MITRE mappings i audytowany deployment; Sigma Etapu 5 ma kontrolowany import/rewizje/publikację; pozostały natywny CRUD przyszły |
| 19 | Rule Testing | 4, 13, 17 | Izolowany endpoint testu given events/expected alerts, fixtures istotnych reguł i regression suite w CI. Test nie modyfikuje aktywnych okien detekcji, rzeczywistych alertów ani SOAR. UI przedstawia wynik i różnicę oczekiwań. | Czyste API i panel testów single-event/correlation bez efektów domenowych; pełny authoring i expected-alert diff pozostają dalszym zakresem |
| 20 | Alert Explainability | 5; uzupełnienia 8–10, 13 | Szczegół alertu odpowiada WHAT/WHY/WHEN/WHERE/WHO, rule/version, contributed events, MITRE i wkłady risk score. Niezmienne dowody pozostają dostępne zgodnie z retencją dowodów po usunięciu eventów z archiwum. Test odtworzenia wyjaśnienia historycznego. | Alert zachowuje pełne dowody, risk explanation i historyczne MITRE mapping; Etap 7 zachowuje pole, observed/canonical value i oryginalną rewizję/hash IOC. Import nie przepisuje starego dowodu; legacy/retencja mają jawne ograniczenia |
| 21 | RBAC | 1, każda faza API; audyt 16–17 | Admin, SOC Manager, SOC Analyst, Read Only, serwerowa macierz permissions i kontrola obiektów/akcji. Każdy endpoint i operacja w tle mają właściwy kontekst autoryzacji; testy dozwolonej i zabronionej akcji dla ról. Ukrycie przycisku nie zastępuje kontroli backendu. | Serwerowa kontrola alertów/reguł/incydentów; Etap 7: intelligence:read oraz manager/admin intelligence:manage, events:read dla event proof i system:manage dla backfill, ponowna sesja/rola po lock; endpoint propozycji Analyst nie istnieje; lokalna regresja i uruchomienie PASS; granice dowodu w raporcie TI |
| 22 | Audit Log | 1; rozszerzenia 4, 7, 12; UI 13; przegląd 16 | Append-only z perspektywy zwykłego użytkownika, aktor/czas/request ID i zmiana: login, incident, rule, playbook creation/run, user. Transakcje domenowe i audyt nie rozchodzą się; odmowa usuwania/edycji przez role aplikacyjne ma test. | Trwały audyt i ograniczone granty od PHASE 1; Etap 7 atomowo audytuje utworzenie/rewizję IOC oraz administracyjny backfill, błąd wycofuje całą mutację/import. No-op nie dopisuje rewizji; końcowa regresja i lokalne uruchomienie PASS w raporcie TI |
| 23 | Demo Data | 14; fixtures od 3 | Generator benign activity i siedmiu wymaganych scenariuszy, seed/run ID i oczekiwane wyniki. Emisja wyłącznie przez ingestion; alertów/incydentów nie seeduje się. Pełny E2E potwierdza wyniki, powtarzalność i działanie bez zewnętrznej infrastruktury. | Planowane |
| 24 | Security | 1 i każda faza; przegląd 16 | Hashing, bezpieczne JWT/refresh, input validation, rate limits, headers, env secrets, brak stałych haseł, injection protection, RBAC i secure errors. Negatywne API tests, secret/dependency scanning i udokumentowany threat model. | Auth/config/limits/errors od PHASE 1; Etap 7 dodaje ścisłą normalizację, bounded JSON import, parametryzowane literal q i signed cursors, tekstowe URL bez DNS/HTTP, source/hash/scope guards. Finalny raport TI potwierdza kontrole lokalne; audyt zależności online i końcowy przegląd całej platformy pozostają otwarte |
| 25 | Testy | Od 1; konsolidacja 17 | Unit, integration, API, detection rule, correlation, risk, RBAC oraz E2E od UI; uzasadnione progi coverage po pomiarze. Realne PostgreSQL/ClickHouse w testach integracyjnych, scenariusze awarii i replay. Faza 0 waliduje wyłącznie dokumentację/szkielet. | Historyczne wyniki Etapów 1–6 zachowano. Testy Etapu 7 obejmują normalizację, ledger/pipeline/ryzyko, rollback, role, SQL i UI; 1966 backend i 206 panel PASS w validation-intelligence.md; browser proof i hostowane CI odrębne |
| 26 | CI/CD | Bootstrap 0; testy od 1; komplet 19 | GitHub Actions: lint/format/typy/tests/security/Docker build, scanning i wymagane status checks. Dowodem ukończenia jest zielony przebieg hostowanego CI i sprawdzona blokada PR przy czerwonych podstawowych testach. Plik workflow to tylko konfiguracja. | Workflow backendu quality/integration istnieje; hostowane CI niezweryfikowane |
| 27 | Observability | Fundament 1; rozszerzenia 2–12; pełny zakres 15 | `/health`, `/ready`, chronione `/metrics`, logi JSON i request/correlation IDs; events processed, alerts generated, latency, failed events, playbook executions. Test awarii zależności i zgodności metryk z wykonaniem; brak tokenów w logach. | PHASE 1 ukończona: sondy, metrics i logi JSON zweryfikowane; metryki domenowe planowane |
| 28 | Dokumentacja | 0 i każda faza; komplet 18 | README: opis, stack, diagram, instalacja/Docker/demo/scenariusze/detekcje/API/security/roadmap i prawdziwe screenshots; osiem wymaganych dokumentów domenowych. Czysty start według instrukcji i kontrola zgodności z kodem. | Aktualne kontrakty TI/IOC, dane, API, security i risk oraz ADR 0013; validation-intelligence.md zawiera końcową regresję, uruchomienie i granice dowodu. Dokumentacja pełnej platformy i screenshots pozostają przyszłe |
| 29 | Architecture Diagram | 0; aktualizacje 1–18 | Mermaid pokazuje Sources → Ingestion → Parser/Normalization → Event Storage → Detection → Correlation → Risk → Alert/Incident → SOAR; diagram i opis rozróżniają logiczną analizę oraz fizyczną trwałość, retry i aktualizacje ocen. Zgodność z rzeczywistą implementacją w audycie. | Projektowane w fazie 0 |
| 30 | API | 1–12, 15; UI 13 | `/api/v1/` z `/auth`, `/events`, `/alerts`, `/incidents`, `/detections`, `/hunts`, `/iocs`, `/playbooks`, `/users`, `/audit`, `/metrics`; OpenAPI, RBAC, walidacja, paginacja/limity i spójne błędy. Osobne techniczne `/metrics` eksportuje telemetrię. Każdy zasób ma test API i integrację UI, gdy jest widokiem użytkownika. | Auth/users/audit/system/sources/events/search/alerts/detections/incidents/correlations/risk/mitre/sigma/entities oraz /intelligence: 8 ścieżek, 10 metod, RBAC/ETag/limity/history/lookup/backfill; regresja i lokalne wdrożenie TI PASS, przyszłe zasoby otwarte |
| 31 | Database | 1 i każda zmiana modelu; kontrola 19 | Alembic dla PostgreSQL, wersjonowane migracje ClickHouse; migracje pustej i istniejącej bazy oraz strategia rollback/backup dla zmian danych. Brak `create_all` jako głównej migracji wdrożeniowej. | Źródła PostgreSQL 0001–0011, dwie migracje ClickHouse; Etap 7 dodaje cztery tabele IOC/rewizji/receipts/matches, SELECT/INSERT i kontrolowany pointer, deferred completeness i blokadę niepustego downgrade. Końcowy wynik migracji/uruchomienia w raporcie TI |
| 32 | Code Quality | 0–20 | Granice modułów, typy, dependency injection tam, gdzie potrzebne, małe funkcje i lint/type checks; review pod kątem God Classes, secrets, martwego kodu i pozornych implementacji TODO. Szkielet jawnie odróżniony od działającego kodu. | Wymóg procesu; kod i testy PHASE 1 zweryfikowane; dokładne kontrole w raporcie walidacji |
| 33 | UX | 13, 18, 20 | Dark mode, priorytet czytelności, jasny kontekst ryzyka i nawigacja Alert → Events → User → Host → IOC → Incident; dostępność klawiatury/kontrast, filtry, loading/empty/error. Test przeglądarkowy zadania analityka na rzeczywistych danych. | Panel Alert→Incident, MITRE/risk/Sigma i profile encji; Etap 7 dodaje lokalny IOC→historia i event/alert→zachowany match proof, tekstowe URL i konflikt z zachowaniem szkicu. Automatyczna walidacja UI: 206 PASS; zalogowany browser proof otwarty |
| 34 | Senior-level elements | 0–20 | ADR z trade-offami, failure model, trwały pipeline, detekcje/regresja, korelacja, IR, hunting, TI, SOAR, observability i secure SDLC. Prezentacja 30–60 min opiera się na działających scenariuszach i decyzjach, nie na liczbie technologii. | 13 ADR, trwały pipeline i wersjonowane dowody; ADR 0013 uzasadnia local-only IOC i opt-in risk v4 bez przepisywania v3. Lokalna bramka Etapu 7 PASS z ograniczeniami z raportu; pełne demo, hunting i SOAR przyszłe |
| 35 | Implementation Strategy | Historyczne 0–20; bieżące 15 etapów | Historyczny implementation-plan.md i nowy soc-expansion-plan.md; przyrosty z test/lint/integracja/poprawki/dokumentacja/Conventional Commit. | PHASE 0–3 i Etapy 1–6 mają historyczne raporty; Etap 6: 1547 backend + 148 frontend + 31 skryptów PASS. Etap 7: 1966 backend + 206 panel PASS, lokalne migracje/start/restart sprawdzone; validation-intelligence.md, dalszy etap Attack Timeline |
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
| Widoczny jest MITRE ATT&CK mapping | 8, 13 | Walidowane techniki reguły/alertu/chain widoczne w UI | Etap 4: nazwy reguły/nowego alertu i projekcja sprawy, coverage; pełny chain przyszły |
| Działa risk scoring | 9–10, 13 | Powtarzalny wynik, snapshot czynników i widoczne wyjaśnienie | Otwarte |
| Działa Threat Intelligence | 10, 13–14 | Lokalny IOC jest dopasowany przez pipeline i widoczny w wyniku | Etap 7: implementacja lokalnego IOC→event→alert/risk i API/UI; pełna regresja i lokalne uruchomienie PASS, zalogowany browser proof otwarty |
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

## Zakres Etapu 7 — lokalne IOC, 2026-10-05

[Kontrakt](intelligence.md) i [ADR 0013](adr/0013-local-intelligence.md)
łączą wymagania 5, 10–13, 16, 20–25, 28 i 30–35 z implementacją lokalnego
katalogu, rewizji i oryginalnych dopasowań. Katalog ma limit 1000 IOC także
dla wpisów wyłączonych, 50 rewizji i 100 rekordów atomowego importu.

Ekstrakcja czyta wyłącznie source.ip, destination.ip, process.hash, file.hash,
http.url, http.referrer i host poprawnego URL/referrer jako domain albo IP.
Nie interpretuje raw_event, command line, extensions ani host.name; schema
normalized 1.0 nie ma network.domain. Dostępny jest wyłącznie lokalny provider,
bez DNS, pobierania URL i zewnętrznego lookup. Reputacja/confidence pozostają
deklaracją źródła; confidence samej detekcji jest nieznany.

Pierwsza analiza zachowuje receipts także dla zero matches. Import/PATCH nie
zmieniają dawnych dopasowań, alertów ani ocen. Backfill tylko brakujących
receipts nie tworzy historycznych alertów; nowe obliczenie wymaga istniejącej
jawnej operacji risk/recalculate. V4 ma maksymalny I=15, malicious przy niskim
albo nieznanym confidence daje 5, a samo medium TI daje D30 i C/E0. Brak TI
zachowuje niezmienione v3 i oryginalną historię v2/v3.

[Raport Etapu 7](validation-intelligence.md) pozostaje źródłem końcowego wyniku.
Macierz potwierdza lokalną regresję i wdrożenie Etapu 7. Nie oznacza
ukończenia całego wymagania 37; browser E2E, online audit i hostowane CI
pozostają otwarte. Ręczne powiązania incident_iocs, proposals
workflow, zewnętrzne providery, hunting i SOAR pozostają dalszym zakresem.
