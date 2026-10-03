# Walidacja Etapu 3 — Risk Engine

Data: 2026-10-03. Punkt wyjścia: `23e50f3`.
Stan: Etap 3 zaimplementowany i wdrożony; automatyczna regresja zaliczona.
Ręczny test panelu po zalogowaniu pozostaje otwarty. [Plan](soc-expansion-plan.md),
[polityka](risk-engine.md), [ADR 0009](adr/0009-explainable-risk.md).

## 1. Zakres

Osobny deterministyczny kalkulator 0–100, poziomy użytkownika,
jawne wkłady i braki kontekstu. Odrębne oceny alertu i incydentu korzystają
z niezmiennych dowodów. Skorelowane i pojedyncze alerty podlegają tej samej
polityce; incydent nie sumuje ich scores. Overlap tej samej kontrolowanej
rodziny scala jednostki, a event IDs są liczone raz.
Zmiana aktywnych dowodów lub false-positive może obniżyć score.
Historia obliczeń pozostaje dostępna; odczyt nie wykonuje mutacji.

## 2. Dodane pliki

Backend: `app/modules/risk/{__init__,engine,inputs,models,schemas,service}.py`,
`app/api/risk.py`, `migrations/versions/0007_risk.py`,
`tests/unit/test_risk_engine.py`, `tests/integration/test_risk.py`
oraz `tests/integration/test_risk_security.py`.
Frontend: `src/risk/{types,levels,labels}.ts`, `src/risk/risk.css`,
`src/risk/{RiskScore,RiskPanel,RiskExplanation,RiskPolicy,AlertRiskButton}.tsx`,
`tests/risk.test.tsx` oraz `tests/riskFixtures.ts`.
Dokumentacja: ten raport i `adr/0009-explainable-risk.md`.

## 3. Zmienione pliki

Backend: `app/main.py`, `app/api/{alerts,health}.py`,
`app/modules/alerts/{models,schemas}.py`,
`app/modules/incidents/{models,schemas,service,views}.py`,
`app/modules/detections/processing.py`, `app/modules/correlation/persistence.py`
oraz `migrations/env.py`. Istniejące integracje:
`tests/integration/test_{correlations,incidents,incident_security,initial_alerts,storage}.py`.
Panel: `src/{App,Alerts}.tsx`,
`src/incidents/{IncidentAlerts,IncidentDetails,IncidentList,IncidentSummary}.tsx`,
`src/types.ts`, `src/incidents/types.ts`, `tests/incidentFixtures.ts`
oraz `tests/incidents.test.tsx`.
`compose.yaml` używa nowego znacznika tego samego obrazu; brak nowej usługi.
Dokumentacja: główny README, README backendu/frontendu/infra,
`docs/{api-contract,data-model,architecture,risk-engine,implementation-plan,soc-expansion-plan,requirements-traceability,validation}.md`
oraz `docs/adr/README.md`.

## 4. Endpointy

Pod `/api/v1`: GET `/risk/policy`, GET `/alerts/{alert_id}/risk`,
GET `/incidents/{incident_id}/risk`, POST `/risk/backfill`, POST `/risk/test`.
Także POST `/alerts/{alert_id}/risk/recalculate` i
`/incidents/{incident_id}/risk/recalculate` z If-Match i właściwymi prawami.
Historia ma limit 1–50 oraz flagę ograniczenia; backfill jest ograniczony
i administracyjny. Czysty test jest symulacją bez zapisu skutków domenowych.
Listy mają score/level/calculation ID, a szczegóły `risk_explanation`.

## 5. Modele

Append-only `RiskCalculation` zapisuje wersję/hash polityki, input snapshot/hash,
wyjaśnienie, raw/clipping, score i poprzednie obliczenie. Bieżący wynik jest
projekcją konkretnego zapisanego obliczenia. Pola dowodów nie są nadpisywane.
Runtime nie edytuje i nie usuwa historii ani nie aktualizuje score bezpośrednio.
Ograniczona funkcja PostgreSQL sprawdza subject/scope i bieżące dowody.

## 6. Nowe testy

Dodano 110 przypadków backendowych: 34 jednostkowe, 4 podstawowe integracyjne
oraz 72 niezależne integracyjne przypadki bezpieczeństwa.
Testy obejmują ręczną arytmetykę i progi, confidence, deduplikację/overlap,
różne kolejności, brak kontekstu, clipping, wersje i hashe, prawdziwe ingestion,
replay, false-positive/attach/detach, retry, rollback audytu, współbieżność,
zmianę autoryzacji po blokadzie oraz granty i uszkodzony dowód.
Panel sprawdza score/null/zero, rozpisanie punktów i wcześniejsze wyniki,
loading/error/empty i odrzucanie spóźnionych odpowiedzi. Dodano 21 przypadków
frontendowych, w tym zmianę uprawnień w trakcie żądania i nowszą ocenę
otrzymaną podczas odczytu historii.

## 7. Wykonane kontrole

| Kontrola | Wynik |
| --- | --- |
| Skrypty | 23 unittest passed |
| Docker | Engine 29.7.2 przywrócony; dotychczasowa aplikacja uruchomiona przez start zachowanych kontenerów |
| Główna baza przed upgrade | 0006_correlation; 0 users/raw/normalized/alerts/incidents |
| Testy jednostkowe backendu | 678 passed, 23,00 s, Windows/Python 3.12.14 |
| Ruff i format backendu | PASS; 124 pliki zgodne z formatterem |
| Typy backendu | mypy PASS, 83 pliki aplikacji |
| Testy ryzyka i storage w Docker | 120 passed, 97,10 s; wszystkie 110 nowych przypadków oraz 10 istniejących storage |
| Pełna regresja Linux/Python 3.12.14 | **1004 passed, 866,72 s**, bez pominiętych przypadków: 678 unit + 326 integracyjnych |
| Coverage | **91% z gałęziami**, 5602 statements i 1352 branches; pojedynczy wspólny pomiar procesu testowego |
| Frontend | 59 passed, 7,82 s; 38 wcześniejszych i 21 nowych przypadków |
| Frontend quality | TypeScript, ESLint, Prettier i kontrola diff PASS |
| Frontend build | Vite PASS w osobnym `.local/risk-dist`, a następnie standardowy build launchera PASS; JS `index-Cgnl2oq6.js` i CSS `index-xmddqoEM.css` |
| Główny start Etapu 3 | Standardowy launcher `start -SkipAdmin -BuildMode offline` PASS; konfiguracja zachowana, 91 przypiętych wheel z poprawnymi hashami |
| Główna migracja | Faktyczne `0006_correlation → 0007_risk` PASS, PostgreSQL i ClickHouse migratory exit 0 |
| Główna baza po upgrade | 0007_risk; nadal 0 users/raw/normalized/alerts/incidents/correlation jobs/scopes, 0 risk calculations |
| HTTP i statyczny panel | `/health` i `/ready` 200, wszystkie siedem ścieżek ryzyka w OpenAPI, nowy produkcyjny JS 200, CSP `script-src 'self'` |
| Restart głównych procesów | detector i correlator uruchomione ponownie; stan running, restartCount 0, `/ready` nadal 200; główne środowisko puste, dowód rzeczywistych detekcji pochodzi z integracji |
| Sprzątanie | 0 pozostałych własnych baz `aegis_test_<UUID>`, 0 users w bazie głównej stosu testowego; projekt testowy zatrzymany z zachowaniem volumes |
| Dokumentacja i diff | Walidator PASS: 283 pliki tekstowe, 43 wymagane katalogi, 21 faz, 37 wymagań, 9 ADR; `git diff --check` PASS |

Testy używają odrębnego projektu `aegis-risk-20261003`, własnych sekretów,
volumes i portu 18082. Każda integracja dodatkowo tworzy własną losową
bazę `aegis_test_<UUID>` i usuwa wyłącznie tę bazę w teardown.
Nie tworzono konta administratora do ręcznej pracy w panelu.
Hostowane CI i zalogowany test przeglądarkowy nie są częścią tego dowodu.

Coverage nie instrumentuje oddzielnych procesów API, relay, worker, detector
i correlator; ich zachowanie sprawdzają integracje z rzeczywistymi usługami.
Pliki aplikacji i migracji w lokalnym drzewie, kontenerze pełnej regresji
oraz odrębnym i głównym API mają identyczny SHA-256 po normalizacji końców linii:
`a5df7023073ddaf49f4b0872e0b89817fd7417a500aee0982bbf22298b17fe2e`.

Pełny przebieg w odrębnym projekcie:

```powershell
docker compose --project-name aegis-risk-20261003 --env-file .local/risk/.env -f compose.yaml -f compose.offline.yaml -f .local/risk/compose.yaml --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests pytest -q -p no:cacheprovider --cov=app --cov-report=term --tb=short
```

Lokalny override i sekrety są ignorowane przez Git. Odtworzenie wymaga własnej
konfiguracji wygenerowanej przez `scripts/bootstrap_env.py`, unikalnego projektu
Compose oraz osobnego portu proxy. Nie należy używać `.env` głównej aplikacji
do niezależnego stosu walidacji. Standardowy build i przypięte zależności
opisuje [instrukcja startu](local-start.md).

## 8. Problemy techniczne i ograniczenia

Pierwszy start Docker ponownie zakończył się błędem AF_UNIX
`Docker/run/dockerInference`. Po potwierdzeniu zatrzymania procesów odłożono
tylko katalogi komunikacji do zachowanych kopii:
`run.aegis-risk-backup-3ad2e21e91e845bcab8e699eca52a9e9` i
`docker-secrets-engine.aegis-risk-backup-6b6713242ec14c9da3b2012b29acbbe4`.
Ponowny start przywrócił silnik. Nie kasowano baz, volumes ani WSL.
Opis wynika z lokalnego logu i rzeczywiście wykonanych działań.

Później procesy Desktop zakończyły się przed budową obrazów; przyczyny tego
zakończenia nie ustalono. Ponownie zachowano wyłącznie katalogi komunikacji:
`run.aegis-risk-backup-c83d1ea4b17444e094e39490f0e1767f` i
`docker-secrets-engine.aegis-risk-backup-91c65cafa78d44768c5467ac90ffed93`.
Oficjalne `docker desktop start --timeout 120` przywróciło działanie.
Obrazy runtime i tests `risk-stage3` zbudowano poprawnie.

Przegląd panelu wykrył brak etykiety rzeczywistego pola
`detection_confidence` oraz możliwą rozbieżność starego podsumowania i nowszego
wyniku pobranego przez historię. Obie poprawki potwierdzono w kodzie i testach:
historia jawnie wskazuje nowszą ocenę, a przycisk odświeża całe szczegóły.
„Wersja oceny” oznacza numer kolejnego obliczenia, niezależny od zmian analityka.

### Ograniczenia

Confidence, inventory hostów/użytkowników, IOC, zweryfikowane taktyki,
potwierdzona historia i uprzednie uprawnienia nie mają jeszcze produkcyjnego
źródła. Są unknown, a nie fikcyjnymi wartościami. Czysty kalkulator wspiera
wersjonowane konteksty w symulacji; arbitralne pola eventu ich nie ustanawiają.
Maksimum obecnych znanych składników to 76. Score jest priorytetem według
jawnej polityki demonstracyjnej, nie potwierdzeniem ataku ani kalibracją
prawdopodobieństwa. IOC-only wymaga kolejnego przyrostu polityki.
Funkcja projekcji SQL sprawdza zakres, aktualny head i referencje;
nie odtwarza arytmetyki polityki. Writer aplikacji pozostaje zaufany.
Przejęty runtime z dostępem INSERT może dopisać nowy fałszywy wynik,
choć nie może edytować wcześniejszych obliczeń. API testu nie zapisuje wyników.
Ręczny test po zalogowaniu nadal nie został wykonany: wcześniejsza automatyczna
kontrola odrzuciła utworzenie tymczasowego administratora jako niezatwierdzoną
zmianę uprawnień. Puste główne środowisko wymaga własnego pierwszego konta,
ustawionego przez użytkownika przez zwykły launcher.

## 9. Następny etap

Etap 4 — lokalny wersjonowany katalog MITRE ATT&CK, walidacja mappings
i rzeczywiste coverage API/panelu. Wdrożenie tego źródła pozwoli jawnie
rozwinąć punktację taktyk; nie przepisze dotychczasowych obliczeń.

Przyrost jest zapisany osobnym Conventional Commit:
`feat: explain alert and incident risk with immutable assessments`.
Identyfikator rewizji: `git log -1 --oneline`. Tożsamość autora ustawiono
tylko dla tej komendy, bez zmiany globalnej konfiguracji. Repozytorium
nie ma remote; nie wykonano push ani hostowanego CI.
