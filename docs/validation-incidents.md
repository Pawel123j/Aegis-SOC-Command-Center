# Walidacja etapu 1 — Incident Management

Data: 2026-10-01. Stan: implementacja, regresja i główny start zweryfikowane;
pełny zalogowany test przeglądarkowy pozostaje otwarty.
Punkt wyjścia: `6119335`. Zakres i uzasadnienie:
[plan rozbudowy](soc-expansion-plan.md),
[ADR 0007](adr/0007-incident-case-management.md).

## Co zaimplementowano

Trwałe ręczne incydenty (także bez alertów), automatyczne sprawy z nowych
High/Critical alertów, wiele alertów z różnych źródeł live, izolacja replay,
owner, status, severity, tags, notes, entities/MITRE i historia.
Odpinanie zachowuje dowód. API sprawdza aktualne uprawnienia, rolę oraz
ważność sesji po blokadzie; wszystkie decyzje mają wspólną transakcję audytu.
Panel zawiera listę, create, details, timeline, dowody i formularze pracy.
Risk/confidence pozostają jawnie NULL do dalszych etapów.

## Nowe modele i endpointy

Migracja `0005_incidents`: `Incident`, `IncidentAlert`, `IncidentTimeline`,
`IncidentNote`, `IncidentCreateReceipt`. Niezmienne dowody są snapshotami
istniejących alertów PostgreSQL. Trigger dodatkowo egzekwuje scope powiązań
i maksymalnie 100 aktywnych alertów.

Nowe trasy `/api/v1`: GET/POST `/incidents`, GET `/incidents/assignees`,
GET/PATCH `/incidents/{id}`, POST `/incidents/{id}/alerts`,
DELETE `/incidents/{id}/alerts/{alert_id}`, POST/GET `/incidents/{id}/notes`,
GET `/incidents/{id}/timeline` i GET `/incidents/{id}/evidence`.
Pełny kontrakt: [incydenty](incidents.md).

## Dodane pliki

- Backend: `backend/app/api/incidents.py`, `backend/app/core/cursors.py`,
  `backend/app/modules/incidents/{__init__,models,schemas,service,views}.py`.
- Baza: `backend/migrations/versions/0005_incidents.py`.
- Testy backendu: `test_incident_contracts.py`, `test_incidents.py`,
  `test_incident_security.py` w katalogach unit/integration.
- Frontend: małe komponenty, typy, API i hooks w `frontend/src/incidents/`,
  `frontend/tests/incidentFixtures.ts`, `frontend/tests/incidents.test.tsx`.
- Dokumentacja: `docs/incidents.md`, `docs/soc-expansion-plan.md`,
  `docs/adr/0007-incident-case-management.md`, ten raport.

## Zmienione pliki

Backend: `main.py`, `api/dependencies.py`, `api/health.py`, routery
alerts/detections/users/sources/events/pipeline, `detections/processing.py`,
`migrations/env.py`, integracyjny `test_storage.py`.
Shared authority helper zastępuje importowanie autoryzacji z routera alertów
i naprawia brak kontroli expiry w części mutacji administracyjnych.

Frontend: `src/App.tsx`, `src/Alerts.tsx`, `src/api.ts`, frontend README.
Uruchomienie: `compose.yaml` używa osobnego tagu `incidents-stage1`.
Dokumentacja: README, backend README, API/data model/incident response,
implementation plan, traceability, indeks ADR i validation.
`scripts/validate_repository.py` dopuszcza dalsze ADR, zachowując wymagane
oryginalne sześć rekordów.

## Testy i wyniki

| Kontrola | Wykonany wynik |
| --- | --- |
| Dotychczasowe unit backendu | **580 passed**, 22,83 s na Windows/Python 3.12.14 |
| Nowe integracje incydentów i bezpieczeństwa | **33 passed**, 33,52 s na Linux, rzeczywisty PostgreSQL |
| Pełna regresja backendu i coverage | **820 passed**, 619 unit + 201 integration, 421,32 s; **92%** branch coverage procesu testowego |
| Ruff lint / format | PASS; 101 plików |
| Mypy | PASS; 65 source files |
| Migracja i uruchomienie osobnego stacku | PASS; 0005, API/bazy healthy, readiness 200 |
| Frontend build / lint / format / test | PASS; **23 Vitest passed**, 12 dotychczasowych + 11 nowych |
| Skrypty | **23 unittest + 1 pytest passed** |
| Dokumentacja i diff | PASS; 226 text files, 43 katalogi, 21 historycznych faz, 37 wymagań, 7 ADR |
| Główne środowisko pod 8080 po upgrade | PASS przez oficjalny launcher offline z SkipAdmin; konta/sekrety/volumes zachowane, 0005, readiness 200 |
| Główny panel i kontrakt | Root/JS 200, application/javascript, self-only CSP, wszystkie osiem ścieżek incydentów w OpenAPI, ekran login w przeglądarce |
| Zgodność obrazów test i runtime | SHA-256 z normalizowanego kodu Python identyczny: `985e0c68aa78f27c318a2e1f8a57ebb0e1e480f5e8566118cf0163045d5c5cad` |

Dodano **39 unit + 33 integration** backendu i **11** testów panelu.
Nowe unit sprawdzają wszystkie 25 par statusów, jawne wymagania przejść,
Unicode, granice i odrzucenie fałszywej oceny ryzyka. Integracje sprawdzają
cross-source live, dataset/run isolation replay, trigger/granty, historyczne
dowody po detach/reattach, paginację ponad 50 notatek, cursor scope,
idempotencję i równoczesne tworzenie, High/Critical automatycznie oraz
Medium bez automatycznej sprawy.

Osobny przegląd bezpieczeństwa dodał testy Viewer/collector, self/any owner,
reopen, pięć rzeczywistych wyścigów cofania roli/sesji/expiry po lock,
concurrent edits (jeden sukces, jeden 412), rollback po błędzie audytu,
duży poprawny Unicode input, niezmienność historii i NULL w CHECK zakresu czasu.

Testy frontendowe sprawdzają uprawnienia Viewer i brak wymyślonego risk,
retry create z tym samym key oraz jego zmianę po zmianie body, zachowanie
szkicu przy 412, graf statusów i reason, aktualną wersję po kolejnych
decyzjach, live/replay picker, paginację, cross-source create, odpięty dowód,
text escaping i nagłówki wire API. Odświeżenie sesji w drugiej karcie
zachowuje widok i szkice dla tej samej identity/role/permissions;
zmiana tożsamości/uprawnień lub logout czyści je.

Coverage 92% dotyczy jednego pełnego przebiegu, a nie sumy odrębnych wyników.
Osobne daemony nie są objęte tym pomiarem. Lockfile i zależności pozostają
bez zmian; nie dodano usługi ani zależności runtime.

## Odtworzenie kontroli

Na tym hoście testy wykonano w osobnym projekcie `aegis-phase3-20261001`
z własnym `.env`, volumes i proxy na 18080. Każda integracja tworzy dodatkowo
własną losową bazę `aegis_test_<UUID>` i usuwa ją w teardown. Nie zmieniano
głównej bazy podczas testów.

```text
docker compose -f compose.yaml -f compose.offline.yaml --profile test build api tests
docker compose up -d --no-build --wait
docker compose --profile test run --rm --no-deps -e COVERAGE_FILE=/tmp/.coverage tests pytest -q -p no:cacheprovider --cov=app --cov-report=term --tb=short
cd frontend
pnpm build
pnpm lint
pnpm format
pnpm test
```

Kontrole frontendowe wykonano także bezpośrednimi CLI z przypiętego Node,
a oficjalny launcher potwierdził `pnpm` offline install oraz build. Main:
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/aegis.ps1 -Action start -SkipAdmin -BuildMode offline`.
SkipAdmin służy wyłącznie kontroli bez tworzenia konta: jeśli baza nie ma
operatorów, użytkownik uruchamia zwykły launcher i sam ustawia hasło pierwszego
administratora. Walidacja nie utworzyła żadnego konta w głównej aplikacji.

## Problemy techniczne i granice dowodu

Docker Desktop 4.86.0 na Windows nie startował przez niedostępne AF_UNIX
runtime endpoints `dockerInference`, potem `engine.sock`. Przy zatrzymanym
programie odłożono tylko katalogi komunikacji `Docker/run` oraz
`docker-secrets-engine` do sąsiednich kopii z UUID; kopie pozostają zachowane.
Po ponownym starcie Engine 29.7.2 działa, stare usługi i dane wróciły.
Nie wykonywano resetu, prune ani kasowania volumes. Podobny przypadek:
[zgłoszenie w Docker Desktop](https://github.com/docker/desktop-feedback/issues/531).

Poprawiono też brak expiry recheck, lukę SQL NULL w CHECK timestamps,
zbyt duży metadata audit dla legalnych opisów/notatek (pełna treść pozostaje
w historii; audit ma hash/długość i timeline ID), podwójne zwiększenie wersji
oraz rozbieżność limitu reason między frontendem i backendem.

Pełny zalogowany przebieg przeglądarkowy nadal wymaga zgody na utworzenie
tymczasowego administratora w osobnym środowisku. Automatyczna kontrola
wcześniej odrzuciła tę konkretną zmianę uprawnień. Nowe wymagania funkcjonalne
nie zastępują brakującej zgody na to konto. Hostowane CI nie było wykonywane.

Historyczne wyniki zachowuje [walidacja pierwszych alertów](validation-initial-soc.md).
Następny etap: **Correlation Engine** według [planu](soc-expansion-plan.md).
