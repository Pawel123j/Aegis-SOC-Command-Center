# Walidacja Etapu 10 — Mini SOAR

Data: 2026-10-08. Punkt wyjścia: `e4ba03e` (Etap 9).
Stan: etap wdrożony lokalnie; regresja, jakość, browser proof i kontrola
uruchomienia/restartu PASS. Granice dowodu opisuje punkt 8.
[Kontrakt](soar.md), [ADR 0016](adr/0016-durable-local-playbooks.md).

## 1. Zaimplementowany zakres

Ręczny start niezmiennej, opublikowanej procedury z dowodu alertu. Dziewięć
zamkniętych akcji obejmuje lokalną analizę IP, przypięte TI/ryzyko, incydent,
nieaktywny IOC do przeglądu, prywatne powiadomienie oraz trzy symulacje.
Edytor panelu obsługuje uporządkowane kroki i osobną publikację. Uruchomienie
wymaga przeglądu planu; historia pokazuje stany, próby, czas, wyniki i dowody.

Osobny proces `soar` używa trwałej kolejki PostgreSQL. Dzierżawa, numer próby,
unikalny ledger efektów i wspólna transakcja efekt/audyt/postęp chronią retry
oraz odzyskiwanie po przerwaniu. Cancel zachowuje wcześniejsze skutki,
a ręczne ponowienie tworzy nowy run. Uprawnienia są ponownie sprawdzane
przed efektem. Blokada IP, izolacja hosta i webhook są zawsze symulowane.

## 2. Dodane pliki

- `backend/app/api/soar.py` i `backend/app/soar.py`.
- `backend/app/modules/soar/`: `__init__.py`, `schemas.py`, `models.py`,
  `evidence.py`, `actions.py`, `service.py`, `processing.py`, `views.py`.
- `backend/migrations/versions/0012_soar.py`.
- `backend/tests/unit/test_soar.py`, `backend/tests/integration/test_soar.py`.
- `frontend/src/soar/`: `types.ts`, `useSoarMutation.ts`, `PlaybookEditor.tsx`,
  `RunLauncher.tsx`, `RunDetails.tsx`, `Soar.tsx`, `soar.css`.
- `frontend/tests/soar.test.tsx`.
- `docs/adr/0016-durable-local-playbooks.md`, `docs/validation-soar.md`.

## 3. Zmienione pliki

- `backend/app/main.py`, `backend/app/api/health.py`, `backend/app/core/http.py`,
  `backend/migrations/env.py`: router, head migracji i ścisła walidacja JSON.
- Istniejące testy `test_storage.py`, `test_entities_security.py`,
  `test_intelligence_catalogue.py`: oczekiwany head migracji.
- `compose.yaml`, `compose.offline.yaml`: obraz `soar-stage10` i proces SOAR.
- `frontend/src/App.tsx`, `Alerts.tsx`, `api.ts`: nawigacja, start z alertu,
  polskie komunikaty błędów.
- `README.md`, `backend/README.md`, `frontend/README.md`.
- `docs/soar.md`, `api-contract.md`, `architecture.md`, `data-model.md`,
  `implementation-plan.md`, `repository-structure.md`,
  `requirements-traceability.md`, `security.md`, `soc-expansion-plan.md`,
  `validation.md`, `adr/README.md` i `scripts/repository_manifest.json`.

## 4. Endpointy

14 operacji HTTP pod `/api/v1`: katalog akcji, cele alertu, lista/tworzenie/
odczyt/dostępność procedur, tworzenie rewizji, publikacja, start, lista/
szczegóły/cancel wykonań, prywatna skrzynka i oznaczenie odczytu.
Dokładne metody/ścieżki i payloady: [kontrakt API](api-contract.md).

Odczyt wymaga pięciu permissions, wykonanie dodatkowo playbooks:run i praw
lokalnych akcji. Zmiany procedury wymagają If-Match, start Idempotency-Key.
Limity: 120 odczytów i 30 mutacji/min na użytkownika; lista do 50 wyników.
Live/replay danych są oddzielone, a tryb infrastruktury zawsze simulation.

## 5. Modele

Migracja `0012_soar`: Playbook, PlaybookRevision, PlaybookRun, PlaybookStep,
PlaybookAttempt, PlaybookEffect, SoarNotification. Rewizje/próby/efekty są
append-only; terminalne stany i niezmienne kolumny chronią granty/triggery.
Pusty downgrade jest sprawdzony; niepusty katalog blokuje usunięcie historii.
Definicja JSON schema_version=1 przyjmuje tylko nazwę/opis i 1–20 kroków.
DTO i rejestr nie dopuszczają kodu, endpointów HTTP ani dowolnych parametrów.

## 6. Nowe testy

**105 testów backendu: 62 unit i 43 integracyjne.** Sprawdzają walidację,
przypięte dowody, uprawnienia, scope, kolejkę, idempotencję, retry/deadline,
wyłączenie konta/procedury, false positive, cancel i świadome ponowienie.
Rzeczywisty PostgreSQL kontroluje wyścigi dwóch wykonawców, starą dzierżawę,
trzy awarie, rollback przy błędzie audytu oraz przerwanie procesu SIGKILL
przed efektem, przed commitem i po commicie. Testowane są lokalne skutki,
prywatna skrzynka, replay bez zmiany globalnego IOC, limity output i migracje.

**22 nowe testy panelu**: edytor/publikacja, podgląd planu, wymagane
potwierdzenie, klucz ponowienia, role, odczyt historii i powiadomień,
anulowanie, odświeżanie oraz odrzucanie odpowiedzi poprzedniej sesji.

## 7. Wyniki kontroli

Pełna regresja backendu: **2286 PASS** (1562 unit + 724 integracyjne),
Linux/Python 3.12.14, rozłączne partie pokrywające całą zebraną listę testów.
Nie jest to deklaracja jednego procesu. Partie integration-2/3/4 używały
końcowego kodu SOAR przed pojedynczą poprawką oczekiwanego head w health.py.
Partię integration-1 i wszystkie unit wykonano ponownie na obrazie z tą
poprawką, włącznie z rzeczywistą gotowością i odzyskiwaniem pipeline.

| Partia | Wynik |
| --- | --- |
| integration-1 | 181 PASS; 434.69 s |
| integration-2 | 183 PASS; 475.52 s |
| integration-3 | 180 PASS; 494.13 s |
| integration-4 | 180 PASS; 438.95 s |
| unit | 1562 PASS; 42.81 s |

| Pozostała kontrola | Wynik |
| --- | --- |
| Nowy moduł i migracje | 115 PASS; 226.97 s: 105 nowych + 10 istniejących testów storage |
| Pokrycie SOAR/routera | **90%** Python: 744 statements, 184 branches; nie jest to coverage SQL ani całego systemu |
| Panel | **308 PASS**, 13 plików, 25.63 s; TypeScript, ESLint, Prettier PASS |
| Backend jakość | Ruff PASS, 217 plików format PASS, mypy 141 plików PASS |
| Zależności | pip check PASS; bez deklaracji aktualnego audytu podatności |
| Skrypty | **31 PASS**; 1.776 s |
| Kompilacja panelu | 111 modułów, 928 ms; JS index-jWKUau4G.js 463.71 kB / gzip 129.72; CSS index-BJttAC4X.css 22.87 kB / gzip 5.77 |
| Zalogowany browser E2E | PASS na jednorazowej bazie: nowa procedura → publikacja → alert → 6 ukończonych kroków → incydent i prywatne powiadomienie → odczyt historii po otwarciu nowej karty → logout |
| Instalacja kontrolna | Końcowy obraz, head 0012, zgodny hash kodu, health/ready/OpenAPI/panel/JS/CSS 200, chronione odczyty 401, CSP self |
| Główna instalacja | Oficjalny launcher offline z SkipAdmin; zachowane liczności i plik env, zgodny kod, restart processor/detector/correlator/soar i HTTP PASS |
| Końcowy format migracji | 10 testów storage PASS; 13.57 s po ujednoliceniu białych znaków SQL |
| Repozytorium | 474 pliki tekstowe, 48 katalogów, 21 faz, 37 wymagań, 16 ADR; linki, składnia, format i git diff --check PASS |

Browser używał rzeczywistego API i serwera wykonującego moduł SOAR w osobnym
wątku, z tymi samymi transakcjami. Testy SIGKILL używały osobnych procesów.
Log przeglądarki końcowej karty nie zawierał ostrzeżeń/błędów. Zapisano
`.local/soar/browser-proof.jpg` i `browser-summary.jpg`. Po teście serwer
zamknięto, a fixture potwierdził usunięcie wyłącznie swojej losowej bazy.
Nie przeniesiono konta lub danych testowych do głównej instalacji.

Hash końcowego kodu app/migrations/katalogu:
`bb980b18062fb93ed135be5908ac4ecb6fa594c725d2e6ae778293f51b0dfc1b`.
Hash jest zgodny z instalacją kontrolną i główną. Lokalna konfiguracja env
i wcześniejsze liczności pozostały bez zmian; główna baza ma nadal zero kont
i danych domenowych oraz jeden deployment TI. Zero pozostałych baz testowych
potwierdzono w obu projektach. Kontrolny projekt zatrzymano, zachowując volumes.
Główny pozostaje uruchomiony. Healthcheck mają API, PostgreSQL, Redis i ClickHouse;
pozostałe procesy potwierdzono jako running. Lokalne logi i dowody są
w ignorowanym `.local/soar/`; to nie jest wynik CI.

## 8. Problemy i granice dowodu

Pierwsza partia integracyjna ujawniła nieaktualne EXPECTED_REVISION w sondzie
gotowości: dwa testy nie przeszły. Poprawiono head na 0012_soar i ponowiono
całą partię; końcowy wynik powyżej jest PASS. Windows sandbox blokował temp
oraz inicjalizację HTTPS w trzech testach skryptów; z własnym temp i poza
sandboxem komplet 31 testów przeszedł. Stubów Windows brakowało, więc pełne
mypy wykonano w docelowym obrazie Linux. Końcowy format SQL migracji ujednolicono bez zmiany tokenów; testy storage
powtórzono na wynikowym obrazie. Panel testowano bez ponownej
instalacji zależności, bezpośrednio narzędziami istniejącego lockfile.

Docker Desktop ponownie kończył start na uszkodzonym gnieździe dockerInference.
Zweryfikowane katalogi komunikacyjne odłożono do kopii i wznowiono silnik;
nie usunięto wolumenów. Nie dowodzi to trwałej naprawy przyszłych restartów.

Główne konto administratora pozostaje do ręcznego utworzenia launcherem:
wcześniejsza automatyczna kontrola odrzuciła jego tworzenie jako zmianę
uprawnień. Wdrożenie używa SkipAdmin. Browser proof obejmuje odizolowaną
instalację testową, nie sesję głównego administratora. Hostowane CI,
internetowy audyt zależności i test pełnego generatora demo pozostają otwarte.

Zakres jest lokalny, sekwencyjny i ręczny. Nie ma automatycznych triggerów,
warunków/pętli, rzeczywistych blokad, dostawców zewnętrznych ani wysyłki.
Ocena ryzyka pozostaje przypiętym odczytem zamiast uznaniowej zmiany punktów.
Powiadomienie jest lokalne, nowy IOC nieaktywny, a zamknięta sprawa wymaga
ręcznej decyzji. Właściciel bazy może obejść granty; model nie obiecuje
odporności na świadome wyłączenie zabezpieczeń przez właściciela danych.

## 9. Następny etap

Etap 11: Dashboard — wydarzenia/alerty 24 h, incydenty i critical,
ranking użytkowników/IP/hostów/reguł, taktyki MITRE, rozkład ryzyka/wagi
oraz tempo ingestion z automatycznym odświeżaniem i izolacją live/replay.
Użytkownik zlecił rozpoczęcie go po ukończeniu Etapu 10.
